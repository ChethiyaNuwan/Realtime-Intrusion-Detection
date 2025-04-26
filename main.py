import numpy as np
import joblib
import scapy.all as scapy
from collections import deque, defaultdict
import time
import logging
import threading
import platform
import subprocess
from flask import Flask, render_template, jsonify

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Flask app
app = Flask(__name__)

# Load the saved model and label encoder
model = joblib.load('models/random_forest_classifier.pkl')
encoder = joblib.load('models/label_encoder.pkl')

# Global variables to store state
packet_data = deque(maxlen=10000)
log_storage = []
flow_stats = defaultdict(lambda: {

    'total_fwd_packets': 0,
    'total_bwd_packets': 0,
    'total_length_fwd': 0,
    'total_length_bwd': 0,
    'fwd_packet_lengths': [],
    'bwd_packet_lengths': [],
    'flow_start_time': None,
    'flow_end_time': None,
    'flow_iat': [],
    'fwd_iat': [],
    'bwd_iat': [],
    'fwd_flags': {'PSH': 0, 'URG': 0, 'FIN': 0, 'SYN': 0, 'RST': 0, 'ACK': 0, 'CWE': 0, 'ECE': 0},
    'bwd_flags': {'PSH': 0, 'URG': 0, 'FIN': 0, 'SYN': 0, 'RST': 0, 'ACK': 0, 'CWE': 0, 'ECE': 0},
    'fwd_header_length': 0,
    'bwd_header_length': 0,
    'init_win_bytes_fwd': 0,
    'init_win_bytes_bwd': 0,
    'act_data_pkt_fwd': 0,
    'min_seg_size_fwd': float('inf'),
    'idle_times': [],
    'fwd_bulk_data': [],
    'bwd_bulk_data': [],
    'flow_duration': 0,
    'protocol': None,
})

# Global dictionary to store data for each interface
interface_data = defaultdict(list)


def get_nics():
    """Function to get list of all NICs on the system."""
    nics = []

    # Check the operating system
    os_type = platform.system()

    if os_type == 'Linux':
        process = subprocess.Popen(['ip', '-o', 'link', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        stdout, _ = process.communicate()
        for line in stdout.splitlines():
            nic_name = line.split(':')[1].strip()
            if nic_name != "lo":  # Exclude the loopback interface
                nics.append(nic_name)
    elif os_type == 'Darwin':
        process = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        stdout, _ = process.communicate()
        for line in stdout.splitlines():
            if line and not line.startswith('\t') and ':' in line:
                nic_name = line.split(':')[0].strip()
                if nic_name != "lo0":  # Exclude the loopback interface
                    nics.append(nic_name)
    elif os_type == 'Windows':
        process = subprocess.Popen(['wmic', 'nic', 'get', 'NetConnectionID'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, universal_newlines=True)
        stdout, _ = process.communicate()
        for line in stdout.splitlines():
            nic_name = line.strip()
            if nic_name and nic_name != "Local Area Connection* 9":  # Exclude default loopback interfaces
                nics.append(nic_name)
    else:
        logging.error(f"Unsupported OS: {os_type}")
        exit(1)

    return nics


def cleanup_flow_stats():
    """Cleans up flow_stats by removing old or completed flows."""
    current_time = time.time()
    for flow_key in list(flow_stats.keys()):
        flow_duration = current_time - flow_stats[flow_key]['flow_end_time']
        if flow_duration > 600:  # Clean up flows idle for more than 10 minutes
            del flow_stats[flow_key]


def calculate_statistics(packet):
    pkt_time = time.time()
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    proto = packet[scapy.IP].proto
    length = len(packet)
    direction = 'fwd' if packet[scapy.IP].src == src_ip else 'bwd'

    flow_key = (src_ip, dst_ip, proto)

    # Set protocol in stats
    flow_stats[flow_key]['protocol'] = proto

    if flow_stats[flow_key]['flow_start_time'] is None:
        flow_stats[flow_key]['flow_start_time'] = pkt_time

    if flow_stats[flow_key]['flow_end_time'] is not None:
        idle_time = pkt_time - flow_stats[flow_key]['flow_end_time']
        flow_stats[flow_key]['idle_times'].append(idle_time)

    flow_stats[flow_key]['flow_end_time'] = pkt_time
    flow_stats[flow_key]['flow_duration'] = flow_stats[flow_key]['flow_end_time'] - flow_stats[flow_key][
        'flow_start_time']
    flow_stats[flow_key][f'total_{direction}_packets'] += 1
    flow_stats[flow_key][f'total_length_{direction}'] += length
    flow_stats[flow_key][f'{direction}_packet_lengths'].append(length)
    flow_stats[flow_key][f'{direction}_iat'].append(pkt_time)

    # Check for flags
    if scapy.TCP in packet:
        tcp_flags = packet[scapy.TCP].flags
        flow_stats[flow_key][f'{direction}_flags']['FIN'] += 1 if tcp_flags.F else 0
        flow_stats[flow_key][f'{direction}_flags']['SYN'] += 1 if tcp_flags.S else 0
        flow_stats[flow_key][f'{direction}_flags']['RST'] += 1 if tcp_flags.R else 0
        flow_stats[flow_key][f'{direction}_flags']['PSH'] += 1 if tcp_flags.P else 0
        flow_stats[flow_key][f'{direction}_flags']['ACK'] += 1 if tcp_flags.A else 0
        flow_stats[flow_key][f'{direction}_flags']['URG'] += 1 if tcp_flags.U else 0
        flow_stats[flow_key][f'{direction}_flags']['CWE'] += 1 if tcp_flags.C else 0
        flow_stats[flow_key][f'{direction}_flags']['ECE'] += 1 if tcp_flags.E else 0
        flow_stats[flow_key][f'{direction}_header_length'] += packet[scapy.TCP].dataofs * 4
        if flow_stats[flow_key]['init_win_bytes_fwd'] == 0:
            flow_stats[flow_key]['init_win_bytes_fwd'] = packet[scapy.TCP].window
        if flow_stats[flow_key]['init_win_bytes_bwd'] == 0:
            flow_stats[flow_key]['init_win_bytes_bwd'] = packet[scapy.TCP].window
        flow_stats[flow_key]['act_data_pkt_fwd'] += 1
        flow_stats[flow_key]['min_seg_size_fwd'] = min(flow_stats[flow_key]['min_seg_size_fwd'],
                                                       packet[scapy.TCP].window)

    # Handle bulk data rate calculations
    bulk_threshold = 3 * 1500  # Example bulk threshold (3 packets of max Ethernet size)
    if direction == 'fwd':
        flow_stats[flow_key]['fwd_bulk_data'].append(length)
        if len(flow_stats[flow_key]['fwd_bulk_data']) > 3:
            if sum(flow_stats[flow_key]['fwd_bulk_data'][-3:]) > bulk_threshold:
                flow_stats[flow_key]['fwd_bulk_data'] = []
    else:
        flow_stats[flow_key]['bwd_bulk_data'].append(length)
        if len(flow_stats[flow_key]['bwd_bulk_data']) > 3:
            if sum(flow_stats[flow_key]['bwd_bulk_data'][-3:]) > bulk_threshold:
                flow_stats[flow_key]['bwd_bulk_data'] = []


def extract_selected_features(flow_key, stats):
    fwd_packet_lengths = stats['fwd_packet_lengths']
    bwd_packet_lengths = stats['bwd_packet_lengths']
    fwd_iat = np.diff(stats['fwd_iat'])
    bwd_iat = np.diff(stats['bwd_iat'])

    selected_features = {
        'Fwd Packet Length Std': np.std(fwd_packet_lengths) if fwd_packet_lengths else 0,
        'Bwd Packet Length Std': np.std(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Fwd IAT Mean': np.mean(fwd_iat) if fwd_iat.size > 0 else 0,
        'Fwd IAT Std': np.std(fwd_iat) if fwd_iat.size > 0 else 0,
        'Fwd IAT Max': np.max(fwd_iat) if fwd_iat.size > 0 else 0,
        'Bwd IAT Std': np.std(bwd_iat) if bwd_iat.size > 0 else 0,
        'Bwd Packets/s': stats['total_bwd_packets'] / stats['flow_duration'] if stats['flow_duration'] > 0 else 0,
        'Idle Mean': np.mean(stats['idle_times']) if stats['idle_times'] else 0,
        'Idle Max': np.max(stats['idle_times']) if stats['idle_times'] else 0,
        'Idle Min': np.min(stats['idle_times']) if stats['idle_times'] else 0
    }

    return selected_features


def process_packet(packet, interface):
    try:
        # Check if the packet has an IP layer
        if packet.haslayer(scapy.IP):
            # Extract features from packet
            calculate_statistics(packet)

            # Retrieve current flow stats
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            flow_key = (src_ip, dst_ip, proto)
            stats = flow_stats[flow_key]

            # Calculate packets per second
            if len(interface_data[interface]) > 0:
                last_record = interface_data[interface][-1]
                time_diff = time.time() - last_record['timestamp']
                if time_diff > 0:
                    pps = (stats['total_fwd_packets'] + stats['total_bwd_packets']) / time_diff
                else:

                    pps = 0
            else:
                pps = 0

            # Predict using the model
            features = extract_selected_features(flow_key, stats)
            feature_values = np.array(list(features.values())).reshape(1, -1)

            #print(f"DEBUG: Extracted Features for ML Prediction: {features}")
            #print(f"DEBUG: Model is using {model.n_features_in_} features")
                ###check the prediction tru out the model

            prediction = model.predict(feature_values)

            feature_values = np.array(list(extract_selected_features(flow_key, stats).values())).reshape(1, -1)
            prediction = model.predict(feature_values)

            try:
                predicted_label = encoder.inverse_transform(prediction)[0]
                logging.info(f"Interface: {interface} - Predicted Class: {predicted_label}")

                # Append the data for visualization
                interface_data[interface].append({
                    'timestamp': time.time(),
                    'pps': pps
                })

                # Store latest prediction for the interface
                interface_data[interface].append({
                    'timestamp': time.time(),
                    'pps': stats['total_fwd_packets'] + stats['total_bwd_packets'],
                    'predicted_label': predicted_label  # Save the label for HTML
                })

                # NEW: Store the output in log_storage (limit to last 50 logs)
                log_storage.append(f"Predicted Label: {predicted_label}")
                if len(log_storage) > 50:
                    log_storage.pop(0)  # Keep only last 50 logs


            except Exception as e:
                logging.error(f"Error in label decoding: {str(e)}")

            # Ensure we only keep the last 80 records
            if len(interface_data[interface]) > 80:
                interface_data[interface] = interface_data[interface][-80:]

            # Clean up old flows
            cleanup_flow_stats()

        else:
            logging.warning(f"Interface: {interface} - Non-IP packet detected, skipping...")

    except Exception as e:
        logging.error(f"Interface: {interface} - Error processing packet: {str(e)}")


def sniff_interface(interface):
    try:
        logging.info(f"Starting sniffing on interface: {interface}")
        scapy.sniff(iface=interface, prn=lambda pkt: process_packet(pkt, interface), store=False)
    except Exception as e:
        logging.error(f"Error sniffing on interface {interface}: {str(e)}")


@app.route('/')
def index():
    return render_template('index.html')

########pass the data to html teminal
@app.route('/api/alerts')
def get_alerts():
    """Returns the latest real-time predicted labels."""
    alerts = []
    for interface, records in interface_data.items():
        if records:
            latest_prediction = records[-1].get('predicted_label', 'Unknown')
            alerts.append({"interface": interface, "label": latest_prediction})

    return jsonify(alerts)

@app.route('/api/logs')
def get_logs():
    """Serve the latest captured logs."""
    return jsonify(log_storage)

@app.route('/api/data')
def get_data():
    global interface_data
    return jsonify(interface_data)


def start_sniffing():
    try:
        # Get list of all available network interfaces
        interfaces = get_nics()
        logging.info(f"Available interfaces: {interfaces}")

        # Create a thread for each interface
        threads = []
        for interface in interfaces:
            thread = threading.Thread(target=sniff_interface, args=(interface,))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    except Exception as e:
        logging.critical(f"Error in sniffing: {str(e)}")


if __name__ == '__main__':
    #Start the network sniffing in a background thread
    threading.Thread(target=start_sniffing, daemon=True).start()
    # Run the Flask app
    app.run(debug=True)
