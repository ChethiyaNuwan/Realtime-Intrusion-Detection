import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' 

import numpy as np
import time
import logging
import threading
import platform
import subprocess
import json
import tensorflow as tf
from flask import Flask, render_template, jsonify, request, Response
from collections import defaultdict
from db import get_db_connection, store_attack_details, get_latest_attack_logs
from capture import capture_traffic, convert_pcap
from predict import preprocess_flow, predict_attack, get_label_mapping
from utils import get_latest_pcap, get_latest_csv

# Constants for monitoring
CAPTURE_DURATION = 10
MONITORING_INTERVAL = 5
CLEANUP_INTERVAL = 60
MAX_FILES_KEPT = 10

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/monitor.log'),
        logging.StreamHandler()
    ]
)

# Initialize db
# connection = get_db_connection()

# Load the models
dl_model = tf.keras.models.load_model('lib/deep_learning_model.h5')
label_mapping = get_label_mapping()

# Global variables to store state
interface_data = defaultdict(list)

# Initialize Flask app
app = Flask(__name__)


def get_interfaces():
    """Function to get list of all network interfaces on the system."""
    nics = []

    # Check the operating system
    os_type = platform.system()

    if os_type == 'Linux':
        process = subprocess.Popen(['ip', '-o', 'link', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        stdout, _ = process.communicate()
        for line in stdout.splitlines():
            nic_name = line.split(':')[1].strip()
            if nic_name != "lo":
                nics.append(nic_name)
    elif os_type == 'Windows':
        process = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, encoding='utf-8')
        stdout, _ = process.communicate()
        current_adapter = None
        
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                if line.endswith(':'):
                    current_adapter = line[:-1].strip()
                    if (not any(x in current_adapter for x in [
                        'Loopback', 'Virtual', 'Pseudo', '*', 'vEthernet', 'Bluetooth'
                    ]) and 'adapter' in current_adapter):
                        adapter_name = current_adapter.split('adapter ')[-1].strip()
                        nics.append(adapter_name)
    else:
        logging.error(f"Unsupported OS: {os_type}")
        exit(1)

    return nics


def cleanup_old_files(directory, max_files):
    """Remove old files when exceeding max_files limit"""
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) 
                if os.path.isfile(os.path.join(directory, f))]
        if len(files) > max_files:
            files.sort(key=lambda x: os.path.getmtime(x))
            for f in files[:-max_files]:
                os.remove(f)
                logging.info(f"Cleaned up old file: {f}")
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")


def monitor_network(interface):
    """Real-time network monitoring function"""
    while True:
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            pcap_file = os.path.join("captures", f"capture_{timestamp}.pcap")
            
            logging.info(f"Starting capture on interface {interface}")
            capture_process = capture_traffic(interface, CAPTURE_DURATION, pcap_file)
            
            if capture_process is None:
                logging.error("Failed to start capture")
                time.sleep(MONITORING_INTERVAL)
                continue
            
            # Process real-time output
            packet_count = 0
            start_time = time.time()
            
            while capture_process.poll() is None:
                output = capture_process.stdout.readline()
                if output:
                    packet_count += 1
                    current_time = time.time()
                    time_diff = current_time - start_time
                    
                    if time_diff >= 1:  # Calculate PPS every second
                        pps = packet_count / time_diff
                        interface_data[interface].append({
                            'timestamp': current_time,
                            'pps': pps,
                            'predicted_label': 'Benign'  # Placeholder until ML prediction
                        })
                        
                        if len(interface_data[interface]) > MAX_FILES_KEPT:
                            interface_data[interface] = interface_data[interface][-MAX_FILES_KEPT:]
                        
                        packet_count = 0
                        start_time = current_time
            
            capture_process.wait()
            
            logging.info("Converting PCAP to flow format")
            convert_process = convert_pcap(pcap_file)
            
            if convert_process is None:
                logging.error("Failed to convert PCAP to flow format")
                time.sleep(MONITORING_INTERVAL)
                continue
                
            convert_process.wait()
            
            flow_file = get_latest_csv("flows/")
            if flow_file:
                logging.info(f"Processing flow file: {flow_file}")
                try:
                    X = preprocess_flow(flow_file)
                    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
                    pred_label, pred_probs = predict_attack(X, dl_model)
                    
                    for i, (label, prob) in enumerate(zip(pred_label, pred_probs)):
                        attack_type = label_mapping[label]
                        confidence = prob.max() * 100
                        
                        interface_data[interface].append({
                            'timestamp': time.time(),
                            'pps': 0, 
                            'predicted_label': attack_type
                        })
                        
                        if len(interface_data[interface]) > MAX_FILES_KEPT:
                            interface_data[interface] = interface_data[interface][-MAX_FILES_KEPT:]
                        
                        logging.info(f"DL Model Detected: {attack_type} (Confidence: {confidence:.2f}%)")
                        
                        if confidence > 90 and str.lower(attack_type) != "benign":
                            logging.warning(f"HIGH CONFIDENCE ATTACK DETECTED: {attack_type}")
                            # store_attack_details(
                            #     connection=connection,
                            #     attack_type=attack_type,
                            #     confidence=confidence,
                            #     interface=interface,
                            #     timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                            #     source_ip="Unknown",
                            #     dest_ip="Unknown"
                            # )
                        
                except Exception as e:
                    logging.error(f"Error during prediction: {e}")
            
            time.sleep(MONITORING_INTERVAL)
            
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            time.sleep(MONITORING_INTERVAL)


def cleanup_thread():
    """Periodic cleanup of capture and flow files"""
    while True:
        cleanup_old_files("captures", MAX_FILES_KEPT)
        cleanup_old_files("flows", MAX_FILES_KEPT)
        time.sleep(CLEANUP_INTERVAL)


# Flask API
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/assets/<path:filename>')
def serve_static(filename):
    logging.info(f"Serving static file: {os.path.join('templates/assets', filename)}")
    
    return app.send_static_file(os.path.join('./templates/assets', filename))

@app.route('/get_interfaces')
def get_interfaces_route():
    interfaces = get_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/start_monitoring', methods=['POST']) # Changed to POST
def start_monitoring_route():
    data = request.get_json()
    interface = data.get('interface')
    if not interface:
        return jsonify({'error': 'No interface specified'}), 400

    # Check if monitoring for this interface is already running (optional, depends on desired behavior)
    # For simplicity, we'll start a new thread each time, assuming the user wants to restart monitoring.
    # A more robust solution might manage threads to avoid duplicates.

    logging.info(f"Received request to start monitoring on {interface}")
    monitoring_thread = threading.Thread(target=monitor_network, args=(interface,), daemon=True)
    monitoring_thread.start()

    return jsonify({'message': f'Started monitoring on {interface}'})

@app.route('/get_latest_data')
def get_latest_data():
    interface = request.args.get('interface')
    if not interface:
        return jsonify({'error': 'No interface specified'}), 400
    if interface not in interface_data:
        return jsonify({'data': []})

    data = interface_data[interface][-1:] if interface_data[interface] else []
    return jsonify({'data': data})

@app.route('/get_attack_logs')
def get_attack_logs_route():
    # logs = get_latest_attack_logs(connection)
    logs = []
    log_list = []
    if logs:
        for log in logs:
            log_list.append({
                'id': log[0],
                'attack_type': log[1],
                'confidence': log[2],
                'interface': log[3],
                'timestamp': log[4].strftime('%Y-%m-%d %H:%M:%S'), # Format datetime
                'source_ip': log[5],
                'dest_ip': log[6]
            })
    return jsonify(log_list)


@app.route('/stream_packets')
def stream_packets():
    interface = request.args.get('interface')  # Extract at the start

    def generate(interface):
        if not interface:
            yield f"data: {json.dumps({'error': 'No interface specified'})}\n\n"
            return

        last_streamed_timestamp = 0
        try:
            while True:
                if interface in interface_data and interface_data[interface]:
                    latest_data = interface_data[interface][-1] 
                    # Only send if it's newer than the last one sent
                    if latest_data['timestamp'] > last_streamed_timestamp:
                        yield f"data: {json.dumps(latest_data)}\n\n"
                        last_streamed_timestamp = latest_data['timestamp']
                time.sleep(1)
        except GeneratorExit:
            logging.info(f"Client disconnected from stream for interface {interface}")
        except Exception as e:
            logging.error(f"Error in stream for interface {interface}: {e}")
            yield f"data: {json.dumps({'error': f'Stream error: {e}'})}\n\n"

    return Response(generate(interface), mimetype='text/event-stream')


if __name__ == '__main__':
    os.makedirs("captures", exist_ok=True)
    os.makedirs("flows", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    # Start the cleanup thread
    cleanup_thread_instance = threading.Thread(target=cleanup_thread, daemon=True)
    cleanup_thread_instance.start()

    # monitor_network('Ethernet 2')

    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True) # Uncommented and enabled debug mode