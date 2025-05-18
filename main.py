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
from collections import defaultdict, deque 
import queue 

from db import get_db_connection, store_attack_details, get_latest_attack_logs
from capture import capture_traffic, convert_pcap
from predict import preprocess_flow, predict_attack, get_label_mapping
# utils.get_latest_csv might be less used if flow file paths are deterministic
# from utils import get_latest_pcap 

# Constants for monitoring
CAPTURE_DURATION = 8
MONITORING_INTERVAL = 1 
CLEANUP_INTERVAL = 30
DB_SYNC_INTERVAL = 60 
MAX_FILES_KEPT = 10
CONFIDENCE_THRESHOLD = 80
PPS_THRESHOLD = 10
CSV_ROWS_THRESHOLD = 10 # Minimum rows in CSV to attempt prediction
DUPLICATE_WINDOW = CAPTURE_DURATION
MAX_LATEST_DATA_POINTS = MAX_FILES_KEPT * 2 # Max points for latest_data deque
MAX_PACKET_QUEUE_SIZE = 500 # Max packets in packet_data deque

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s', datefmt='%H:%M:%S', # Added threadName
    handlers=[
        logging.FileHandler('logs/monitor.log'),
        logging.StreamHandler()
    ]
)

# Initialize db
connection = get_db_connection()

# Load the models
dl_model = tf.keras.models.load_model('lib/deep_learning_model.h5')
label_mapping = get_label_mapping()

# --- Global State for Interface Dominant Monitoring ---
current_active_interface = None
active_monitoring_details = {} # Stores {'capture_thread', 'processing_thread', 'stop_event', 'pcap_queue'}
global_state_lock = threading.Lock() # To protect current_active_interface and active_monitoring_details

# Global variables to store data (can still be defaultdict for simplicity of access)
latest_data = defaultdict(lambda: deque(maxlen=MAX_LATEST_DATA_POINTS)) 
packet_data = defaultdict(lambda: deque(maxlen=MAX_PACKET_QUEUE_SIZE)) 
attack_logs = defaultdict(list) # Global attack logs
attack_logs_lock = threading.Lock()

# Initialize Flask app
app = Flask(__name__)


def get_interfaces():
    """Function to get list of all network interfaces on the system."""
    nics = []
    os_type = platform.system()
    if os_type == 'Linux':
        process = subprocess.Popen(['ip', '-o', 'link', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, _ = process.communicate()
        for line in stdout.splitlines():
            nic_name = line.split(':')[1].strip()
            if nic_name != "lo":
                nics.append(nic_name)
    elif os_type == 'Windows':
        process = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, encoding='utf-8')
        stdout, _ = process.communicate()
        current_adapter = None
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                if line.endswith(':'):
                    current_adapter = line[:-1].strip()
                    if (not any(x in current_adapter for x in ['Loopback', 'Virtual', 'Pseudo', '*', 'vEthernet', 'Bluetooth']) and 'adapter' in current_adapter):
                        adapter_name = current_adapter.split('adapter ')[-1].strip()
                        nics.append(adapter_name)
    else:
        logging.error(f"Unsupported OS: {os_type}")
    return nics


def cleanup_old_files(directory, max_files):
    """Remove old files when exceeding max_files limit"""
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if len(files) > max_files:
            files.sort(key=lambda x: os.path.getmtime(x))
            for f_to_delete in files[:-max_files]:
                try:
                    os.remove(f_to_delete)
                    logging.info(f"Cleaned up old file: {f_to_delete}")
                except PermissionError:
                    logging.warning(f"Could not delete file {f_to_delete} as it is currently in use. Will retry later.")
                except Exception as e_file_delete: # Catch other potential errors during individual file deletion
                    logging.error(f"Error deleting file {f_to_delete}: {e_file_delete}")
    except Exception as e:
        logging.error(f"Error during cleanup in directory {directory}: {e}")

# --- Worker Threads ---
def capture_worker(interface_name, pcap_q, stop_event_ref):
    """Captures traffic and puts pcap file paths onto a queue."""
    logging.info(f"Starting capture on {interface_name}")
    capture_process = None # Initialize to ensure it's defined in finally
    try:
        while not stop_event_ref.is_set():
            timestamp_str = time.strftime("%Y%m%d_%H%M%S")
            # Sanitize interface_name for use in filename
            safe_interface_name = "".join(c if c.isalnum() else "_" for c in interface_name)
            pcap_file_path = os.path.join("captures", f"capture_{safe_interface_name}_{timestamp_str}.pcap")
            
            logging.info(f"Starting capture to {pcap_file_path} for {CAPTURE_DURATION}s")
            capture_process = capture_traffic(interface_name, CAPTURE_DURATION, pcap_file_path)
            
            if capture_process is None:
                logging.error(f"Failed to start capture on {interface_name}")
                if stop_event_ref.wait(MONITORING_INTERVAL): break # Check stop event during sleep
                continue
            
            packet_count = 0
            loop_start_time = time.time()
            last_pps_update_time = loop_start_time
            current_capture_pps = 0

            # Monitor the capture process and read its output
            while capture_process.poll() is None:
                if stop_event_ref.is_set():
                    logging.info(f"Stop event received, terminating capture for {interface_name}.")
                    capture_process.terminate()
                    break
                
                output = capture_process.stdout.readline()
                if output:
                    try:
                        packet_info = output.strip().split(',')
                        if len(packet_info) >= 6:
                            packet = {
                                'timestamp': time.time(),
                                'source': packet_info[2].strip(),
                                'destination': packet_info[3].strip(),
                                'protocol': packet_info[4].strip(),
                                'length': packet_info[5].strip()
                            }
                            packet_data[interface_name].append(packet)
                            packet_count += 1
                    except Exception as e:
                        logging.error(f"Error parsing packet data: {e}, data: {output}")
                        
                    current_loop_time = time.time()
                    time_diff_pps = current_loop_time - last_pps_update_time
                    
                    if time_diff_pps >= 1:
                        time_elapsed_total = current_loop_time - loop_start_time
                        if time_elapsed_total > 0:
                             current_capture_pps = packet_count / time_elapsed_total
                        
                        latest_data[interface_name].append({
                            'timestamp': current_loop_time,
                            'pps': int(current_capture_pps),
                            'predicted_label': 'BENIGN', # Changed from 'Capturing...'
                            'confidence': 100.0          # Changed from 0
                        })
                        # The following block is removed as maxlen handles the size limit:
                        # if len(latest_data[interface_name]) > MAX_LATEST_DATA_POINTS:
                        #     latest_data[interface_name] = latest_data[interface_name][-MAX_LATEST_DATA_POINTS:]
                        last_pps_update_time = current_loop_time
                else: # No output, process might have ended or readline timed out (if non-blocking)
                    time.sleep(0.01) # Small sleep to prevent busy-waiting if readline is non-blocking

            if capture_process: capture_process.wait(timeout=5) # Wait for tshark to finish
            
            if stop_event_ref.is_set(): break # Exit loop if stop was signaled

            total_duration = time.time() - loop_start_time
            final_pps_for_capture = (packet_count / total_duration) if total_duration > 0 else 0
            
            if os.path.exists(pcap_file_path) and os.path.getsize(pcap_file_path) > 0: # Ensure pcap has data
                logging.info(f"Capture finished: {pcap_file_path}, PPS: {final_pps_for_capture:.2f}. Queuing for processing.")
                pcap_q.put((pcap_file_path, int(final_pps_for_capture)))
            else:
                logging.warning(f"PCAP file {pcap_file_path} is empty or does not exist. Skipping.")

            if stop_event_ref.wait(MONITORING_INTERVAL): break # Check stop event during sleep
    except Exception as e:
        logging.error(f"Error in capture_worker for {interface_name}: {e}")
    finally:
        if capture_process and capture_process.poll() is None:
            logging.info(f"Ensuring capture process for {interface_name} is terminated.")
            capture_process.terminate()
            capture_process.wait()
        logging.info(f"Capture worker for {interface_name} stopped.")


def processing_worker(interface_name, pcap_q, stop_event_ref):
    """Processes pcap files from a queue for conversion and prediction."""
    logging.info(f"Starting processing for {interface_name}")
    convert_process = None # Initialize
    try:
        while not stop_event_ref.is_set():
            try:
                pcap_file_path, pps_at_capture = pcap_q.get(timeout=1) # Timeout to check stop_event
            except queue.Empty:
                continue # No item, loop back to check stop_event

            if stop_event_ref.is_set(): break

            logging.info(f"Processing PCAP: {pcap_file_path}, PPS: {pps_at_capture}")
            
            base_pcap_name = os.path.basename(pcap_file_path)
            # CICFlowMeter typically appends "_Flow.csv" or similar to the pcap filename.
            # Ensure this matches the actual output of your convert_pcap / CICFlowMeter setup.
            # Common convention is <pcap_filename>_Flow.csv
            flow_file_name = base_pcap_name + "_Flow.csv" 
            
            # Corrected path: CICFlowMeter is configured to output to the "flows" directory
            flow_file_to_process = os.path.join("flows", flow_file_name)

            logging.info(f"Converting PCAP to flow: {pcap_file_path}, expecting CSV at: {flow_file_to_process}")
            convert_process = convert_pcap(pcap_file_path) # convert_pcap should manage its subprocess
            
            if convert_process is None:
                logging.error(f"Failed to start PCAP conversion for {pcap_file_path}")
                pcap_q.task_done()
                continue
            
            # Wait for conversion, but periodically check stop_event
            while convert_process.poll() is None:
                if stop_event_ref.is_set():
                    logging.info(f"Stop event received, terminating conversion for {pcap_file_path}.")
                    convert_process.terminate()
                    break
                time.sleep(0.1)
            if convert_process: convert_process.wait(timeout=5)

            if stop_event_ref.is_set():
                pcap_q.task_done()
                break

            if os.path.exists(flow_file_to_process) and os.path.getsize(flow_file_to_process) > 0:
                logging.info(f"Processing flow file: {flow_file_to_process}")
                X = preprocess_flow(flow_file_to_process)
                
                attack_type = 'BENIGN' # Default
                confidence = 100.0   # Default

                if X.shape[0] <= CSV_ROWS_THRESHOLD:
                    logging.warning(f"Not enough data ({X.shape[0]} rows) in {flow_file_to_process} to predict.")
                else:
                    pred_label_per_flow, pred_probs_per_flow = predict_attack(X, dl_model)
                    
                    if pred_probs_per_flow.ndim == 1:
                        pred_probs_per_flow = np.expand_dims(pred_probs_per_flow, axis=0)

                    if pred_probs_per_flow.shape[0] > 0:
                        average_confidence_per_class = np.mean(pred_probs_per_flow, axis=0)
                        dominant_class_index = np.argmax(average_confidence_per_class)
                        attack_type = label_mapping[dominant_class_index]
                        confidence = average_confidence_per_class[dominant_class_index] * 100
                
                latest_data[interface_name].append({
                    'timestamp': time.time(), 'pps': pps_at_capture, 
                    'predicted_label': attack_type, 'confidence': round(float(confidence), 2),
                })
                # The following block is removed as maxlen handles the size limit:
                # if len(latest_data[interface_name]) > MAX_LATEST_DATA_POINTS:
                #      latest_data[interface_name] = latest_data[interface_name][-MAX_LATEST_DATA_POINTS:]
                
                logging.info(f"DL Model: {attack_type} (Conf: {confidence:.2f}%) from {flow_file_to_process}")
                
                if confidence > CONFIDENCE_THRESHOLD and pps_at_capture > PPS_THRESHOLD and str.lower(attack_type) != "benign":
                    logging.warning(f"HIGH CONFIDENCE ATTACK: {attack_type} on {interface_name}")
                    log_timestamp = time.time()
                    with attack_logs_lock:
                        # Simplified duplicate check for this example
                        is_duplicate = any(
                            att['attack_type'] == attack_type and abs(att['timestamp'] - log_timestamp) < DUPLICATE_WINDOW
                            for att in attack_logs.get(interface_name, []) # Check logs for this interface if stored that way, or global
                        ) # Or check global attack_logs['attacks']
                        
                        if not is_duplicate: # For global logs, check attack_logs['attacks']
                            log_entry = {
                                'attack_type': attack_type, 
                                'confidence': round(float(confidence), 2),
                                'interface': interface_name, 
                                'timestamp': log_timestamp, 
                                'pps': pps_at_capture,
                            }
                            attack_logs['attacks'].append(log_entry) # Append to global log
                            if len(attack_logs['attacks']) > MAX_FILES_KEPT * 5:
                                attack_logs['attacks'] = attack_logs['attacks'][-(MAX_FILES_KEPT*5):]
            else:
                logging.error(f"Converted CSV file not found or empty: {flow_file_to_process}")

            pcap_q.task_done()
        
    except ValueError as ve:
        logging.error(f"ValueError in processing_worker for {interface_name}: {ve}")
        if 'pcap_q' in locals() and not pcap_q.empty(): pcap_q.task_done() # Ensure task_done if item was dequeued
    except Exception as e:
        logging.error(f"Error in processing_worker for {interface_name}: {e}")
        if 'pcap_q' in locals() and not pcap_q.empty(): pcap_q.task_done()
    finally:
        if convert_process and convert_process.poll() is None:
            logging.info(f"Ensuring conversion process for {interface_name} is terminated.")
            convert_process.terminate()
            convert_process.wait()
        logging.info(f"Processing worker for {interface_name} stopped.")

# --- Background System Threads ---
def cleanup_thread_func():
    """Periodic cleanup of capture and flow files"""
    while True:
        cleanup_old_files("captures", MAX_FILES_KEPT)
        cleanup_old_files("flows", MAX_FILES_KEPT) 
        time.sleep(CLEANUP_INTERVAL)

def sync_database_func():
    """Thread to sync attack logs with database"""
    while True:
        try:
            logs_to_sync_copy = []
            with attack_logs_lock:
                if attack_logs.get('attacks'): # Check if 'attacks' key exists
                    logs_to_sync_copy = list(attack_logs['attacks']) 
                    attack_logs['attacks'] = [] 
            
            if logs_to_sync_copy:
                logging.info(f"Syncing {len(logs_to_sync_copy)} attack logs to DB.")
                # Ensure DB connection is valid
                global connection
                if connection is None or (hasattr(connection, 'is_connected') and not connection.is_connected()): # MySQL check
                    logging.warning("DB connection lost. Attempting to reconnect for sync.")
                    connection = get_db_connection()
                
                if connection is None: # If still no connection
                    logging.error("Failed to reconnect to DB for sync. Logs will be retried later.")
                    with attack_logs_lock: # Put logs back if sync failed
                        attack_logs['attacks'].extend(logs_to_sync_copy)
                    time.sleep(DB_SYNC_INTERVAL) # Wait before retrying
                    continue

                for log_entry in logs_to_sync_copy:
                    datetime_obj = time.localtime(log_entry['timestamp'])
                    datetime_str = time.strftime('%Y-%m-%d %H:%M:%S', datetime_obj)
                    store_attack_details(connection, log_entry['attack_type'], log_entry['confidence'], log_entry['interface'], datetime_str)
                logging.info(f"DB Sync Complete for {len(logs_to_sync_copy)} logs.")
            
            time.sleep(DB_SYNC_INTERVAL)
        except Exception as e:
            logging.error(f"Error in Database Sync Thread: {e}")
            time.sleep(DB_SYNC_INTERVAL)


# --- Flask API ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_interfaces')
def get_interfaces_route():
    interfaces = get_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring_route():
    global current_active_interface, active_monitoring_details
    data = request.get_json()
    new_interface_to_monitor = data.get('interface')

    if not new_interface_to_monitor:
        return jsonify({'error': 'No interface specified'}), 400

    with global_state_lock:
        if current_active_interface == new_interface_to_monitor and active_monitoring_details:
            # Check if threads are alive
            details = active_monitoring_details
            if details['capture_thread'].is_alive() and details['processing_thread'].is_alive():
                logging.info(f"Monitoring is already active and healthy on {new_interface_to_monitor}.")
                return jsonify({'message': f'Monitoring is already active on {new_interface_to_monitor}'}), 200
            else:
                logging.warning(f"Monitoring on {new_interface_to_monitor} was marked active, but threads are dead. Restarting.")
                # Proceed to stop and restart

        # Stop existing monitoring if different interface or restarting
        if active_monitoring_details:
            logging.info(f"Stopping existing monitoring on {current_active_interface} to switch to {new_interface_to_monitor}.")
            details = active_monitoring_details
            details['stop_event'].set() # Signal threads to stop

            # Wait for threads to terminate
            details['capture_thread'].join(timeout=10)
            details['processing_thread'].join(timeout=10)

            if details['capture_thread'].is_alive():
                logging.warning(f"Capture thread for {current_active_interface} did not stop gracefully.")
            if details['processing_thread'].is_alive():
                logging.warning(f"Processing thread for {current_active_interface} did not stop gracefully.")

            # Clear data for the old interface
            if current_active_interface:
                latest_data.pop(current_active_interface, None)
                packet_data.pop(current_active_interface, None)
                # attack_logs are global, so not cleared per interface, but new logs won't come from old one.
            
            active_monitoring_details = {} # Clear details of old monitoring

        logging.info(f"Starting new monitoring on {new_interface_to_monitor}")
        current_active_interface = new_interface_to_monitor
        
        stop_event = threading.Event()
        pcap_processing_queue = queue.Queue(maxsize=MAX_FILES_KEPT * 2)

        capture_thread_instance = threading.Thread(
            target=capture_worker, 
            args=(current_active_interface, pcap_processing_queue, stop_event), 
            daemon=True,
            name=f"Capture-{current_active_interface[:10]}"
        )
        processing_thread_instance = threading.Thread(
            target=processing_worker, 
            args=(current_active_interface, pcap_processing_queue, stop_event), 
            daemon=True,
            name=f"Process-{current_active_interface[:10]}"
        )
        
        active_monitoring_details = {
            'capture_thread': capture_thread_instance,
            'processing_thread': processing_thread_instance,
            'stop_event': stop_event,
            'pcap_queue': pcap_processing_queue
        }
        
        capture_thread_instance.start()
        processing_thread_instance.start()

    return jsonify({'message': f'Started monitoring on {new_interface_to_monitor}'})

@app.route('/get_latest_data')
def get_latest_data_route():
    interface_param = request.args.get('interface')
    with global_state_lock: # Ensure consistency with current_active_interface
        if not interface_param:
            return jsonify({'error': 'No interface specified'}), 400
        # Optionally, only serve data if interface_param == current_active_interface
        # if interface_param != current_active_interface:
        #     return jsonify({'data': [], 'message': f'Interface {interface_param} is not actively monitored.'})

    data_deque = latest_data.get(interface_param)
    
    if not data_deque: # If deque is None or empty
        return jsonify({'data': []})

    # Convert deque to list to allow indexing
    data_list = list(data_deque)
    if not data_list: # If list is empty after conversion
        return jsonify({'data': []})

    # Return only the very last (most recent) record
    return jsonify({'data': [data_list[-1]]})

@app.route('/get_attack_logs')
def get_attack_logs_route():
    with attack_logs_lock:
        logs_to_return = list(attack_logs.get('attacks', [])) # Return a copy
    return jsonify(logs_to_return)


@app.route('/stream_packets')
def stream_packets_route():
    interface_stream_param = request.args.get('interface')

    def generate_packet_stream(target_interface):
        if not target_interface:
            yield f"data: {json.dumps({'error': 'No interface specified for stream'})}\n\n"
            return

        logging.info(f"Client connected to packet stream for interface {target_interface}")
        try:
            while True:
                # Check if monitoring on this interface is still active, or if interface has changed
                with global_state_lock:
                    if target_interface != current_active_interface:
                        logging.info(f"Packet stream for {target_interface} stopping, active interface changed to {current_active_interface}")
                        yield f"data: {json.dumps({'message': 'Monitoring on this interface stopped or changed.'})}\n\n"
                        break
                
                if target_interface in packet_data and packet_data[target_interface]:
                    try:
                        packet_item = packet_data[target_interface].popleft()
                        yield f"data: {json.dumps(packet_item)}\n\n"
                    except IndexError: # Deque was empty
                        time.sleep(0.1)
                else:
                    time.sleep(0.1) 
        except GeneratorExit:
            logging.info(f"Client disconnected from packet stream for interface {target_interface}")
        except Exception as e_stream:
            logging.error(f"Error in packet stream for interface {target_interface}: {e_stream}")
            try:
                yield f"data: {json.dumps({'error': f'Stream error: {str(e_stream)}'})}\n\n"
            except Exception: 
                pass
    return Response(generate_packet_stream(interface_stream_param), mimetype='text/event-stream')


if __name__ == '__main__':
    os.makedirs("captures", exist_ok=True)
    os.makedirs("flows", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    cleanup_daemon = threading.Thread(target=cleanup_thread_func, daemon=True, name="CleanupThread")
    cleanup_daemon.start()
    
    sync_daemon = threading.Thread(target=sync_database_func, daemon=True, name="DatabaseSyncThread")
    sync_daemon.start()

    logging.info("Starting Flask app...")
    app.run(host='localhost', port=5000, debug=False, use_reloader=False)