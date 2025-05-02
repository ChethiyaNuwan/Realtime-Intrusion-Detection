import os
import subprocess
import logging
import time
from utils import get_latest_pcap

def capture_traffic(interface=None, duration=None, output_file=None):
    """
    Capture network traffic using tshark with real-time output
    """
    command = ["tshark", "-l"]
    
    if interface:
        command.extend(["-i", interface])
    
    if duration:
        command.extend(["-a", f"duration:{duration}"])
    
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        command.extend(["-F", "pcap", "-w", output_file])
    
    command.extend(["-T", "fields", "-E", "separator=,", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "frame.len"])
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        error = process.stderr.readline()
        if error and "error" in error.lower():
            raise Exception(f"Tshark error: {error}")

        return process
    except Exception as e:
        logging.error(f"Failed to start packet capture: {str(e)}")
        return None


def convert_pcap(pcap_file_path, output_dir='flows/'):
    """
    Convert pcap file to flow file using cicflowmeter
    Args:
        pcap_file_path (str): Path to the pcap file to be converted
        output_dir (str): Directory path to save the generated flow files (CSV format), defaults to 'flows/'
    Returns:
        subprocess.Popen: The cicflowmeter process object, or None if conversion fails
    Raises:
        FileNotFoundError: If the specified PCAP file does not exist
        Exception: If cicflowmeter command fails to execute
    """
    if not os.path.exists(pcap_file_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file_path}")
    
    os.makedirs(output_dir, exist_ok=True)

    cicflowmeter_path = os.path.join('lib', 'CICFlowmeter', 'bin', 'cfm.bat')
    
    if not os.path.exists(cicflowmeter_path):
        raise FileNotFoundError(f"CICFlowmeter not found at: {cicflowmeter_path}")
    
    command = [cicflowmeter_path, pcap_file_path, output_dir]
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True
        )
        error = process.stderr.readline()
        if error:
            logging.exception(f"CICFlowmeter error: {error}")
        return process
    except Exception as e:
        logging.error(f"Failed to convert pcap to flow: {str(e)}")
        return None


if __name__ == "__main__":
    pcap_dir = "captures"
    flow_dir = "flows"
    os.makedirs(pcap_dir, exist_ok=True)
    os.makedirs(flow_dir, exist_ok=True)
    
    # Generate timestamp for pcap file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(pcap_dir, f"capture_{timestamp}.pcap")
    
    capture_duration = 10
    interface = None
    
    print(f"Starting packet capture for {capture_duration} seconds...")
    capture_process = capture_traffic(interface, capture_duration, pcap_file)
    
    if capture_process is None:
        print("Failed to start capture!")
        exit(1)
    
    capture_process.wait()
    print(f"Capture completed! Saved to: {pcap_file}")
    
    print("\nConverting PCAP to flow format...")
    latest_pcap = get_latest_pcap(pcap_dir)
    if latest_pcap is None:
        print("No pcap files found in captures directory!")
        exit(1)
        
    convert_process = convert_pcap(latest_pcap, flow_dir)

    if convert_process is None:
        print("Failed to convert PCAP to flow format!")
        exit(1)

    convert_process.wait()
    print("Conversion completed!")