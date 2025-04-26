import os
import subprocess
import logging

def capture_traffic(interface=None, duration=None, output_file=None):
    """
    Capture network traffic using tshark
    Args:
        interface (str): Network interface to capture traffic from
        duration (int): Duration in seconds to capture traffic (None for continuous)
        output_file (str): Path to save the captured packets
    Returns:
        subprocess.Popen: The tshark process
    """
    command = ["tshark", "-l"]
    
    if interface:
        command.extend(["-i", interface])
    
    if duration:
        command.extend(["-a", f"duration:{duration}"])
    
    if output_file:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        command.extend(["-F", "pcap", "-w", output_file])
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return process
    except Exception as e:
        logging.error(f"Failed to start packet capture: {str(e)}")
        return None


def convert_pcap(pcap_file, output_dir='flows/'):
    """
    Convert pcap file to flow file using cicflowmeter
    Args:
        pcap_file (str): Path to the pcap file
        output_file (str): Path to save the flow file (CSV format)
    Returns:
        str: Path to the generated flow file
    """
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
    
    os.makedirs(output_dir, exist_ok=True)

    command = ["cicflowmeter", "-c", "-f", pcap_file, "--dir", output_dir]
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return process
    except Exception as e:
        logging.error(f"Failed to convert pcap to flow: {str(e)}")
        return None


if __name__ == "__main__":
    import time
    
    test_pcap_file = "captures/test_capture.pcap"
    test_flow_dir = "flows/"
    capture_duration = 10
    interface = "Ethernet 2"
    
    print(f"Starting packet capture for {capture_duration} seconds...")
    capture_process = capture_traffic(interface, capture_duration, test_pcap_file)
    
    if capture_process is None:
        print("Failed to start capture!")
        exit(1)
    
    capture_process.wait()
    print("Capture completed!")
    
    print("\nConverting PCAP to flow format...")
    convert_process = convert_pcap(test_pcap_file, test_flow_dir)

    if convert_process is None:
        print("Failed to convert PCAP to flow format!")
        exit(1)

    convert_process.wait()
    print("Conversion completed!")

