import os
from cicflowmeter.sniffer import parse_pcap

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
        command.extend(["-F pcap -w", output_file])
    
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


def convert_pcap(pcap_file, output_file=None):
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
    
    if output_file is None:
        output_file = os.path.splitext(pcap_file)[0] + '_flows.csv'
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        parse_pcap(pcap_file, output_file)
        return output_file
    except Exception as e:
        logging.error(f"Failed to convert pcap to flow: {str(e)}")
        return None


if __name__ == "__main__":
    import time
    
    test_pcap = "test_capture.pcap"
    test_flow = "test_flows.csv"
    capture_duration = 10
    
    print(f"Starting packet capture for {capture_duration} seconds...")
    
    process = capture_traffic(
        interface="Ethernet 2",
        duration=capture_duration,
        output_file=test_pcap
    )
    
    if process is None:
        print("Failed to start capture!")
        exit(1)
    
    process.wait()
    print("Capture completed!")
    
    print("\nConverting PCAP to flow format...")
    flow_file = convert_pcap(test_pcap, test_flow)
    
    if flow_file:
        print(f"Success! Flow file created at: {flow_file}")
    else:
        print("Failed to convert PCAP to flow format!")

