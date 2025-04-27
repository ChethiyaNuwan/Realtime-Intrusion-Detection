import os

def get_latest_pcap(pcap_dir):
    """
    Get the latest pcap file from the specified directory
    Args:
        pcap_dir (str): Directory containing pcap files
    Returns:
        str: Path to the latest pcap file, or None if no pcap files found
    """
    if not os.path.exists(pcap_dir):
        return None
        
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
    if not pcap_files:
        return None
        
    latest_pcap = max(pcap_files, key=lambda x: os.path.getctime(os.path.join(pcap_dir, x)))
    return os.path.join(pcap_dir, latest_pcap)

def get_latest_csv(csv_dir):
    """
    Get the latest CSV file from the specified directory
    Args:
        csv_dir (str): Directory containing CSV files
    Returns:
        str: Path to the latest CSV file, or None if no CSV files found
    """
    if not os.path.exists(csv_dir):
        return None
        
    csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]
    if not csv_files:
        return None
        
    latest_csv = max(csv_files, key=lambda x: os.path.getctime(os.path.join(csv_dir, x)))
    return os.path.join(csv_dir, latest_csv)