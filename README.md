# Real-time Network Intrusion Detection System

A real-time network traffic monitoring and intrusion detection system that uses deep learning to detect potential network attacks and anomalies.

## Features

- Real-time network traffic monitoring
- Deep learning-based attack detection
- Interactive web dashboard with:
  - Live packet monitoring
  - Network traffic visualization
  - Attack detection alerts
  - Configurable detection thresholds
- Support for multiple network interfaces
- Real-time packet capture and analysis
- Flow-based traffic analysis using CICFlowMeter

## Components

- **Frontend**: Interactive web dashboard built with HTML, JavaScript, and Bootstrap
- **Backend**: Python-based server using Flask
- **ML Model**: Deep learning model for attack classification
- **Network Analysis**: CICFlowMeter for network flow analysis
- **Data Processing**: Real-time packet capture and preprocessing pipeline

## Technical Stack

- Python
- Flask
- TensorFlow
- Chart.js
- Bootstrap 5
- Server-Sent Events (SSE) for real-time updates
- CICFlowMeter for network flow generation

## Getting Started

1. Ensure you have Python installed
2. Install the required dependencies:
`pip install -r requirements.txt`

3. Run the system:
`python main.py`

4. Access the client application
`http://localhost:5000`