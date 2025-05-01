# Security Dashboard Prototype

This project is a prototype for an interactive security dashboard built using Streamlit. It visualizes threat intelligence data and system anomalies to provide insights into potential security issues.

## Features

- **Key Metrics Overview**: Displays total threat intelligence records, critical and high-severity threats, and detected anomalies.
- **Threat Intelligence Feed**: Interactive table with filters for severity, IOC type, and search functionality.
- **System Anomaly Monitoring**: Time-series visualization of system metrics with anomaly detection.
- **AI Assistant Integration**: Built-in chat interface with an AI assistant that can analyze security data and provide insights.
- **Security Tool Integration**: Includes tools for domain analysis, network scanning, and vulnerability checks.

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```

2. Navigate to the project directory:

   ```bash
   cd dashboard-security
   ```

3. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Install Ollama for the AI integration (follow instructions at https://ollama.com/):
   - Download and install Ollama
   - Pull the required model: `ollama pull granite3.2:8b`

## Usage

1. Run the Streamlit app:

   ```bash
   streamlit run security_dashboard.py
   ```

2. Open the provided URL in your browser to view the dashboard.
3. Interact with the AI assistant in the sidebar to analyze security data.

## Available Tools

The AI assistant can use the following security tools:

- **get_info**: Get information about a domain, including IP address and WHOIS data
- **scan_network**: Scan a network for open ports
- **check_vulnerability**: Check for basic vulnerabilities in a domain
- **sql_injection**: Simulate checking for SQL injection vulnerabilities
- **get_threat_summary**: Get a summary of threat intelligence data
- **get_anomaly_summary**: Get a summary of anomalies detected
- **get_anomalies_for_metric**: Get details about anomalies for a specific metric
- **get_data_overview**: Get a comprehensive overview of all dashboard data

## Running Tests

To run the tests and check coverage, use the following command:

```bash
pytest
```

## Project Structure

```
project-root/
│
├── security_dashboard.py  # Main Streamlit app
├── app/
│   └── dashboard_layout.py  # Dashboard UI components
│
├── data/
│   └── mock_data.py  # Mock data generation functions
│
├── tools/
│   ├── tool_functions.py  # Security tool implementations
│   ├── async_tools.py  # Async processing for tools
│   └── tool_config.yaml  # Tool definitions for the AI
│
├── utils/
│   └── correlation.py  # Functions for data correlation
│
├── tests/  # Test files
│
├── requirements.txt  # Project dependencies
└── README.md  # Project documentation
```

## Requirements

- Python 3.8 or higher
- Streamlit
- Pandas
- Plotly
- Ollama
- Additional packages for security tools:
  - python-whois
  - dnspython
  - python-nmap

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- [Streamlit Documentation](https://docs.streamlit.io/)
- [Plotly Documentation](https://plotly.com/python/)
- [Ollama](https://ollama.com/)
