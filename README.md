# Security Dashboard Prototype

This project is a prototype for an interactive security dashboard built using Streamlit. It visualizes threat intelligence data and system anomalies to provide insights into potential security issues.

## Features

- **Key Metrics Overview**: Displays total threat intelligence records, critical and high-severity threats, and detected anomalies.
- **Threat Intelligence Feed**: Interactive table with filters for severity, IOC type, and search functionality.
- **System Anomaly Monitoring**: Time-series visualization of system metrics with anomaly detection.

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```plaintext

2. Navigate to the project directory:

   ```bash
   cd dashboard-security
   ```plaintext

3. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```plaintext

4. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```plaintext

## Usage

1. Run the Streamlit app:

   ```bash
   streamlit run src/security_dashboard.py
   ```

2. Open the provided URL in your browser to view the dashboard.

## Running Tests

To run the tests and check coverage, use the following command:

```bash
pytest
```

## Project Structure

```bash
project-root/
│
├── src/
│   ├── security_dashboard.py  # Main Streamlit app
│   └── data/
│       └── mock_data.py       # Mock data generation (if applicable)
│
├── .gitignore                 # Git ignore file
└── README.md                  # Project documentation
```

## Requirements

- Python 3.8 or higher
- Streamlit
- Pandas
- Plotly
- Pytest

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- [Streamlit Documentation](https://docs.streamlit.io/)
- [Plotly Documentation](https://plotly.com/python/)
