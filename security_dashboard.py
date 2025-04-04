import streamlit as st
import pandas as pd
import plotly.express as px
import random
from datetime import datetime, timedelta

st.set_page_config(layout="wide", page_title="Security Dashboard MVP")

# --- Mock Data Generation Functions ---
def create_mock_threat_intel(num_records=100):
    """
    Generates mock threat intelligence data.

    Args:
        num_records (int): Number of threat intelligence records to generate.

    Returns:
        pd.DataFrame: A DataFrame containing mock threat intelligence data.
    """
    data = []
    ioc_types = ['ip_address', 'domain', 'file_hash', 'url']
    severities = ['Low', 'Medium', 'High', 'Critical']
    threat_actors = ['APT_Shadow', 'CrimsonSpider', 'GenericBotnet', 'PhishingGroupX', None] # None represents unknown
    base_time = datetime.now()

    for i in range(num_records):
        ioc_type = random.choice(ioc_types)
        if ioc_type == 'ip_address':
            value = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif ioc_type == 'domain':
            value = f"malicious-domain-{random.randint(100, 999)}.com"
        elif ioc_type == 'file_hash':
            value = ''.join(random.choices('abcdef0123456789', k=64)) # SHA256 example
        else: # url
            value = f"http://{random.choice(['evil-site', 'phish-central', 'update-service'])}/payload{random.randint(1, 100)}.exe"

        data.append({
            'timestamp': base_time - timedelta(days=random.randint(0, 30), hours=random.randint(0,23)),
            'ioc_type': ioc_type,
            'value': value,
            'severity': random.choice(severities),
            'threat_actor': random.choice(threat_actors) if random.random() > 0.3 else None, # Make None more frequent
            'source': random.choice(['Internal Scan', 'OSINT Feed', 'Partner Intel'])
        })
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values(by='timestamp', ascending=False)

def create_mock_anomalies(days=7, points_per_day=24):
    """
    Generates mock time-series anomaly data.

    Args:
        days (int): Number of days to generate data for.
        points_per_day (int): Number of data points per day.

    Returns:
        pd.DataFrame: A DataFrame containing mock anomaly data.
    """
    data = []
    metrics = ['login_failures', 'egress_traffic_mb', 'cpu_utilization_percent']
    base_time = datetime.now() - timedelta(days=days)
    time_increment = timedelta(days=days) / (days * points_per_day) # More regular time steps

    current_time = base_time
    for _ in range(days * points_per_day):
        for metric in metrics:
            # Add small random jitter to timestamp
            ts = current_time + timedelta(minutes=random.randint(-10, 10))
            is_anomaly = False
            if metric == 'login_failures':
                value = random.gauss(5, 2)
                if random.random() < 0.03:
                    value = random.gauss(25, 5)
                    is_anomaly = True
            elif metric == 'egress_traffic_mb':
                value = random.gauss(100, 20)
                if random.random() < 0.02:
                    value = random.gauss(500, 50)
                    is_anomaly = True
            else: # cpu_utilization_percent
                value = random.gauss(30, 10)
                if random.random() < 0.04:
                     value = random.gauss(90, 5)
                     is_anomaly = True

            value = max(0, value)
            if metric == 'cpu_utilization_percent':
                 value = min(100, value)

            data.append({
                'timestamp': ts,
                'metric': metric,
                'value': round(value, 2),
                'is_anomaly': is_anomaly
            })
        current_time += time_increment # Move to the next time step

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values(by='timestamp')

# --- Generate the data ---
@st.cache_data
def load_data():
    """
    Loads and caches the mock data for threat intelligence and anomalies.

    Returns:
        tuple: A tuple containing two DataFrames:
            - threat_intel_df: Mock threat intelligence data.
            - anomalies_df: Mock anomaly data.
    """
    threat_intel_df = create_mock_threat_intel(250) # More data points
    anomalies_df = create_mock_anomalies(7) # Data for the last 7 days
    return threat_intel_df, anomalies_df

threat_intel_df, anomalies_df = load_data()

# --- Correlation Logic ---
def correlate_findings(threat_intel_df, anomalies_df):
    """
    Correlates anomalies with recent critical IOCs.

    Args:
        threat_intel_df (pd.DataFrame): Threat intelligence data.
        anomalies_df (pd.DataFrame): Anomaly data.

    Returns:
        pd.DataFrame: Anomalies with an additional column indicating correlation with critical IOCs.
    """
    # Filter for recent critical IOCs (last 7 days)
    recent_critical_iocs = threat_intel_df[
        (threat_intel_df['severity'] == 'Critical') &
        (threat_intel_df['timestamp'] >= datetime.now() - timedelta(days=7))
    ]

    # Extract unique IOC values (e.g., IPs, domains) from recent critical IOCs
    ioc_values = set(recent_critical_iocs['value'])

    # Add a correlation column to anomalies_df
    anomalies_df['correlated_with_ioc'] = anomalies_df['metric'].apply(
        lambda metric: any(ioc in metric for ioc in ioc_values)
    )

    return anomalies_df

# Apply correlation logic
anomalies_df = correlate_findings(threat_intel_df, anomalies_df)

# --- Streamlit App Layout ---
st.title("🛡️ Interactive Security Dashboard")
st.markdown("Visualize threat intelligence and system anomalies.")

# --- Key Metrics Section ---
st.header("📊 Key Metrics Overview")
col1, col2, col3, col4 = st.columns(4)

# Calculate metrics (using the full dataset for overview)
total_threats = threat_intel_df.shape[0]
critical_threats = threat_intel_df[threat_intel_df['severity'] == 'Critical'].shape[0]
high_threats = threat_intel_df[threat_intel_df['severity'] == 'High'].shape[0]
total_anomalies = anomalies_df[anomalies_df['is_anomaly']].shape[0]

col1.metric("Total Threat Intel Records", total_threats)
col2.metric("Critical Severity Threats", critical_threats)
col3.metric("High Severity Threats", high_threats)
col4.metric("Total Anomalies Detected (7d)", total_anomalies)

st.divider() # Visual separator

# --- Threat Intelligence Section ---
st.header("🔍 Threat Intelligence Feed")

# Filters
col_filter1, col_filter2, col_filter3 = st.columns(3)
with col_filter1:
    selected_severity = st.multiselect(
        'Filter by Severity:',
        options=threat_intel_df['severity'].unique(),
        default=threat_intel_df['severity'].unique()
    )
with col_filter2:
    selected_ioc_type = st.multiselect(
        'Filter by IOC Type:',
        options=threat_intel_df['ioc_type'].unique(),
        default=threat_intel_df['ioc_type'].unique()
    )
with col_filter3:
    # Simple text search on the 'value' column
    search_term = st.text_input("Search IOC Value (contains):", placeholder="e.g., 192.168, .exe, evil-site")

# Apply filters
filtered_threat_df = threat_intel_df[
    threat_intel_df['severity'].isin(selected_severity) &
    threat_intel_df['ioc_type'].isin(selected_ioc_type)
]
if search_term:
    filtered_threat_df = filtered_threat_df[filtered_threat_df['value'].str.contains(search_term, case=False, na=False)]


# Display filtered data
st.dataframe(filtered_threat_df, use_container_width=True)
st.caption(f"Displaying {filtered_threat_df.shape[0]} out of {total_threats} threat intel records.")

st.divider()

# Add a heatmap visualization for threat intelligence data
st.header("🔍 Threat Intelligence Heatmap")

# Create a pivot table for heatmap visualization
heatmap_data = threat_intel_df.pivot_table(
    index=threat_intel_df['timestamp'].dt.date,  # Group by date
    columns='severity',
    values='value',
    aggfunc='count',  # Count the number of records per severity level
    fill_value=0
)

# Create the heatmap using Plotly Express
heatmap_fig = px.imshow(
    heatmap_data,
    labels=dict(x="Severity", y="Date", color="Count"),
    title="Threat Intelligence Heatmap",
    color_continuous_scale="Viridis"
)

# Display the heatmap
st.plotly_chart(heatmap_fig, use_container_width=True)

# --- Anomaly Detection Section ---
st.header("📈 System Anomaly Monitoring (Correlated)")

# Select metric to visualize
metric_to_plot = st.selectbox(
    'Select Metric to Visualize:',
    options=anomalies_df['metric'].unique()
)

# Filter data for the selected metric
metric_df = anomalies_df[anomalies_df['metric'] == metric_to_plot].copy()

# Create the plot using Plotly Express
fig = px.line(metric_df, x='timestamp', y='value', title=f'Time Series for {metric_to_plot}', markers=False)

# Add markers for anomalies
anomalies_points = metric_df[metric_df['is_anomaly']]
if not anomalies_points.empty:
    fig.add_scatter(
        x=anomalies_points['timestamp'],
        y=anomalies_points['value'],
        mode='markers',
        marker=dict(color='red', size=10, symbol='x'),
        name='Anomaly Detected'
    )

# Highlight correlated anomalies
correlated_points = metric_df[metric_df['correlated_with_ioc']]
if not correlated_points.empty:
    fig.add_scatter(
        x=correlated_points['timestamp'],
        y=correlated_points['value'],
        mode='markers',
        marker=dict(color='blue', size=12, symbol='circle'),
        name='Correlated with IOC'
    )

# Improve layout and axes
fig.update_layout(
    xaxis_title="Time",
    yaxis_title="Value",
    legend_title="Legend"
)
fig.update_traces(hovertemplate='<b>Time</b>: %{x}<br><b>Value</b>: %{y}<extra></extra>')

st.plotly_chart(fig, use_container_width=True)

# Optionally display anomaly details in a table
show_anomaly_table = st.checkbox("Show Anomaly Details Table for Selected Metric")
if show_anomaly_table:
    st.dataframe(anomalies_points[['timestamp', 'metric', 'value', 'correlated_with_ioc']], use_container_width=True)

st.divider()
st.caption("Dashboard MVP - Data is randomly generated.")