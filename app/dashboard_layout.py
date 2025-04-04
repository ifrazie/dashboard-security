# This module will contain the Streamlit app layout and logic.
import streamlit as st
import pandas as pd
import plotly.express as px

def render_dashboard(threat_intel_df, anomalies_df):
    """Renders the Streamlit dashboard layout."""
    st.title("🔒 AI-Assisted Security Dashboard")
    st.markdown("Interact with the AI assistant below to query data, identify insights, and get guidance.")

    # Key Metrics Section
    st.header("📊 Key Metrics Overview")
    col1, col2, col3, col4 = st.columns(4)

    total_threats = threat_intel_df.shape[0]
    critical_threats = threat_intel_df[threat_intel_df['severity'] == 'Critical'].shape[0]
    high_threats = threat_intel_df[threat_intel_df['severity'] == 'High'].shape[0]
    total_anomalies = anomalies_df[anomalies_df['is_anomaly']].shape[0]

    col1.metric("Total Threat Intel Records", total_threats)
    col2.metric("Critical Severity Threats", critical_threats)
    col3.metric("High Severity Threats", high_threats)
    col4.metric("Total Anomalies Detected (7d)", total_anomalies)

    st.divider()

    # Threat Intelligence Section
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
    st.caption(f"Displaying {filtered_threat_df.shape[0]} out of {threat_intel_df.shape[0]} threat intel records.")

    st.divider()

    # Threat Intelligence Heatmap
    st.header("🔍 Threat Intelligence Heatmap")

    heatmap_data = threat_intel_df.pivot_table(
        index=threat_intel_df['timestamp'].dt.date,
        columns='severity',
        values='value',
        aggfunc='count',
        fill_value=0
    )

    heatmap_fig = px.imshow(
        heatmap_data,
        labels=dict(x="Severity", y="Date", color="Count"),
        title="Threat Intelligence Heatmap",
        color_continuous_scale="Viridis"
    )

    st.plotly_chart(heatmap_fig, use_container_width=True)

    # Anomaly Detection Section
    st.header("📈 System Anomaly Monitoring (Correlated)")

    metric_to_plot = st.selectbox(
        'Select Metric to Visualize:',
        options=anomalies_df['metric'].unique()
    )

    metric_df = anomalies_df[anomalies_df['metric'] == metric_to_plot].copy()

    fig = px.line(metric_df, x='timestamp', y='value', title=f'Time Series for {metric_to_plot}', markers=False)

    anomalies_points = metric_df[metric_df['is_anomaly']]
    if not anomalies_points.empty:
        fig.add_scatter(
            x=anomalies_points['timestamp'],
            y=anomalies_points['value'],
            mode='markers',
            marker=dict(color='red', size=10, symbol='x'),
            name='Anomaly Detected'
        )

    correlated_points = metric_df[metric_df['correlated_with_ioc']]
    if not correlated_points.empty:
        fig.add_scatter(
            x=correlated_points['timestamp'],
            y=correlated_points['value'],
            mode='markers',
            marker=dict(color='blue', size=12, symbol='circle'),
            name='Correlated with IOC'
        )

    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Value",
        legend_title="Legend"
    )
    fig.update_traces(hovertemplate='<b>Time</b>: %{x}<br><b>Value</b>: %{y}<extra></extra>')

    st.plotly_chart(fig, use_container_width=True)

    show_anomaly_table = st.checkbox("Show Anomaly Details Table for Selected Metric")
    if show_anomaly_table:
        st.dataframe(anomalies_points[['timestamp', 'metric', 'value', 'correlated_with_ioc']], use_container_width=True)

    st.divider()
    st.caption("Dashboard MVP - Data is randomly generated.")