import streamlit as st
import pandas as pd
import plotly.express as px
import random
from datetime import datetime, timedelta
import json
import requests
import asyncio
import logging
import ollama
from ollama import ChatResponse
from data.mock_data import create_mock_threat_intel, create_mock_anomalies
from utils.correlation import correlate_findings
from app.dashboard_layout import render_dashboard

logging.basicConfig(level=logging.INFO)

st.set_page_config(layout="wide", page_title="Security Dashboard MVP")

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

# Apply correlation logic
anomalies_df = correlate_findings(threat_intel_df, anomalies_df)

# --- Streamlit App Layout ---
render_dashboard(threat_intel_df, anomalies_df)

# --- Tool/Function Definitions ---
# These are the Python functions the LLM can call.
# They need access to the data currently in the dashboard.

def get_threat_summary(df_threat):
    """Calculates and returns a summary of threat intelligence data."""
    if df_threat is None or df_threat.empty:
        return "No threat intelligence data available to summarize."
    summary = {
        "total_records": int(df_threat.shape[0]),
        "severity_counts": df_threat['severity'].value_counts().to_dict(),
        "ioc_type_counts": df_threat['ioc_type'].value_counts().to_dict(),
        "recent_threat_timestamp": str(df_threat['timestamp'].max()) if not df_threat.empty else "N/A"
    }
    return json.dumps(summary)  # Return results as JSON string for the LLM

def get_anomaly_summary(df_anomaly):
    """Calculates and returns a summary of anomaly data."""
    if df_anomaly is None or df_anomaly.empty:
        return "No anomaly data available to summarize."
    anomalies_detected = df_anomaly[df_anomaly['is_anomaly']]
    summary = {
        "total_anomalies_detected": int(anomalies_detected.shape[0]),
        "anomaly_counts_by_metric": anomalies_detected['metric'].value_counts().to_dict()
    }
    return json.dumps(summary)

def get_anomalies_for_metric(df_anomaly, metric_name):
    """Retrieves specific anomaly details for a given metric."""
    if df_anomaly is None or df_anomaly.empty:
        return f"No anomaly data available for metric: {metric_name}."
    if metric_name not in df_anomaly['metric'].unique():
        return f"Metric '{metric_name}' not found in the anomaly data."

    anomalies = df_anomaly[(df_anomaly['metric'] == metric_name) & (df_anomaly['is_anomaly'])]
    if anomalies.empty:
        return f"No anomalies detected for metric: {metric_name}."

    # Return limited, relevant info as JSON
    return anomalies[['timestamp', 'value']].to_json(orient='records', date_format='iso')

# Map tool names the LLM can use to the actual Python functions
available_tools = {
    "get_threat_summary": get_threat_summary,
    "get_anomaly_summary": get_anomaly_summary,
    "get_anomalies_for_metric": get_anomalies_for_metric,
}

# --- AI Assistant Integration ---

# --- Initialize Session State ---
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "How can I help you analyze the security data?"}]

# --- Chatbot Integration ---
async def stream_chat_with_tools(model, messages):
    try:
        client = ollama.AsyncClient()
        response: ChatResponse = await client.chat(
            model,
            messages=[{"role": m["role"], "content": m["content"]} for m in messages]
        )
        return response.message.content
    except Exception as e:
        logging.error(f"Error during streaming: {str(e)}")
        raise e

def export_chat_history(model, messages):
    if not messages:
        return None

    chat_data = {
        "model": model,
        "timestamp": datetime.now().isoformat(),
        "messages": messages
    }

    return json.dumps(chat_data, indent=2)

# --- Sidebar for Chatbot ---
st.sidebar.title("🤖 AI Assistant")
st.sidebar.markdown("Interact with the AI assistant to query data and gain insights.")

# Initialize session state for chatbot
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "How can I help you analyze the security data?"}]

# Display chat messages in the sidebar
for message in st.session_state.messages:
    with st.sidebar.expander(message["role"].capitalize()):
        st.markdown(message["content"])

# Chat input in the sidebar
if prompt := st.sidebar.text_input("Ask about the data..."):
    # Add user message to state and display
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.sidebar.expander("User"):
        st.markdown(prompt)

    # Prepare the conversation history for the Ollama API
    conversation_history = [
        {"role": message["role"], "content": message["content"]}
        for message in st.session_state.messages
    ]

    try:
        # Call the Ollama API
        response_message = asyncio.run(stream_chat_with_tools("granite3.1-dense:8b", conversation_history))

        # Add assistant response to state and display
        st.session_state.messages.append({"role": "assistant", "content": response_message})
        with st.sidebar.expander("Assistant"):
            st.markdown(response_message)

    except Exception as e:
        st.sidebar.error(f"Error communicating with Ollama API: {e}")
        st.session_state.messages.append({"role": "assistant", "content": f"Sorry, I encountered an error: {e}"})