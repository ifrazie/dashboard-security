import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json
import asyncio
import logging
import ollama
from ollama import ChatResponse
from data.mock_data import create_mock_threat_intel, create_mock_anomalies
from utils.correlation import correlate_findings
from app.dashboard_layout import render_dashboard

# Import tools and async processing functions
from tools.tool_functions import available_functions
from tools.async_tools import process_tool_calls
import yaml

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
# Updated to access data directly rather than requiring it as parameters

def get_threat_summary():
    """Calculates and returns a summary of threat intelligence data."""
    df_threat = threat_intel_df
    if df_threat is None or df_threat.empty:
        return "No threat intelligence data available to summarize."
    summary = {
        "total_records": int(df_threat.shape[0]),
        "severity_counts": df_threat['severity'].value_counts().to_dict(),
        "ioc_type_counts": df_threat['ioc_type'].value_counts().to_dict(),
        "recent_threat_timestamp": str(df_threat['timestamp'].max()) if not df_threat.empty else "N/A"
    }
    return json.dumps(summary)  # Return results as JSON string for the LLM

def get_anomaly_summary():
    """Calculates and returns a summary of anomaly data."""
    df_anomaly = anomalies_df
    if df_anomaly is None or df_anomaly.empty:
        return "No anomaly data available to summarize."
    anomalies_detected = df_anomaly[df_anomaly['is_anomaly']]
    summary = {
        "total_anomalies_detected": int(anomalies_detected.shape[0]),
        "anomaly_counts_by_metric": anomalies_detected['metric'].value_counts().to_dict()
    }
    return json.dumps(summary)

def get_anomalies_for_metric(metric_name):
    """Retrieves specific anomaly details for a given metric."""
    df_anomaly = anomalies_df
    if df_anomaly is None or df_anomaly.empty:
        return f"No anomaly data available for metric: {metric_name}."
    if metric_name not in df_anomaly['metric'].unique():
        return f"Metric '{metric_name}' not found in the anomaly data."

    anomalies = df_anomaly[(df_anomaly['metric'] == metric_name) & (df_anomaly['is_anomaly'])]
    if anomalies.empty:
        return f"No anomalies detected for metric: {metric_name}."

    # Return limited, relevant info as JSON
    return anomalies[['timestamp', 'value']].to_json(orient='records', date_format='iso')

def get_data_overview():
    """Provides a general overview of all available data in the dashboard."""
    threat_summary = json.loads(get_threat_summary())
    anomaly_summary = json.loads(get_anomaly_summary())
    
    # Extract unique metrics
    metrics = anomalies_df['metric'].unique().tolist() if not anomalies_df.empty else []
    
    # Create a comprehensive overview
    overview = {
        "threat_intel": threat_summary,
        "anomalies": anomaly_summary,
        "available_metrics": metrics,
        "data_timespan": {
            "start": str(anomalies_df['timestamp'].min()) if not anomalies_df.empty else "N/A",
            "end": str(anomalies_df['timestamp'].max()) if not anomalies_df.empty else "N/A"
        }
    }
    
    return json.dumps(overview)

# Map tool names the LLM can use to the actual Python functions
dashboard_tools = {
    "get_threat_summary": get_threat_summary,
    "get_anomaly_summary": get_anomaly_summary,
    "get_anomalies_for_metric": get_anomalies_for_metric,
    "get_data_overview": get_data_overview
}

# Load tool configuration from YAML file
def load_tool_config():
    try:
        with open('tools/tool_config.yaml', 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Error loading tool config: {str(e)}")
        return {"tools": []}

# Combine all tools from documentation and dashboard
all_tools = {**available_functions, **dashboard_tools}
tool_config = load_tool_config()

# --- AI Assistant Integration ---

# --- Initialize Session State ---
if "messages" not in st.session_state:
    # Start with an empty list or initialize with a welcome message
    st.session_state.messages = [{"role": "assistant", "content": "How can I help you analyze the security data?"}]

# --- Chatbot Integration ---
async def stream_chat_with_tools(model, messages):
    try:
        client = ollama.AsyncClient()
        response = await client.chat(
            model,
            messages=[{"role": m["role"], "content": m["content"]} for m in messages]
        )
        
        # Check if the response contains tool calls and process them
        if hasattr(response.message, 'tool_calls') and response.message.tool_calls:
            return await process_tool_calls(client, model, messages, response, external_tools=dashboard_tools)
        
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

def get_data_context():
    """Generate a concise data context message for the LLM"""
    # Get basics about the data
    metrics = anomalies_df['metric'].unique().tolist() if not anomalies_df.empty else []
    threat_types = threat_intel_df['ioc_type'].unique().tolist() if not threat_intel_df.empty else []
    
    context = {
        "dashboard_data": {
            "threat_intel_count": len(threat_intel_df) if not threat_intel_df.empty else 0,
            "anomaly_count": len(anomalies_df) if not anomalies_df.empty else 0,
            "available_metrics": metrics,
            "threat_types": threat_types,
            "time_range": {
                "start": str(anomalies_df['timestamp'].min()) if not anomalies_df.empty else "N/A",
                "end": str(anomalies_df['timestamp'].max()) if not anomalies_df.empty else "N/A"
            }
        },
        "available_tools": [tool["name"] for tool in tool_config.get("tools", [])],
    }
    
    return json.dumps(context, indent=2)

# --- Sidebar for Chatbot ---
st.sidebar.title("🤖 AI Assistant")
st.sidebar.markdown("Interact with the AI assistant to query data and gain insights.")

# Display available tools in the sidebar for reference
with st.sidebar.expander("Available Security Tools"):
    for tool in tool_config.get("tools", []):
        st.markdown(f"**{tool['name']}**: {tool['description']}")

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
    
    # Add data context to the conversation for the LLM
    # Insert context right before the user's latest message
    if len(conversation_history) > 1:
        # Create a system message with current data context
        data_context = {"role": "system", "content": f"Current data context:\n{get_data_context()}"}
        
        # Insert before the last user message
        conversation_history.insert(-1, data_context)

    try:
        # Call the Ollama API with tool support
        response_message = asyncio.run(stream_chat_with_tools("granite3.2:8b", conversation_history))

        # Add assistant response to state and display
        st.session_state.messages.append({"role": "assistant", "content": response_message})
        with st.sidebar.expander("Assistant"):
            st.markdown(response_message)

    except Exception as e:
        st.sidebar.error(f"Error communicating with Ollama API: {e}")
        st.session_state.messages.append({"role": "assistant", "content": f"Sorry, I encountered an error: {e}"})