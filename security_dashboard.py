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
from tools.tool_functions import available_functions, get_threat_summary, get_anomaly_summary, get_anomalies_for_metric, get_data_overview
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
    # Start with an empty list or initialize with a welcome message and a system message instructing about tool usage
    st.session_state.messages = [
        {"role": "system", "content": """You are an AI assistant with access to security analysis tools. 
You can and should directly execute these tools when users ask about security data. 
DO NOT explain how to use the tools - instead, call them directly. 
For example, if a user asks about threats, call the get_threat_summary tool.
Available tools: get_threat_summary, get_anomaly_summary, get_anomalies_for_metric, get_data_overview, 
get_info, scan_network, check_vulnerability, sql_injection."""},
        {"role": "assistant", "content": "How can I help you analyze the security data?"}
    ]

# --- Chatbot Integration ---
async def stream_chat_with_tools(model, messages):
    try:
        client = ollama.AsyncClient()
        
        # Include tool definitions in the model call
        tools = tool_config.get("tools", [])
        
        logging.info(f"Sending request to model with {len(tools)} tools")
        
        response = await client.chat(
            model,
            messages=[{"role": m["role"], "content": m["content"]} for m in messages],
            options={"tools": tools}  # Explicitly pass tool definitions
        )
        
        # Log the full response structure for debugging
        logging.info(f"Response type: {type(response)}")
        logging.info(f"Response message type: {type(response.message)}")
        logging.info(f"Response message content: {response.message.content}")
        
        # Check response content for tool call patterns
        content = response.message.content
        tool_call_detected = False
        
        # If the response contains tool call format [{"name": "tool_name", "arguments": {}}]
        if content and ('[{"name":' in content or '[{"name": ' in content):
            logging.info("Detected tool call in message content")
            try:
                # Try to extract the tool call from the content
                start_idx = content.find('[{')
                end_idx = content.find('}]', start_idx) + 2 if start_idx > -1 else -1
                
                if start_idx > -1 and end_idx > -1:
                    tool_call_str = content[start_idx:end_idx]
                    logging.info(f"Extracted tool call string: {tool_call_str}")
                    
                    # Parse the tool call JSON
                    tool_calls = json.loads(tool_call_str)
                    logging.info(f"Parsed tool calls: {tool_calls}")
                    
                    # Process tools directly to avoid conversion issues
                    tool_outputs = []
                    for tool in tool_calls:
                        tool_name = tool.get("name", "")
                        arguments = tool.get("arguments", {})
                        
                        if function_to_call := dashboard_tools.get(tool_name) or available_functions.get(tool_name):
                            logging.info(f"Executing tool directly: {tool_name}")
                            try:
                                # Get function parameters
                                import inspect
                                sig = inspect.signature(function_to_call)
                                func_params = sig.parameters
                                
                                # Add dataframes if needed
                                kwargs = arguments.copy() if arguments else {}
                                if 'threat_intel_df' in func_params and 'threat_intel_df' not in kwargs:
                                    kwargs['threat_intel_df'] = threat_intel_df
                                if 'anomalies_df' in func_params and 'anomalies_df' not in kwargs:
                                    kwargs['anomalies_df'] = anomalies_df
                                
                                # Call the function
                                result = function_to_call(**kwargs)
                                logging.info(f"Tool execution successful: {tool_name}")
                                
                                # Add to outputs
                                tool_outputs.append({
                                    'output': result,
                                    'name': tool_name
                                })
                            except Exception as e:
                                error_msg = f"Error directly executing {tool_name}: {str(e)}"
                                logging.error(error_msg)
                                tool_outputs.append({
                                    'output': error_msg,
                                    'name': tool_name
                                })
                        else:
                            error_msg = f"Tool {tool_name} not found"
                            logging.error(error_msg)
                            tool_outputs.append({
                                'output': error_msg,
                                'name': tool_name
                            })
                    
                    # Send the tool outputs to the model for a final response
                    tool_messages = []
                    for output in tool_outputs:
                        tool_messages.append({
                            'role': 'tool',
                            'content': str(output['output']),
                            'name': output['name']
                        })
                    
                    # Create new messages array with the tool outputs
                    new_messages = messages.copy()
                    # Add a custom assistant message showing intention to use tools
                    new_messages.append({
                        'role': 'assistant',
                        'content': f"I'll help you by using the {tool_name} tool."
                    })
                    # Add tool messages
                    new_messages.extend(tool_messages)
                    
                    # Get final response from model
                    try:
                        filtered_messages = []
                        for msg in new_messages:
                            filtered_msg = {"role": msg["role"], "content": msg["content"]}
                            if msg["role"] == "tool" and "name" in msg:
                                filtered_msg["name"] = msg["name"]
                            filtered_messages.append(filtered_msg)
                        
                        # Get final response
                        final_response = await client.chat(model, messages=filtered_messages)
                        final_content = final_response.message.content
                        
                        # Format and return the result
                        return final_content
                    except Exception as e:
                        error_msg = f"Error getting final response after tool execution: {str(e)}"
                        logging.error(error_msg)
                        return f"I tried to use the {tool_name} tool but encountered an error: {error_msg}"
                    
                    tool_call_detected = True
            except Exception as e:
                logging.error(f"Error parsing tool call from content: {str(e)}")
        
        # Regular check for tool_calls attribute
        if not tool_call_detected and hasattr(response.message, 'tool_calls') and response.message.tool_calls:
            logging.info(f"Processing tool calls from response.message.tool_calls")
            return await process_tool_calls(client, model, messages, response, external_tools=dashboard_tools)
        
        # If no tool calls detected, return the original content
        logging.info("No tool calls detected, returning original response")
        return response.message.content
    except Exception as e:
        logging.error(f"Error during streaming: {str(e)}")
        return f"I encountered an error while processing your request: {str(e)}"

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