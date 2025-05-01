from ollama import ChatResponse
from typing import Dict, Any, List
import json
import logging
import inspect

# Import the functions and dictionary from tool_functions.py
from documentation.tool_functions import available_functions

# Set up logging
logging.basicConfig(level=logging.INFO)

async def process_tool_calls(client, model: str, messages: List[Dict[str, Any]], 
                            response: ChatResponse, external_tools=None) -> str:
    """
    Process tool calls from the model response and get the final response.
    
    Args:
        client: The Ollama client
        model: The model name
        messages: The message history
        response: The model's response containing tool calls
        external_tools: Additional tools passed from outside the module
        
    Returns:
        str: The final response after processing tool calls
    """
    # Create the all_available_functions dictionary
    all_available_functions = {**available_functions}
    
    # Add external tools if provided (from security_dashboard.py)
    if external_tools and isinstance(external_tools, dict):
        all_available_functions.update(external_tools)
    
    tool_outputs = []
    tool_info = []
    
    # Process each tool call
    if response.message.tool_calls:
        for tool in response.message.tool_calls:
            tool_name = tool.function.name
            logging.info(f"Tool call detected: {tool_name}")
            
            # Check if the tool exists in our available functions
            if function_to_call := all_available_functions.get(tool_name):
                # Create tool call info string
                tool_call_info = (
                    f"\n🔧 Tool Called: {tool_name}\n"
                    f"📝 Parameters: {tool.function.arguments}\n"
                )
                
                # Parse arguments from JSON string
                arguments = {}
                try:
                    # Ensure we have a valid JSON string
                    if tool.function.arguments.strip():
                        arguments = json.loads(tool.function.arguments)
                    logging.info(f"Parsed arguments: {arguments}")
                except Exception as e:
                    error_msg = f"Error parsing arguments: {str(e)}"
                    logging.error(error_msg)
                    tool_call_info += f"{error_msg}\n"
                    tool_outputs.append({
                        'output': f"Error: Could not parse arguments for {tool_name}: {str(e)}",
                        'name': tool_name
                    })
                    tool_info.append(tool_call_info)
                    continue
                
                # Get function signature and parameters
                sig = inspect.signature(function_to_call)
                func_params = sig.parameters
                logging.info(f"Function {tool_name} parameters: {list(func_params.keys())}")
                
                # Prepare the actual arguments to pass to the function
                kwargs = {}
                
                # Filter arguments to only include those in the function signature
                for param_name in func_params:
                    if param_name in arguments:
                        kwargs[param_name] = arguments[param_name]
                        logging.info(f"Added parameter {param_name}={arguments[param_name]}")
                
                # Call the function with the prepared arguments
                try:
                    logging.info(f"Calling {tool_name} with kwargs: {kwargs}")
                    
                    # Use late binding for importing dashboard data if needed
                    # Only import if we need it and we don't have these parameters
                    if ('df_threat' in func_params and 'df_threat' not in kwargs) or \
                       ('df_anomaly' in func_params and 'df_anomaly' not in kwargs):
                        try:
                            # Late import to avoid circular dependency
                            import security_dashboard
                            
                            if 'df_threat' in func_params and 'df_threat' not in kwargs:
                                kwargs['df_threat'] = security_dashboard.threat_intel_df
                                logging.info("Added df_threat from security_dashboard")
                                
                            if 'df_anomaly' in func_params and 'df_anomaly' not in kwargs:
                                kwargs['df_anomaly'] = security_dashboard.anomalies_df
                                logging.info("Added df_anomaly from security_dashboard")
                                
                        except Exception as e:
                            logging.error(f"Error importing dashboard data: {str(e)}")
                    
                    # If function requires no arguments, call it without kwargs
                    if len(func_params) == 0:
                        tool_output = function_to_call()
                    else:
                        tool_output = function_to_call(**kwargs)
                    
                    logging.info(f"Tool output type: {type(tool_output)}")
                    
                    # Ensure the output is a string
                    if not isinstance(tool_output, str):
                        tool_output = str(tool_output)
                        
                except Exception as e:
                    error_msg = f"Error executing {tool_name}: {str(e)}"
                    logging.error(error_msg)
                    tool_output = error_msg
                
                # Store the output for adding to messages
                tool_outputs.append({
                    'output': tool_output,
                    'name': tool_name
                })
                
                # Add result to tool info for display
                tool_call_info += f"📊 Result: {tool_output}\n"
                tool_info.append(tool_call_info)
            else:
                logging.error(f"Tool {tool_name} not found in available functions")
                tool_outputs.append({
                    'output': f"Error: Tool '{tool_name}' not found",
                    'name': tool_name
                })
    
    # If we have tool outputs, get final response from model
    if tool_outputs:
        logging.info(f"Processing {len(tool_outputs)} tool outputs")
        
        # Add the model's initial response with tool calls
        messages.append(response.message)
        
        # Add each tool output as a separate message
        for tool_output in tool_outputs:
            tool_message = {
                'role': 'tool', 
                'content': str(tool_output['output']), 
                'name': tool_output['name']
            }
            messages.append(tool_message)
            logging.info(f"Added tool message: {tool_message}")
        
        # Get final response with tool outputs
        try:
            # Convert messages to the format expected by the client.chat method
            filtered_messages = []
            for msg in messages:
                if "role" in msg and "content" in msg:
                    filtered_msg = {"role": msg["role"], "content": msg["content"]}
                    # Add name field for tool messages
                    if msg["role"] == "tool" and "name" in msg:
                        filtered_msg["name"] = msg["name"]
                    filtered_messages.append(filtered_msg)
            
            logging.info(f"Sending {len(filtered_messages)} messages to model for final response")
            
            final_response = await client.chat(model, messages=filtered_messages)
            
            # Format the complete response
            complete_response = final_response.message.content
            if tool_info:
                complete_response += "\n\n💡 Tool Usage Details:" + "".join(tool_info)
            
            logging.info("Final response generated successfully")
            return complete_response
            
        except Exception as e:
            error_msg = f"Error getting final response: {str(e)}"
            logging.error(error_msg)
            return error_msg
    
    # If no tool calls, return the original response
    logging.info("No tool calls to process, returning original response")
    return response.message.content
