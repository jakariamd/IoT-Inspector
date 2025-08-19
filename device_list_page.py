import streamlit as st
import functools
import time
import json
import libinspector.global_state
import privacy_agent.llm_prompts as llm_prompts
import utils
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
import uuid

import common
import privacy_agent.rag_iot_service as rag_iot

# Global thread pool for async operations
if 'thread_pool' not in st.session_state:
    st.session_state.thread_pool = ThreadPoolExecutor(max_workers=4)

@st.fragment(run_every=5)
def show():
    human_readable_time = common.get_human_readable_time()
    st.markdown(f'Updated: {human_readable_time}')

    db_conn, rwlock = libinspector.global_state.db_conn_and_lock

    # Get the list of devices from the database
    sql = """
        SELECT * FROM devices
        WHERE is_gateway = 0
    """
    device_list = []
    with rwlock:
        for device_dict in db_conn.execute(sql):
            device_list.append(dict(device_dict))

    for device_dict in device_list:
        with st.container(border=True):
            show_device_card(device_dict)

def query_rag_async(query: str, device_mac: str):
    """Async function to query RAG system"""
    try:
        # Check if RAG service is available
        if not rag_iot.is_service_running():
            return {
                'status': 'error',
                'answer': '❌ RAG service is not running. Please start the service first.',
                'device_mac': device_mac
            }
        
        # Query the RAG system
        answer = rag_iot.query_rag_system(query)
        return {
            'status': 'success',
            'answer': answer,
            'device_mac': device_mac,
            'query': query
        }
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error querying RAG system: {str(e)}',
            'device_mac': device_mac
        }

def start_rag_query(query: str, device_mac: str):
    """Start an async RAG query"""
    # Generate unique request ID
    request_id = f"rag_query_{device_mac}_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    # Store query status
    query_status_key = f"rag_status_{device_mac}"
    st.session_state[query_status_key] = {
        'status': 'processing',
        'request_id': request_id,
        'query': query,
        'start_time': time.time()
    }
    
    # Submit to thread pool
    future = st.session_state.thread_pool.submit(query_rag_async, query, device_mac)
    
    # Store future for tracking
    future_key = f"rag_future_{device_mac}"
    st.session_state[future_key] = future
    
    return request_id

def check_rag_query_status(device_mac: str):
    """Check if RAG query is complete"""
    future_key = f"rag_future_{device_mac}"
    query_status_key = f"rag_status_{device_mac}"
    
    if future_key not in st.session_state:
        return None
    
    future = st.session_state[future_key]
    
    if future.done():
        # Query is complete, get result
        try:
            result = future.result()
            # Update status with result
            st.session_state[query_status_key] = {
                'status': 'completed',
                'result': result,
                'completion_time': time.time()
            }
            # Clean up future
            del st.session_state[future_key]
            return result
        except Exception as e:
            # Handle any errors
            error_result = {
                'status': 'error',
                'answer': f'❌ Query failed: {str(e)}',
                'device_mac': device_mac
            }
            st.session_state[query_status_key] = {
                'status': 'completed',
                'result': error_result,
                'completion_time': time.time()
            }
            del st.session_state[future_key]
            return error_result
    
    return None  # Still processing

def show_device_card(device_dict):
    # Check if the user has previously inspected this device
    device_inspected_config_key = f'device_is_inspected_{device_dict["mac_address"]}'
    is_inspected = common.config_get(device_inspected_config_key, False)

    # Update the inspected status in the database if it is different
    if is_inspected != (device_dict['is_inspected'] == 1):
        db_conn, rwlock = libinspector.global_state.db_conn_and_lock
        with rwlock:
            sql = """
                UPDATE devices
                SET is_inspected = ?
                WHERE mac_address = ?
            """
            db_conn.execute(sql, (is_inspected, device_dict['mac_address']))

    # Extra information on the device's metadata, e.g., OUI
    metadata_dict = json.loads(device_dict['metadata_json'])

    left_col, right_col = st.columns([6, 4])
    hostnames = utils.get_hostnames(device_dict["mac_address"])

    llm_predicted_device_info = llm_prompts.predict_device_vendor_and_name(
        hostname=str(hostnames),
        vendor=metadata_dict["oui_vendor"],
        oui=device_dict["mac_address"][:8].upper(),
        metadata= device_dict["metadata_json"]
    )

    with left_col:
        # Get custom device name from config
        device_name_config_key = f'device_name_{device_dict["mac_address"]}'
        device_display_name = common.config_get(device_name_config_key, "Unnamed Device")
        
        st.markdown(f'#### {device_display_name}')
        st.caption(f'IP Address: `{device_dict["ip_address"]}` -- MAC Address: `{device_dict["mac_address"]}` -- OUI: {metadata_dict["oui_vendor"]}')
        st.caption(f'Probable Device: {llm_predicted_device_info.get("vendor", "")} {llm_predicted_device_info.get("device_name", "")}')
        
        # Show a dropdown to select a question
        question_options = [
            f"What is the privacy implication of {device_display_name} device?",
            f"What functionality does this {device_display_name} device have?",
            f"What data does this {device_display_name} device collect?",
            f"Is this {device_display_name} device safe to use on my network?",
            f"Can this {device_display_name} device be hacked remotely?"
        ]
        question_options.insert(0, "(Select a question)")

        # Get the currently selected question from session state
        question_key = f"device_question_{device_dict['mac_address']}"
        selected_question_index = st.session_state.get(question_key, 0)

        selected_question = st.selectbox(
            "Ask about this device:",
            question_options,
            index=selected_question_index,
            key=f"device_question_select_{device_dict['mac_address']}"
        )

        device_mac = device_dict['mac_address']
        query_status_key = f"rag_status_{device_mac}"
        
        if selected_question and selected_question != "(Select a question)":
            # Store the selected question index
            st.session_state[question_key] = question_options.index(selected_question)
            
            # Check if we have a current query status
            current_status = st.session_state.get(query_status_key, {})
            
            # Check if query is in progress or completed
            if current_status.get('status') == 'processing':
                # Check if query completed
                result = check_rag_query_status(device_mac)
                
                if result is None:
                    # Still processing
                    elapsed_time = time.time() - current_status.get('start_time', 0)
                    st.info(f"🔄 Processing query: '{selected_question}' (Running for {elapsed_time:.1f}s)")
                    st.progress(min(elapsed_time / 120, 1.0))  # Assume max 2 minutes
                    
                    # Add cancel button
                    col1, col2, col3 = st.columns([1, 1, 3])
                    with col1:
                        if st.button("Cancel", key=f"cancel_query_{device_mac}"):
                            # Cancel the query
                            future_key = f"rag_future_{device_mac}"
                            if future_key in st.session_state:
                                future = st.session_state[future_key]
                                future.cancel()  # This might not work if already running
                                del st.session_state[future_key]
                            del st.session_state[query_status_key]
                            st.rerun()
                    
                    with col2:
                        if st.button("Refresh", key=f"refresh_query_{device_mac}"):
                            st.rerun()
                    
                    # Auto-refresh every 2 seconds
                    time.sleep(2)
                    st.rerun()
                else:
                    # Query completed, show result
                    if result['status'] == 'success':
                        st.success(f"✅ Answer to: '{selected_question}'")
                        st.markdown(result['answer'])
                    else:
                        st.error(f"❌ Error processing query: '{selected_question}'")
                        st.error(result['answer'])
                    
                    # Add button to ask another question
                    if st.button("Ask Another Question", key=f"ask_another_{device_mac}"):
                        # Clear the current status
                        del st.session_state[query_status_key]
                        st.rerun()
            
            elif current_status.get('status') == 'completed':
                # Show completed result
                result = current_status['result']
                if result['status'] == 'success':
                    st.success(f"✅ Answer to: '{selected_question}'")
                    st.markdown(result['answer'])
                else:
                    st.error(f"❌ Error processing query: '{selected_question}'")
                    st.error(result['answer'])
                
                # Add button to ask another question
                if st.button("Ask Another Question", key=f"ask_another_{device_mac}"):
                    # Clear the current status
                    del st.session_state[query_status_key]
                    st.rerun()
            
            else:
                # No query in progress, show button to start
                col1, col2 = st.columns([2, 3])
                
                with col1:
                    if st.button("Get Answer", key=f"get_answer_{device_mac}", type="primary"):
                        # Check if RAG service is available first
                        if rag_iot.is_service_running():
                            # Start async query
                            request_id = start_rag_query(selected_question, device_mac)
                            st.success(f"🚀 Query started! (ID: {request_id[:8]}...)")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ RAG service is not running. Please start the service first.")
                
                with col2:
                    # Show service status
                    if rag_iot.is_service_running():
                        st.success("🟢 RAG Service Online")
                    else:
                        st.error("🔴 RAG Service Offline")

        elif selected_question == "(Select a question)":
            st.info("Please select a question to get an answer.")
            
            # Show service status
            col1, col2 = st.columns([1, 1])
            with col1:
                if rag_iot.is_service_running():
                    st.success("🟢 RAG Service Online")
                else:
                    st.error("🔴 RAG Service Offline")
            
            with col2:
                if st.button("Check Service", key=f"check_service_{device_mac}"):
                    if rag_iot.is_service_running():
                        try:
                            client = rag_iot.RAGClient()
                            status = client.get_status()
                            if status.get('status') == 'success':
                                service_info = status['system_status']
                                st.info(f"✅ Service OK - {service_info.get('available_models', 0)}/{service_info.get('total_models', 0)} models ready")
                            else:
                                st.warning("⚠️ Service responding but may have issues")
                        except Exception as e:
                            st.error(f"❌ Service error: {str(e)}")
                    else:
                        st.error("❌ Service not responding")

    with right_col:
        st.toggle(
            label='Monitored',
            value=is_inspected,
            key=f"device_inspected_toggle_{device_dict['mac_address']}",
            on_change=common.config_set,
            args=(device_inspected_config_key, not is_inspected),
        )

        device_pinned_config_key = f'device_is_pinned_{device_dict["mac_address"]}'
        device_is_pinned = common.config_get(device_pinned_config_key, False)
        st.toggle(
            label='Pinned to top',
            value=device_is_pinned,
            key=f"device_pinned_toggle_{device_dict['mac_address']}",
            on_change=common.config_set,
            args=(device_pinned_config_key, not device_is_pinned),
        )

        c1, c2 = st.columns(2)

        # A button to show the device activities
        c1.link_button(
            label=':material/monitoring: Device Activities',
            url=f"/device_details?device_mac_address={device_dict['mac_address']}",
            use_container_width=True,
            disabled=not is_inspected
        )

        def _rename_device_callback(mac_address):
            # Toggle the rename mode for this device
            rename_mode_key = f'device_rename_mode_{mac_address}'
            current_mode = st.session_state.get(rename_mode_key, False)
            st.session_state[rename_mode_key] = not current_mode

        # A button to rename the device
        c2.button(
            label=':material/edit: Rename Device',
            key=f"device_rename_button_{device_dict['mac_address']}",
            on_click=_rename_device_callback,
            args=(device_dict['mac_address'],),
            use_container_width=True
        )

        # Show input field if in rename mode
        rename_mode_key = f'device_rename_mode_{device_dict["mac_address"]}'
        if st.session_state.get(rename_mode_key, False):
            device_name_config_key = f'device_name_{device_dict["mac_address"]}'
            current_name = common.config_get(device_name_config_key, "")
            
            new_name = st.text_input(
                label="Enter device name:",
                value=current_name,
                key=f"device_name_input_{device_dict['mac_address']}",
                placeholder="Enter a name for this device"
            )
            
            # Save the name when Enter is pressed or text changes
            if new_name != current_name:
                if new_name.strip():  # Only save non-empty names
                    common.config_set(device_name_config_key, new_name.strip())
                else:
                    # Remove the custom name if empty (revert to "Unnamed Device")
                    try:
                        # Remove from config if exists
                        config_dict = common.config_get('', {})  # This will trigger loading
                        if device_name_config_key in config_dict:
                            del config_dict[device_name_config_key]
                            # Save the updated config
                            with open(common.config_file_name, 'w') as f:
                                json.dump(config_dict, f, indent=2, sort_keys=True)
                    except:
                        pass
                
                # Exit rename mode after saving
                st.session_state[rename_mode_key] = False
                st.rerun()

