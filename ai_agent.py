import streamlit as st
import json
import time
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import libinspector.global_state
import privacy_agent.rag_iot_service as rag_iot
import utils
import common
from privacy_agent import llm_prompts

from device_detail_page import show_device_list

def get_device_info(device_mac: str):
    """Get device information from database"""
    db_conn, rwlock = libinspector.global_state.db_conn_and_lock
    
    with rwlock:
        sql = "SELECT * FROM devices WHERE mac_address = ?"
        result = db_conn.execute(sql, (device_mac,)).fetchone()
        if result:
            return dict(result)
    return None

def get_device_activities(device_mac: str):
    return None



def process_user_query_async(prompt: str, intent_analysis: dict, device_mac: str, context: dict):
    """
    Main function to analyze intent and route to appropriate handler
    """
    try:
        # Analyze the user's intent
        # intent_analysis = llm_prompts.analyze_intent(prompt)
        
        if intent_analysis['intent'] == 'action':
            # Route to action handler
            return utils.execute_device_action_async(
                intent_analysis['action_type'],
                device_mac, 
                context,
                prompt
            )
        else:
            # Route to information handler (RAG system)
            return utils.query_information_async(prompt, device_mac, context)
            
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error processing query: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }

def main():
    # Initialize thread pool at the very beginning of main()
    if 'chat_thread_pool' not in st.session_state:
        st.session_state.chat_thread_pool = ThreadPoolExecutor(max_workers=2)
        
    # Get device MAC from URL params
    device_mac = st.query_params.get("device_mac_address", "")
    
    if not device_mac:
        device_mac = show_device_list()
    
    # Get device info
    device_info = get_device_info(device_mac)
    if not device_info:
        st.error(f"❌ Device {device_mac} not found")
        st.stop()
    
    # Get device display name
    device_name_config_key = f'device_name_{device_mac}'
    device_display_name = common.config_get(device_name_config_key, "Unnamed Device")
    
    # Page header
    st.header(f"💬 AI Agent for `{device_display_name}` device")
    st.caption(f"Device: {device_mac} | IP: {device_info.get('ip_address', 'Unknown')}")
    
    # Add intent indicator
    with st.expander("🧠 How the AI Agent works"):
        st.markdown("""
        **This AI agent can help you in two ways:**
        
        📚 **Information Queries** - Ask questions about your device:
        - "What data does this device collect?"
        - "Is this device secure?"
        - "How does this device work?"
        
        🎛️ **Device Actions** - Take control of your device:
        - "Block this device from the network"
        - "Scan this device for vulnerabilities"  
        - "Enable monitoring for this device"
        
        The agent automatically detects your intent and routes your request appropriately.
        """)
    
    # Sidebar with device info and controls
    with st.sidebar:
        st.header("📱 Device Info")
        
        # Device metadata
        metadata = json.loads(device_info.get('metadata_json', '{}'))
        st.json({
            "MAC Address": device_mac,
            "IP Address": device_info.get('ip_address'),
            "Vendor": metadata.get('oui_vendor', 'Unknown'),
            "Status": "Online"
        })
        
        st.header("🔧 Quick Actions")
        
        # Quick action buttons that use the new system - ADD UNIQUE KEYS
        if st.button("🔍 Show Activities", use_container_width=True, key=f"sidebar_scan_{device_mac}"):
            st.session_state[f"quick_query_{device_mac}"] = "Show network activities for this device"
            st.rerun()

        if st.button("🚫 Block Device", use_container_width=True, key=f"sidebar_block_{device_mac}"):
            st.session_state[f"quick_query_{device_mac}"] = "Block this device from accessing the network"
            st.rerun()

        if st.button("📊 Enable Monitoring", use_container_width=True, key=f"sidebar_monitor_{device_mac}"):
            st.session_state[f"quick_query_{device_mac}"] = "Enable network monitoring for this device"
            st.rerun()
        
        # RAG Service Status
        st.header("🤖 AI Services")
        if rag_iot.is_service_running():
            st.success("🟢 RAG Online")
        else:
            st.error("🔴 RAG Offline")

        st.success("🟢 Monitoring Network")

    # Chat interface
    chat_container = st.container()
    
    # Initialize chat history
    chat_key = f"chat_history_{device_mac}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = [
            {
                "role": "assistant",
                "content": f"👋 Hello! I'm your AI agent for {device_display_name}.\n\n"
                          f"**I can help you with:** \n\n "
                          f"📚 **Information**: Ask questions about privacy, security, functionality\n\n"
                          f"🎛️ **Actions**: Block/unblock, scan, monitor, configure the device\n\n"
                        #   f"**Try saying:**\n\n"
                        #   f"• \"What data does this device collect?\"\n\n"
                        #   f"• \"Block this device from the network\"\n\n"
                        #   f"• \"Is this device safe to use?\"\n\n"
                        #   f"• \"Scan this device for vulnerabilities\"\n\n"
                          f"What would you like to know or do?",
                "timestamp": datetime.now().isoformat()
            }
        ]
    
    # Display chat messages
    with chat_container:
        for i, message in enumerate(st.session_state[chat_key]):
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
                
                # Show timestamp for messages
                if "timestamp" in message:
                    st.caption(f"🕒 {message['timestamp'][:19].replace('T', ' ')}")
                
                # Show intent analysis for user messages
                if message["role"] == "user" and "intent_info" in message:
                    intent_info = message["intent_info"]
                    if intent_info['intent'] == 'action':
                        st.info(f"🎛️ Received Action Request: {intent_info['action_type']}")
                    else:
                        st.info(f"📚 Received Information Query")
                
                # Add copy button for assistant responses - ADD UNIQUE KEYS
                if message["role"] == "assistant" and len(message["content"]) > 50:
                    if st.button("📋 Copy", key=f"copy_{device_mac}_{i}"):
                        st.success("Response copied to clipboard!")
    
    # Chat input
    if prompt := st.chat_input(f"Ask a question or request an action for {device_display_name} device"):
        device_context = {
                "device_info": device_info,
                "device_name": device_display_name,
            }

        # Set processing flag for chat input too
        st.session_state[f"processing_{device_mac}"] = True
        handle_user_query(prompt, device_mac, device_context)
    
    # Updated quick action buttons at bottom - ADD UNIQUE KEYS
    st.markdown("---")

    # Check if we should show quick examples (hide when processing)
    processing_key = f"processing_{device_mac}"
    show_quick_examples = not st.session_state.get(processing_key, False)

    if show_quick_examples:
        st.subheader("💡 Quick Examples")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("🔒 Privacy Info", use_container_width=True, key=f"bottom_privacy_{device_mac}"):
                st.session_state[processing_key] = True
                st.session_state[f"quick_query_{device_mac}"] = f"What are the privacy implications of the {device_display_name} device?"
                st.rerun()
        
        with col2:
            if st.button("🚫 Block Device", use_container_width=True, key=f"bottom_block_{device_mac}"):
                st.session_state[processing_key] = True
                st.session_state[f"quick_query_{device_mac}"] = f"Block the {device_display_name} device from network access"
                st.rerun()
        
        with col3:
            if st.button("🔍 Network Scan", use_container_width=True, key=f"bottom_scan_{device_mac}"):
                st.session_state[processing_key] = True
                st.session_state[f"quick_query_{device_mac}"] = f"Scan network activities for this {device_display_name} device"
                st.rerun()
        
        with col4:
            if st.button("⚙️ Device Functions", use_container_width=True, key=f"bottom_functions_{device_mac}"):
                st.session_state[processing_key] = True
                st.session_state[f"quick_query_{device_mac}"] = f"What functionality does the {device_display_name} device have?"
                st.rerun()
    else:
        # Show processing message instead of buttons
        st.info("🔄 Processing your request...")

    # Handle quick queries
    quick_query_key = f"quick_query_{device_mac}"
    if quick_query_key in st.session_state:
        quick_query = st.session_state[quick_query_key]
        del st.session_state[quick_query_key]
        
        handle_user_query(quick_query, device_mac, {
            "device_info": device_info,
            "device_name": device_display_name,
        })


def handle_user_query(prompt: str, device_mac: str, device_context: dict):
    chat_key = f"chat_history_{device_mac}"
    processing_key = f"processing_{device_mac}"

    # Set processing flag
    st.session_state[processing_key] = True

    # Display user message immediately
    intent_analysis = None
    with st.chat_message("user"):
        st.markdown(prompt)
        # Analyze intent 
        intent_analysis = llm_prompts.analyze_intent(prompt)

        if intent_analysis['intent'] == 'action':
            st.info(f"🎛️ Received Action Request: {intent_analysis['action_type']}")
        else:
            st.info(f"📚 Received Information Query")
    
        # Add user message with intent info
        st.session_state[chat_key].append({
            "role": "user", 
            "content": prompt,
            "timestamp": datetime.now().isoformat(),
            "intent_info": intent_analysis
        })

    # Show "thinking" message
    with st.chat_message("assistant"):
        thinking_placeholder = st.empty()
        if intent_analysis['intent'] == 'action':
            thinking_placeholder.markdown(f"🎛️ Processing action: {intent_analysis['action_type']}...")
        else:
            thinking_placeholder.markdown("📚 Searching knowledge base...")
        
        # Submit async query using the new routing system
        future = st.session_state.chat_thread_pool.submit(
            process_user_query_async, 
            prompt, 
            intent_analysis,
            device_mac, 
            device_context
        )
        
        # Wait for result with progress
        start_time = time.time()
        while not future.done():
            elapsed = time.time() - start_time
            if intent_analysis['intent'] == 'action':
                thinking_placeholder.markdown(f"🎛️ Executing {intent_analysis['action_type']} action... ({elapsed:.1f}s)")
            else:
                thinking_placeholder.markdown(f"📚 Analyzing your question... ({elapsed:.1f}s)")
            time.sleep(1)
            
            # Timeout after 2 minutes
            if elapsed > 120:
                future.cancel()
                thinking_placeholder.markdown("⏰ Request timed out. Please try again.")
                break
        
        if future.done():
            try:
                result = future.result()
                
                response = result['answer']
                
                # Replace thinking message with actual response
                thinking_placeholder.markdown(response)
                
                # Add assistant response to chat history
                st.session_state[chat_key].append({
                    "role": "assistant",
                    "content": response,
                    "timestamp": result['timestamp']
                })
                
            except Exception as e:
                error_msg = f"❌ Error getting response: {str(e)}"
                thinking_placeholder.markdown(error_msg)
                
                st.session_state[chat_key].append({
                    "role": "assistant",
                    "content": error_msg,
                    "timestamp": datetime.now().isoformat()
                })
    
    # Clear processing flag when done
    st.session_state[processing_key] = False
    
    # Rerun to update chat display
    st.rerun()
    


if __name__ == "__main__":
    main()