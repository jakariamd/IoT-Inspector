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

# Global thread pool for async operations
if 'chat_thread_pool' not in st.session_state:
    st.session_state.chat_thread_pool = ThreadPoolExecutor(max_workers=2)

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
    """Get recent activities for the device"""
    db_conn, rwlock = libinspector.global_state.db_conn_and_lock
    
    with rwlock:
        sql = """
            SELECT * FROM activities 
            WHERE device_mac = ? 
            ORDER BY timestamp DESC 
            LIMIT 20
        """
        activities = []
        for row in db_conn.execute(sql, (device_mac,)):
            activities.append(dict(row))
        return activities

def query_device_async(query: str, device_mac: str, context: dict):
    """Async function to query about device with context"""
    try:
        # Enhanced query with device context
        enhanced_query = f"""
        Query about device {device_mac}:
        Device Context: {json.dumps(context, indent=2)}
        
        User Question: {query}
        
        Please provide a comprehensive answer about this specific device.
        """
        
        if not rag_iot.is_service_running():
            return {
                'status': 'error',
                'answer': '❌ RAG service is not running. Please start the service first.',
                'timestamp': datetime.now().isoformat()
            }
        
        answer = rag_iot.query_rag_system(enhanced_query)
        return {
            'status': 'success',
            'answer': answer,
            'timestamp': datetime.now().isoformat(),
            'query': query
        }
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }

def main():
    # Get device MAC from URL params
    device_mac = st.query_params.get("device_mac_address", "")
    
    if not device_mac:
        st.error("❌ No device specified")
        st.stop()
    
    # Get device info
    device_info = get_device_info(device_mac)
    if not device_info:
        st.error(f"❌ Device {device_mac} not found")
        st.stop()
    
    # Get device display name
    device_name_config_key = f'device_name_{device_mac}'
    device_display_name = common.config_get(device_name_config_key, "Unnamed Device")
    
    # Page header
    st.title(f"💬 Chat with {device_display_name}")
    st.caption(f"Device: {device_mac} | IP: {device_info.get('ip_address', 'Unknown')}")
    
    # Sidebar with device info and controls
    with st.sidebar:
        st.header("📱 Device Info")
        
        # Device metadata
        metadata = json.loads(device_info.get('metadata_json', '{}'))
        st.json({
            "MAC Address": device_mac,
            "IP Address": device_info.get('ip_address'),
            "Vendor": metadata.get('oui_vendor', 'Unknown'),
            "Status": "Online" if device_info.get('is_active') else "Offline"
        })
        
        st.header("🔧 Device Controls")
        
        # Quick action buttons
        if st.button("🔍 Scan Device", use_container_width=True):
            st.info("Device scan initiated...")
        
        if st.button("🚫 Block Device", use_container_width=True):
            st.warning("Device blocking not yet implemented")

        # TODO Implement the activities view
        if st.button("📊 View Activities", use_container_width=True):
            activities = get_device_activities(device_mac)
            st.write(f"Found {len(activities)} recent activities")
        
        # RAG Service Status
        st.header("🤖 AI Service")
        if rag_iot.is_service_running():
            st.success("🟢 Online")
        else:
            st.error("🔴 Offline")
    
    # Chat interface
    chat_container = st.container()
    
    # Initialize chat history
    chat_key = f"chat_history_{device_mac}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = [
            {
                "role": "assistant",
                "content": f"👋 Hello! I'm here to help you with your {device_display_name}. You can ask me about:\n\n• Privacy and security concerns\n• Device functionality\n• Network behavior\n• Troubleshooting\n• Device controls\n\nWhat would you like to know?",
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
                
                # Add copy button for assistant responses
                if message["role"] == "assistant" and len(message["content"]) > 50:
                    if st.button("📋 Copy", key=f"copy_{i}"):
                        st.success("Response copied to clipboard!")
    
    # Chat input
    if prompt := st.chat_input("Ask about your device..."):
        # Add user message
        st.session_state[chat_key].append({
            "role": "user", 
            "content": prompt,
            "timestamp": datetime.now().isoformat()
        })
        
        # Display user message immediately
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Show "thinking" message
        with st.chat_message("assistant"):
            thinking_placeholder = st.empty()
            thinking_placeholder.markdown("🤔 Thinking...")
            
            # Query device asynchronously
            device_context = {
                "device_info": device_info,
                "device_name": device_display_name,
                "recent_activities": get_device_activities(device_mac)[:5]  # Last 5 activities
            }
            
            # Submit async query
            future = st.session_state.chat_thread_pool.submit(
                query_device_async, 
                prompt, 
                device_mac, 
                device_context
            )
            
            # Wait for result with progress
            start_time = time.time()
            while not future.done():
                elapsed = time.time() - start_time
                thinking_placeholder.markdown(f"🤔 Analyzing your question... ({elapsed:.1f}s)")
                time.sleep(1)
                
                # Timeout after 2 minutes
                if elapsed > 120:
                    future.cancel()
                    thinking_placeholder.markdown("⏰ Query timed out. Please try again.")
                    break
            
            if future.done():
                try:
                    result = future.result()
                    
                    if result['status'] == 'success':
                        response = result['answer']
                    else:
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
        
        # Rerun to update chat display
        st.rerun()
    
    # Quick action buttons at bottom
    st.markdown("---")
    st.subheader("💡 Quick Questions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔒 Privacy Concerns", use_container_width=True):
            st.session_state[f"quick_query_{device_mac}"] = f"What are the privacy implications of the {device_display_name} device?"
            st.rerun()
    
    with col2:
        if st.button("⚙️ Device Functions", use_container_width=True):
            st.session_state[f"quick_query_{device_mac}"] = f"What functionality does the {device_display_name} device have?"
            st.rerun()
    
    with col3:
        if st.button("🛡️ Security Check", use_container_width=True):
            st.session_state[f"quick_query_{device_mac}"] = f"Is the {device_display_name} device safe to use on my network?"
            st.rerun()
    
    # Handle quick queries
    quick_query_key = f"quick_query_{device_mac}"
    if quick_query_key in st.session_state:
        quick_query = st.session_state[quick_query_key]
        del st.session_state[quick_query_key]
        
        # Add to chat and process
        st.session_state[chat_key].append({
            "role": "user",
            "content": quick_query,
            "timestamp": datetime.now().isoformat()
        })
        st.rerun()

if __name__ == "__main__":
    main()