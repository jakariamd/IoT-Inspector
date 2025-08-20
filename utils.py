import functools
import libinspector
import requests
import json
import hashlib
from datetime import datetime
import streamlit as st
import time
import privacy_agent.rag_iot_service as rag_iot

def get_hostnames(mac_address):
    db_conn, rwlock = libinspector.global_state.db_conn_and_lock
    with rwlock:
        # Get src_hostnames where mac_address = dest_mac_address
        # UNION
        # Get dest_hostnames where mac_address = src_mac_address
        query = """
        SELECT DISTINCT hostname FROM (
            SELECT src_hostname as hostname 
            FROM network_flows 
            WHERE dest_mac_address = ? AND src_hostname IS NOT NULL AND src_hostname != ''
            
            UNION
            
            SELECT dest_hostname as hostname 
            FROM network_flows 
            WHERE src_mac_address = ? AND dest_hostname IS NOT NULL AND dest_hostname != ''
        )
        """
        
        result = db_conn.execute(query, (mac_address, mac_address))
        rows = result.fetchall()
        
        # Extract hostnames from rows and return as list
        hostnames = [row[0] for row in rows if row[0]]
        # print(f"Hostnames for MAC {mac_address}: {hostnames}")
        return hostnames if hostnames else None


@functools.lru_cache(maxsize=256)
def predict_vendor(payload):
    """
    Predict vendor name using the API with caching.
    
    Args:
        user_agent (str): User agent string
        oui (str): OUI information
        netdisco_info (str): Network discovery information
        remote_hostnames (str): Remote hostnames (comma-separated if multiple)
        user_label (str): User-provided label
        talks_to_ads (bool): Whether device communicates with ad servers
        
    Returns:
        str: Predicted vendor name or None if API call fails
    """
    print(f'input: {payload}')
    try:
        # API endpoint and headers
        url = "https://instance-20250625-161432.tailcedbd.ts.net/predict"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": "momo"
        }
        
        
        # Make API call with timeout
        response = requests.post(url, headers=headers, json=json.loads(payload), timeout=30)
        response.raise_for_status()
        
        # Parse response and extract vendor prediction
        # result = response.json()
        # return result.get("predicted_vendor", None)
        print(f'input: {payload} response.status_code: {response.status_code} response.json(): {response.json()}')
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse API response: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in predict_vendor: {e}")
        return None



def query_information_async(query: str, device_mac: str, context: dict):
    """Async function to query RAG system for information"""
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



def execute_device_action_async(action_type: str, device_mac: str, context: dict, original_prompt: str):
    """
    Async function to execute device actions
    
    Args:
        action_type: Type of action to perform
        device_mac: Device MAC address
        context: Device context information
        original_prompt: Original user prompt for context
    """
    try:
        device_info = context.get('device_info', {})
        device_name = context.get('device_name', 'Unknown Device')
        
        if action_type == 'block':
            # TODO: Implement device blocking
            result = block_device(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'✅ Successfully blocked {device_name} ({device_mac})\n\n'
                         f'The device has been blocked from accessing the network. '
                         f'You can unblock it later if needed.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'block_device'
            }
            
        elif action_type == 'unblock':
            # TODO: Implement device unblocking
            result = unblock_device(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'✅ Successfully unblocked {device_name} ({device_mac})\n\n'
                         f'The device now has access to the network.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'unblock_device'
            }
            
        elif action_type == 'scan':
            # TODO: Implement device scanning
            result = scan_device(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'🔍 Device scan initiated for {device_name} ({device_mac})\n\n'
                         f'Scanning for:\n'
                         f'• Open ports and services\n'
                         f'• Security vulnerabilities\n'
                         f'• Network behavior\n'
                         f'• Device capabilities\n\n'
                         f'Results will be available in the device activities section.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'scan_device'
            }
            
        elif action_type == 'restart':
            # TODO: Implement device restart
            return {
                'status': 'error',
                'answer': f'⚠️ Device restart not supported for {device_name}\n\n'
                         f'This device does not support remote restart commands. '
                         f'You may need to physically restart the device.',
                'timestamp': datetime.now().isoformat()
            }
            
        elif action_type == 'configure':
            # TODO: Implement device configuration
            return {
                'status': 'success',
                'answer': f'⚙️ Configuration options for {device_name}:\n\n'
                         f'Available actions:\n'
                         f'• Block/Unblock device\n'
                         f'• Monitor network activity\n'
                         f'• Set device priorities\n'
                         f'• Configure alerts\n\n'
                         f'Please specify what you would like to configure.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'show_config_options'
            }
            
        elif action_type == 'monitor':
            # TODO: Implement device monitoring
            result = enable_monitoring(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'📊 Monitoring enabled for {device_name} ({device_mac})\n\n'
                         f'Now tracking:\n'
                         f'• Network traffic patterns\n'
                         f'• Connection attempts\n'
                         f'• Data usage\n'
                         f'• Suspicious activity\n\n'
                         f'View real-time data in the Device Activities section.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'enable_monitoring'
            }
            
        else:
            return {
                'status': 'error',
                'answer': f'❌ Action "{action_type}" not supported yet\n\n'
                         f'Available actions:\n'
                         f'• Block/Unblock device\n'
                         f'• Scan device\n'
                         f'• Monitor device\n'
                         f'• Configure settings\n\n'
                         f'More actions coming soon!',
                'timestamp': datetime.now().isoformat()
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error performing action: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }

# Action implementation functions (TODO: Implement actual functionality)
def block_device(device_mac: str, device_info: dict) -> bool:
    """Block a device from network access"""
    # TODO: Implement actual blocking logic
    # This could involve:
    # - Adding to router's block list
    # - Updating firewall rules
    # - Using network management APIs
    st.info("⚠️ Device blocking functionality not yet implemented")
    return True

def unblock_device(device_mac: str, device_info: dict) -> bool:
    """Unblock a device to restore network access"""
    # TODO: Implement actual unblocking logic
    st.info("⚠️ Device unblocking functionality not yet implemented")
    return True

def scan_device(device_mac: str, device_info: dict) -> dict:
    """Perform a security scan on the device"""
    # TODO: Implement actual scanning logic
    # This could involve:
    # - Port scanning
    # - Service detection
    # - Vulnerability assessment
    st.info("⚠️ Device scanning functionality not yet implemented")
    return {"scan_id": f"scan_{int(time.time())}"}

def enable_monitoring(device_mac: str, device_info: dict) -> bool:
    """Enable enhanced monitoring for the device"""
    # TODO: Implement actual monitoring logic
    # Update database to mark device as monitored
    db_conn, rwlock = libinspector.global_state.db_conn_and_lock
    with rwlock:
        sql = "UPDATE devices SET is_inspected = 1 WHERE mac_address = ?"
        db_conn.execute(sql, (device_mac,))
    return True