import functools
import libinspector
import requests
import json
import hashlib
from datetime import datetime
import streamlit as st
import time
from privacy_agent.llm_prompts import query_llm_fallback
import privacy_agent.rag_iot_service as rag_iot
from datetime import datetime

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
    """
    Async function to query information - handles both general info (RAG) and device activity (database)
    
    Args:
        query: User's question
        device_mac: Device MAC address
        context: Device context information
    """
    try:
        # Determine query type based on keywords and content
        query_type = determine_query_type(query)
        
        if query_type == 'device_activity':
            return query_device_activity(query, device_mac, context)
        else:
            return query_general_information(query, device_mac, context)
            
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }


def determine_query_type(query: str) -> str:
    """
    Determine if the query is about device activity or general information using LLM
    
    Args:
        query: User's question
        
    Returns:
        'device_activity' or 'general_information'
    """
    # Import here to avoid circular imports
    try:
        from privacy_agent.llm_prompts import determine_query_type_llm
        return determine_query_type_llm(query)
    except Exception as e:
        print(f"Failed to use LLM for query classification: {e}")
        # Fallback to keyword-based classification
        activity_keywords = [
            'turn on', 'turn off', 'activity', 'activities', 'communication', 'communicate', 'communicates',
            'endpoint', 'endpoints', 'connection', 'connections', 'traffic', 'network',
            'contact', 'contacts', 'talking to', 'connects to', 'communicating with',
            'sends data to', 'receives from', 'accessing', 'visited', 'requests',
            'current', 'currently', 'now', 'recent', 'lately', 'today',
            'behavior', 'patterns', 'usage', 'logs', 'history'
        ]
        
        query_lower = query.lower()
        
        # Check if query contains activity-related keywords
        for keyword in activity_keywords:
            if keyword in query_lower:
                return 'device_activity'
        
        # Default to general information for privacy, features, functions, etc.
        return 'general_information'


def query_device_activity(query: str, device_mac: str, context: dict) -> dict:
    """
    Query device activity information from the database
    
    Args:
        query: User's question about device activity
        device_mac: Device MAC address
        context: Device context information
    """
    try:
        db_conn, rwlock = libinspector.global_state.db_conn_and_lock
        device_name = context.get('device_name', 'Unknown Device')
        
        with rwlock:
            # Get network flows for this device
            flows_query = """
            SELECT DISTINCT 
                dest_hostname, dest_ip_address, dest_port,
                src_hostname, src_ip_address, src_port,
                protocol, timestamp, byte_count
            FROM network_flows 
            WHERE src_mac_address = ? OR dest_mac_address = ?
            ORDER BY timestamp DESC 
            LIMIT 50
            """
            
            flows_result = db_conn.execute(flows_query, (device_mac, device_mac))
            flows = flows_result.fetchall()
            
            # Get remote endpoints this device communicates with
            endpoints_query = """
            SELECT DISTINCT 
                CASE 
                    WHEN src_mac_address = ? THEN dest_hostname 
                    ELSE src_hostname 
                END as remote_hostname,
                CASE 
                    WHEN src_mac_address = ? THEN dest_ip_address 
                    ELSE src_ip_address 
                END as remote_ip,
                COUNT(*) as connection_count,
                MAX(timestamp) as last_seen
            FROM network_flows 
            WHERE (src_mac_address = ? AND dest_hostname IS NOT NULL) 
               OR (dest_mac_address = ? AND src_hostname IS NOT NULL)
            GROUP BY remote_hostname, remote_ip
            ORDER BY connection_count DESC
            LIMIT 20
            """
            
            endpoints_result = db_conn.execute(endpoints_query, 
                                             (device_mac, device_mac, device_mac, device_mac))
            endpoints = endpoints_result.fetchall()
        
        # Format the activity information
        activity_info = format_device_activity(device_name, device_mac, flows, endpoints, query)
        
        return {
            'status': 'success',
            'answer': activity_info,
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'query_type': 'device_activity'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error retrieving device activity: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }


def query_general_information(query: str, device_mac: str, context: dict) -> dict:
    """
    Query general information using RAG system
    
    Args:
        query: User's question about general device information
        device_mac: Device MAC address
        context: Device context information
    """
    try:
        # Enhanced query with device context for RAG
        enhanced_query = f"""
        Device Context: {json.dumps(context, indent=2)}
        
        User Question: {query}

        Please provide comprehensive information on this question about this device.
        """
        
        if not rag_iot.is_service_running():
            try:
                llm_answer = query_llm_fallback(query, context)
                return {
                    'status': 'success',
                    'answer': llm_answer,
                    'timestamp': datetime.now().isoformat(),
                    'query': query,
                    'query_type': 'general_information',
                    'source': 'llm_fallback',
                    'note': '⚠️ RAG service unavailable - using general LLM knowledge'
                }
            except Exception as llm_error:
                return {
                    'status': 'error',
                    'answer': f'❌ Error querying LLM fallback: {str(llm_error)}',
                    'timestamp': datetime.now().isoformat()
                }
        
        answer = rag_iot.query_rag_system(enhanced_query)
        return {
            'status': 'success',
            'answer': answer,
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'query_type': 'general_information'
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'answer': f'❌ Error querying RAG system: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }


def get_device_events(device_mac: str, max_events: int = 20) -> list:
    """
    Get detected events for a specific device from the event detection queue
    
    Args:
        device_mac: Device MAC address
        max_events: Maximum number of events to return
        
    Returns:
        List of (timestamp, event) tuples
    """
    try:
        # Import the event detection global state
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), 'event_detection'))
        
        from event_detection import global_state
        
        device_events = []
        
        # Access the queue in a thread-safe manner
        with global_state.global_state_lock:
            # Check if this device has events in the filtered_event_queue dictionary
            if device_mac in global_state.filtered_event_queue:
                device_events = global_state.filtered_event_queue[device_mac].copy()
                
                # Optionally clear old events (keep only recent ones)
                if len(device_events) > max_events * 2:
                    # Keep only the most recent events and update the queue
                    device_events.sort(key=lambda x: x[0], reverse=True)
                    global_state.filtered_event_queue[device_mac] = device_events[:max_events * 2]
                    device_events = device_events[:max_events]
                else:
                    device_events = device_events[:max_events]
        
        # Sort by timestamp (most recent first)
        device_events.sort(key=lambda x: x[0], reverse=True)
        return device_events
        
    except Exception as e:
        print(f"Error getting device events: {e}")
        return []


def format_device_activity(device_name: str, device_mac: str, flows: list, endpoints: list, query: str) -> str:
    """
    Format device activity information into a readable response with table-like structure
    
    Args:
        device_name: Name of the device
        device_mac: Device MAC address
        flows: Recent network flows
        endpoints: Remote endpoints the device communicates with
        query: Original user query
        
    Returns:
        Formatted activity information string with dataframe-like tables
    """
    from datetime import datetime
    import time
    
    activity_info = f"📊 **Device Activity Report for {device_name}** ({device_mac})\n\n"
    
    # Get detected events for this device
    detected_events = get_device_events(device_mac)
    
    # Detected Events Section (NEW)
    if detected_events:
        activity_info += "🔍 **Detected Events:**\n\n"
        activity_info += "| Timestamp | Event Description |\n"
        activity_info += "|-----------|------------------|\n"
        
        for timestamp, event in detected_events[:10]:  # Show last 10 events
            # Format timestamp
            if isinstance(timestamp, (int, float)):
                try:
                    formatted_time = datetime.fromtimestamp(timestamp).strftime('%m-%d %H:%M:%S')
                except:
                    formatted_time = str(timestamp)[:10]
            else:
                formatted_time = str(timestamp)[:15] if timestamp else "N/A"
            
            # Truncate long event descriptions
            event_desc = str(event)
            if len(event_desc) > 40:
                event_desc = event_desc[:37] + "..."
            
            activity_info += f"| {formatted_time:<13} | {event_desc:<40} |\n"
        
        activity_info += f"\n**📈 Events Summary:** {len(detected_events)} events detected\n\n"
    else:
        activity_info += "🔍 **Detected Events:** No recent events detected\n\n"
    
    # Remote endpoints section with table format
    if endpoints:
        activity_info += "🌐 **Remote Endpoints Communication:**\n\n"
        
        # Create table header
        activity_info += "| Hostname/IP | Connections | Last Seen |\n"
        activity_info += "|-------------|-------------|----------|\n"
        
        for endpoint in endpoints[:15]:  # Show top 15
            hostname = endpoint[0] or endpoint[1] or "Unknown"
            count = endpoint[2]
            last_seen = endpoint[3] or "N/A"
            
            # Truncate long hostnames for better table display
            if len(hostname) > 30:
                hostname = hostname[:27] + "..."
            
            activity_info += f"| {hostname:<30} | {count:>8} | {last_seen:<15} |\n"
        
        activity_info += "\n"
        
        # Summary stats
        total_endpoints = len(endpoints)
        total_connections = sum([ep[2] for ep in endpoints])
        activity_info += f"**📈 Endpoints Summary:** {total_endpoints} unique endpoints, {total_connections} total connections\n\n"
    else:
        activity_info += "🌐 **Remote Endpoints:** No recent communications found\n\n"
    
    # Recent activity section with table format
    if flows:
        activity_info += "🔄 **Recent Network Activity:**\n\n"
        
        # Create table header
        activity_info += "| Timestamp | Protocol | Destination | Bytes |\n"
        activity_info += "|-----------|----------|-------------|-------|\n"
        
        for flow in flows[:20]:  # Show last 20 activities
            dest_host = flow[0] or flow[1] or "Unknown"
            protocol = flow[6] or "Unknown"
            timestamp = flow[7] or "N/A"
            byte_count = flow[8] or 0
            
            # Format timestamp to be more readable
            if isinstance(timestamp, (int, float)) and timestamp > 0:
                try:
                    formatted_time = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                except:
                    formatted_time = str(timestamp)[:10]
            else:
                formatted_time = str(timestamp)[:10] if timestamp else "N/A"
            
            # Truncate long destinations
            if len(dest_host) > 25:
                dest_host = dest_host[:22] + "..."
            
            # Format byte count
            if byte_count >= 1024*1024:
                byte_display = f"{byte_count/(1024*1024):.1f}MB"
            elif byte_count >= 1024:
                byte_display = f"{byte_count/1024:.1f}KB"
            else:
                byte_display = f"{byte_count}B"
            
            activity_info += f"| {formatted_time:<9} | {protocol:<8} | {dest_host:<25} | {byte_display:>7} |\n"
        
        activity_info += "\n"
        
        # Network activity summary
        total_bytes = sum([f[8] for f in flows if f[8]])
        protocols = list(set([f[6] for f in flows if f[6]]))
        unique_destinations = len(set([f[0] or f[1] for f in flows if f[0] or f[1]]))
        
        # Format total bytes
        if total_bytes >= 1024*1024*1024:
            total_display = f"{total_bytes/(1024*1024*1024):.2f} GB"
        elif total_bytes >= 1024*1024:
            total_display = f"{total_bytes/(1024*1024):.1f} MB"
        elif total_bytes >= 1024:
            total_display = f"{total_bytes/1024:.1f} KB"
        else:
            total_display = f"{total_bytes} bytes"
        
        activity_info += f"**📊 Activity Summary:** {len(flows)} flows, {unique_destinations} destinations, {total_display} transferred\n"
        if protocols:
            activity_info += f"**🔌 Protocols Used:** {', '.join(protocols[:5])}\n\n"
    else:
        activity_info += "🔄 **Recent Activity:** No recent network activity found\n\n"
    
    # Device behavior analysis table (UPDATED to include events)
    if endpoints or flows or detected_events:
        activity_info += "📋 **Device Behavior Analysis:**\n\n"
        activity_info += "| Metric | Value | Status |\n"
        activity_info += "|--------|-------|--------|\n"
        
        recent_events_count = 0
        if detected_events:
            recent_events_count = len([e for e in detected_events if (time.time() - e[0]) < 3600])  # Last hour
            activity_info += f"| Recent Events | {len(detected_events)} total | {'⚠️ Active' if recent_events_count > 3 else '✅ Normal'} |\n"
            
            # Show latest event info
            if detected_events:
                latest_event_time = detected_events[0][0]
                latest_event = detected_events[0][1]
                try:
                    latest_time_str = datetime.fromtimestamp(latest_event_time).strftime('%H:%M:%S')
                    time_ago = int(time.time() - latest_event_time)
                    
                    if time_ago < 60:
                        status = "🔥 Just now"
                    elif time_ago < 300:
                        status = f"🟡 {time_ago//60}m ago"
                    else:
                        status = "📝 Logged"
                        
                    activity_info += f"| Latest Event | {latest_event[:15]}... | {status} |\n"
                except:
                    activity_info += f"| Latest Event | {str(latest_event)[:15]}... | 📝 Logged |\n"
        
        if endpoints:
            most_contacted = endpoints[0][0] if endpoints[0][0] else endpoints[0][1]
            contact_frequency = endpoints[0][2]
            activity_info += f"| Most Contacted | {most_contacted[:20]}... | {contact_frequency} times |\n"
            activity_info += f"| Total Endpoints | {len(endpoints)} unique | {'⚠️ High' if len(endpoints) > 20 else '✅ Normal'} |\n"
        
        if flows:
            activity_info += f"| Recent Flows | {len(flows)} flows | {'⚠️ Active' if len(flows) > 30 else '✅ Normal'} |\n"
            
            # Determine overall activity level
            activity_score = 0
            if len(flows) > 30: activity_score += 2
            elif len(flows) > 15: activity_score += 1
            
            if len(detected_events) > 5: activity_score += 2
            elif len(detected_events) > 2: activity_score += 1
            
            if recent_events_count > 3: activity_score += 1
            
            if activity_score >= 4:
                activity_level = "High Activity"
                status = "⚠️ Monitor"
            elif activity_score >= 2:
                activity_level = "Moderate Activity"  
                status = "🟡 Watch"
            else:
                activity_level = "Low Activity"
                status = "✅ Normal"
                
            activity_info += f"| Activity Level | {activity_level} | {status} |\n"
        
        activity_info += "\n"
    
    activity_info += "💡 *This data combines network traffic analysis and ML-based event detection.*\n"
    activity_info += "📝 *Events are detected using machine learning models trained on device behavior patterns.*\n"
    
    # Add timestamp for when this report was generated
    report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    activity_info += f"🕐 *Report generated at: {report_time}*"
    
    return activity_info



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
                'answer': f'⚠️ Device/network blocking is not implemented yet for {device_name} ({device_mac}).\n\n'
                         f'This feature will be added soon.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'block_device'
            }
            
        elif action_type == 'unblock':
            # TODO: Implement device unblocking
            result = unblock_device(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'⚠️ Device/network unblocking is not implemented yet for {device_name} ({device_mac}).\n\n'
                         f'This feature will be added soon.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'unblock_device'
            }
            
        elif action_type == 'scan':
            # TODO: Implement device scanning
            return query_device_activity(action_type, device_mac, context)
            
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
                'status': 'error',
                'answer': f'⚙️ Configuration is not supported yet for {device_name} ({device_mac}).\n\n'
                         f'This feature will be available soon.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'configure_not_supported'
            }
            
        elif action_type == 'monitor':
            # TODO: Implement device monitoring
            result = enable_monitoring(device_mac, device_info)
            return {
                'status': 'success',
                'answer': f'⚠️ Device/network monitoring is not implemented yet for {device_name} ({device_mac}).\n\n'
                         f'This feature will be added soon.',
                'timestamp': datetime.now().isoformat(),
                'action_performed': 'enable_monitoring'
            }
            
        else:
            return {
                'status': 'error',
                'answer': f'❌ Action "{action_type}" not supported yet\n\n'
                         f'Probable actions:\n\n'
                         f'• Block/Unblock device\n\n'
                         f'• Scan device\n\n'
                         f'• Monitor device\n\n'
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