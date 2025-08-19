import functools
import libinspector
import requests
import json
import hashlib


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
