import functools
import requests
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils

# Optional: use Hugging Face API or local model like ollama
# Ollama default endpoint= "http://localhost:11434/api/generate"  # Ollama default endpoint
LLM_API_URL = "http://localhost:11434/api/generate"  


# MODEL_NAME = "phi3"  # or 
# MODEL_NAME = "mistral" # or
MODEL_NAME = "llama3" 


@functools.lru_cache(maxsize=256)
def generate_device_description_cached(mac, ip, hostname, vendor, oui):
    device = {"ip": ip, "mac": mac, "oui": oui, "hostname": hostname, "vendor": vendor}
    prompt = f"""
    You are a network device analyzer. Based on device information, 
    provide a brief description of what the device likely is and its common use.

    Examples:
    Device Info:
    - IP: 192.168.1.24
    - MAC: aa:bb:cc:dd:ee:ff
    - OUI: AA:BB:CC
    - Hostname: android-dcbab
    - Vendor: Google
    Description: Android phone streaming social apps

    Device Info:
    - IP: 192.168.1.5
    - MAC: 11:22:33:44:55:66
    - OUI: 11:22:33
    - Hostname: LGWebOSTV
    - Vendor: LG
    Description: LG smart TV likely used for Netflix

    Device Info:
    - IP: 192.168.1.10
    - MAC: ff:ee:dd:cc:bb:aa
    - OUI: FF:EE:DD
    - Hostname: hp-printer
    - Vendor: HP
    Description: Wireless printer connected over Wi-Fi

    Now analyze this device:
    Device Info:
    - IP: {device['ip']}
    - MAC: {device['mac']}
    - OUI: {device['oui']}
    - Hostname: {device['hostname']}
    - Vendor: {device['vendor']}
    Describe this device in 1 sentence in the same format of the given examples. 
    Remove the "Device Info" and "Description" labels, just provide the description."""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(LLM_API_URL, json=payload)
        return response.json().get("response", "No response").strip()
    except Exception as e:
        return f"LLM error: {str(e)}"
    


@functools.lru_cache(maxsize=256)
def generate_device_description(hostname, vendor, oui, metadata=None):
    # Convert JSON string back to dict if needed
    metadata = json.loads(metadata) if metadata else None

    prompt = f"""
    You are a network device analyzer. Based on device information, 
    provide a brief description of what the device likely is and its common use.

    Examples:
    Device Info:
    - OUI: AA:BB:CC
    - Hostname: ["android-dcbab", "google.com"]
    - Vendor: Google
    - Metadata: {{"os": "Android", "device_type": "phone"}}
    Description: Android phone streaming social apps

    Device Info:
    - OUI: 11:22:33
    - Hostname: ["LGWebOSTV", "lg.com"]
    - Vendor: LG
    - Metadata: {{"os": "WebOS", "device_type": "TV"}}
    Description: LG smart TV likely used for Netflix

    Device Info:
    - OUI: FF:EE:DD
    - Hostname: ["hp-printer"]
    - Vendor: HP
    - Metadata: None
    Description: Wireless printer connected over Wi-Fi

    Now analyze this device:
    Device Info:
    - OUI: {oui}
    - Hostname: {hostname}
    - Vendor: {vendor}
    - Metadata: {json.dumps(metadata) if metadata else "None"}

    Describe this device in 1 sentence and return only "Description" field value. 
    Exclude "OUI", "Hostname", "Vendor" and "Metadata" labels, just provide the description."""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(LLM_API_URL, json=payload)
        return response.json().get("response", "No response").strip()
    except Exception as e:
        return f"LLM error: {str(e)}"


@functools.lru_cache(maxsize=256)
def device_privacy_information_agent(device_description):
    """
    This function retrieves privacy-related information for a device based on its description.
    It uses the LLM to generate a description of the device's likely use and privacy implications.
    """

    prompt = f"""
    You are a privacy information agent. Based on the device description, 
    provide a brief summary of the device's any potential privacy implications.

    Device Description: {device_description}

    Only list a few key points about the device's privacy implications.
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(LLM_API_URL, json=payload)
        return response.json().get("response", "No response").strip()
    except Exception as e:
        return f"LLM error: {str(e)}"