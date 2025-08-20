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


@functools.lru_cache(maxsize=256)
def predict_device_vendor_and_name(hostname, vendor, oui, metadata=None):
    """
    Predict device vendor and name based on device information.
    Returns a dictionary with predicted vendor and device name.
    """
    # Convert JSON string back to dict if needed
    # metadata = json.loads(metadata) if metadata else None

    prompt = f"""
    You are a network device identification expert. Based on device information, 
    predict the most likely device vendor and specific device name/model.

    Examples:
    Device Info:
    - OUI: AA:BB:CC
    - Hostname: ["android-dcbab", "google.com"]
    - Vendor: Google
    - Metadata: {{"os": "Android", "device_type": "phone"}}
    Prediction: {{"vendor": "Google", "device_name": "Pixel Phone"}}

    Device Info:
    - OUI: 11:22:33
    - Hostname: ["LGWebOSTV", "lg.com"]
    - Vendor: LG
    - Metadata: {{"os": "WebOS", "device_type": "TV"}}
    Prediction: {{"vendor": "LG", "device_name": "WebOS Smart TV"}}

    Device Info:
    - OUI: FF:EE:DD
    - Hostname: ["hp-printer"]
    - Vendor: HP
    - Metadata: None
    Prediction: {{"vendor": "HP", "device_name": "LaserJet Printer"}}

    Device Info:
    - OUI: 44:85:00
    - Hostname: ["AppleTV"]
    - Vendor: Apple
    - Metadata: {{"os": "tvOS", "device_type": "streaming_device"}}
    Prediction: {{"vendor": "Apple", "device_name": "Apple TV 4K"}}

    Now predict for this device:
    Device Info:
    - OUI: {oui}
    - Hostname: {hostname}
    - Vendor: {vendor}
    - Metadata: {metadata if metadata else "None"}

    Return only a JSON object with "vendor" and "device_name" fields. Use the provided vendor if it's reliable, otherwise predict the most likely vendor based on OUI and hostname patterns.
    Do not return any explanation."""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(LLM_API_URL, json=payload)
        response_text = response.json().get("response", "").strip()
        
        # Try to parse the JSON response
        try:
            # Clean the response to extract JSON
            if response_text.startswith("```"):
                # Remove code block formatting if present
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
            
            prediction = json.loads(response_text)
            
            # Ensure the response has the expected format
            if isinstance(prediction, dict) and "vendor" in prediction and "device_name" in prediction:
                return prediction
            else:
                return {"vendor": vendor or " ", "device_name": "Unknown Device"}
                
        except json.JSONDecodeError:
            # Fallback: try to extract vendor and device name from text response
            lines = response_text.split('\n')
            result = {"vendor": vendor or " ", "device_name": "Unknown Device"}
            
            for line in lines:
                if "vendor" in line.lower() and ":" in line:
                    result["vendor"] = line.split(":")[-1].strip().strip('"')
                elif "device" in line.lower() and "name" in line.lower() and ":" in line:
                    result["device_name"] = line.split(":")[-1].strip().strip('"')
            
            return result
            
    except Exception as e:
        return {"vendor": vendor or "", "device_name": f"LLM error: {str(e)}"}


def analyze_intent(prompt: str) -> dict:
    """
    Analyze user prompt to determine if it's asking for information or requesting an action using LLM
    
    Returns:
        dict: {
            'intent': 'information' | 'action' | 'unknown',
            'confidence': float,
            'action_type': str (if intent is 'action'),
            'original_prompt': str
        }
    """
    
    llm_prompt = f"""
    You are an intent classification system for IoT device management. Analyze the user prompt and classify it as either requesting "information" or requesting an "action".

    Classification Guidelines:
    1. INFORMATION intent: User is asking questions, wants explanations, or seeking data about devices
       - Examples: "What is this device?", "How does it work?", "Show me network traffic", "Tell me about privacy"
    
    2. ACTION intent: User wants to perform an operation or change something
       - Action types: block, unblock, scan, restart, update, configure, monitor, backup, factory_reset
       - Examples: "Block this device", "Turn off the camera", "Scan the network", "Restart the router"

    Examples:
    
    User: "What is this device doing?"
    Response: {{"intent": "information", "confidence": 0.9, "action_type": null}}
    
    User: "Please block this device"
    Response: {{"intent": "action", "confidence": 0.9, "action_type": "block"}}
    
    User: "Can you explain how it connects?"
    Response: {{"intent": "information", "confidence": 0.8, "action_type": null}}
    
    User: "Turn off this smart TV"
    Response: {{"intent": "action", "confidence": 0.8, "action_type": "block"}}
    
    User: "Scan my network for vulnerabilities"
    Response: {{"intent": "action", "confidence": 0.9, "action_type": "scan"}}
    
    User: "Hello"
    Response: {{"intent": "information", "confidence": 0.3, "action_type": null}}

    Now analyze this user prompt:
    User: "{prompt}"
    
    Respond with ONLY a JSON object containing:
    - "intent": either "information" or "action"
    - "confidence": float between 0.1 and 0.9 
    - "action_type": specific action type if intent is "action", otherwise null
    
    Valid action types: block, unblock, scan, restart, update, configure, monitor, backup, factory_reset, generic
    """

    # Use the same LLM configuration as other functions
    from privacy_agent.llm_prompts import LLM_API_URL, MODEL_NAME
    
    payload = {
        "model": MODEL_NAME,
        "prompt": llm_prompt,
        "stream": False
    }
    
    try:
        response = requests.post(LLM_API_URL, json=payload, timeout=10)
        response_text = response.json().get("response", "").strip()
        
        # Clean and parse JSON response
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        
        result = json.loads(response_text)
        
        # Validate and format response
        if isinstance(result, dict) and "intent" in result and "confidence" in result:
            # Ensure confidence is within valid range
            confidence = max(0.1, min(0.9, float(result.get("confidence", 0.5))))
            
            # Validate intent
            intent = result.get("intent", "information")
            if intent not in ["information", "action"]:
                intent = "information"
            
            # Handle action_type
            action_type = result.get("action_type", None)
            if intent == "information":
                action_type = None
            elif intent == "action" and not action_type:
                action_type = "generic"
            
            return {
                'intent': intent,
                'confidence': confidence,
                'action_type': action_type,
                'original_prompt': prompt
            }
    
    except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"LLM intent analysis failed: {e}")
    
    # Fallback to information intent with low confidence
    return {
        'intent': 'information',
        'confidence': 0.3,
        'action_type': None,
        'original_prompt': prompt
    }