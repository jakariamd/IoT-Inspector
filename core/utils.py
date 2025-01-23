import ipaddress
from functools import lru_cache
from core.common import get_project_directory
import os
import json

def validate_ip_address(address):
    """ check if it's a valid ip address

    Args:
        address (string): ip address

    Returns:
        bool: true as valid 
    """
    try:
        ip = ipaddress.ip_address(address)
        # print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        # print("IP address {} is not valid".format(address)) 
        return False


# NOTE: Currently using hard coded values for device names
# TODO: Update this function to use a database or configuration file or a dropdown list from the UI to get the device names
@lru_cache(maxsize=128)
def device_name_mapping(device_name):
    if device_name == 'Amazon Plug':
        return 'amazon-plug'
    if device_name == 'Amazon Echo':
        return 'echodot4b'
    if device_name == 'Amazon Echo Dot':
        return 'echoshow5'
    if device_name == 'Ring Camera':
        return 'ring-camera' 
    if device_name == 'Tapo Bulb':
        return 'tplink-bulb'
    if device_name == 'Yi Cam':
        return 'yi-camera'
    if device_name == 'Ring Doorbell':
        return 'ring-camera'
    if device_name == 'Wyze Cam':
        return 'wyze-cam'
    
    return 'unknown'



@lru_cache(maxsize=128)
def protocol_transform(test_protocols):
    # for i in range(len(test_protocols)):
    if 'TCP' in test_protocols:
        test_protocols = 'TCP'
    elif 'MQTT' in test_protocols:
        test_protocols = 'TCP'
    elif 'UDP' in test_protocols:
        test_protocols = 'UDP'
    elif 'TLS' in test_protocols:
        test_protocols = 'TCP'
    if ';' in test_protocols:
        tmp = test_protocols.split(';')
        test_protocols = ' & '.join(tmp)
    return test_protocols

# transform multiple hosts to single host
@lru_cache(maxsize=128)
def host_transform(test_hosts):
    # process host
    if test_hosts == None:
        return 'non'

    if test_hosts!= '':
        try:
            tmp = test_hosts.split(';')
        except:
            return 'non'
        test_hosts= tmp[0]
    else:
        return 'non'

    test_hosts = test_hosts.lower()   
    test_hosts = test_hosts.replace('?','')   

    return test_hosts


# Jakaria: Added the following functions are not needed anymore, 
# as we are using the variables  to store device info 
# TODO: can be deleted, along with the data_devices.json file and test cases 
def add_idle_device_in_db(mac_address, is_idle=1):
    """
    Add device info in database
    Args:
        device: Device object
    """
    try:
        # Load the existing JSON data from the file
        file_path = os.path.join(get_project_directory(), 'data_devices.json')
        with open(file_path, 'r') as file:
            data = json.load(file)
            data['devices'][mac_address] = {
                'is_idle': is_idle
            }
            # Save the updated JSON data back to the file
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
    except Exception as e:
        print('Error saving device info in database: ' + str(e))


def is_device_idle(mac_address):
    """
    Check if a device is set to be idle in the database
    Args:
        mac_address: MAC address of the device
    Returns:
        bool: True if the device is idle, False otherwise
    """
    try:
        # Load the existing JSON data from the file
        file_path = os.path.join(get_project_directory(), 'data_devices.json')
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # Check if the device exists and its is_idle status
        if mac_address in data['devices']:
            return data['devices'][mac_address].get('is_idle', 0) == 1
        else:
            return False
    except Exception as e:
        print('Error reading device info from database: ' + str(e))
        return False