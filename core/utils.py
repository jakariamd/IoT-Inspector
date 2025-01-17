import ipaddress
from functools import lru_cache

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
