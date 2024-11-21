import ipaddress

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