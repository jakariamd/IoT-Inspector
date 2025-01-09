import time
import scapy.all as sc
import core.global_state as global_state
import core.model as model
import core.common as common
import core.networking as networking
import traceback
from core.tls_processor import extract_sni
import core.friendly_organizer as friendly_organizer

# Jakaria: import additional libraries
import core.utils as utils
import ipaddress
import pandas as pd
import numpy as np
from scipy.stats import kurtosis
from scipy.stats import skew
from statsmodels import robust

# Jakaria: How often to write the burst statistics to the database (in seconds)
BURST_WRITE_INTERVAL = 1

# Jakaria: Timestamp of the last time the burst_dict was written to db
burst_dict_start_time = {}
burst_dict_all_burst = {}  # key (flow key) -> {key (time) -> [[packet element]]}


# How often to write the flow statistics to the database (in seconds)
FLOW_WRITE_INTERVAL = 2

# Temporarily holds the flow statistics; maps <src_device_mac_addr, dst_device_mac_addr, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol> -> a dictionary with keys <start_ts, end_ts, byte_count, packet_count>
flow_dict = {}

# Timestamp of the last time the flow_dict was written to db
flow_dict_last_db_write_ts = {'_': 0}


def process_packet():

    pkt = global_state.packet_queue.get()

    try:
        process_packet_helper(pkt)

    except Exception as e:
        common.log('[Pkt Processor] Error processing packet: ' + str(e) + ' for packet: ' + str(pkt) + '\n' + traceback.format_exc())


def process_packet_helper(pkt):

    # Write pending flows to database if the flow_dict has not been updated for FLOW_WRITE_INTERVAL sec
    if time.time() - flow_dict_last_db_write_ts['_'] > FLOW_WRITE_INTERVAL:
        write_pending_flows_to_db()
        flow_dict_last_db_write_ts['_'] = time.time()

    # ====================
    # Process individual packets and terminate
    # ====================

    if sc.ARP in pkt:
        return process_arp(pkt)

    if sc.DHCP in pkt:
        return process_dhcp(pkt)

    # Must have Ether frame and IP frame.
    if not (sc.Ether in pkt and sc.IP in pkt):
        return

    # Ignore traffic to and from this host's IP
    if global_state.host_ip_addr in (pkt[sc.IP].src, pkt[sc.IP].dst):
        return

    # DNS
    if sc.DNS in pkt:
        return process_dns(pkt)

    # ====================
    # Process flows and their first packets
    # ====================

    process_client_hello(pkt)

    # Jakaria: process burst; Resolve BuG burst processing error
    # BUG: Resolve BuG burst processing error: dictionary updated while in loop
    # Note: not considering ARP, DHCP, DNS packets in burst
    try: process_burst(pkt)
    except Exception as e: common.log('[Burst Processor] Error processing packet: ' + str(e))

    # Process flow
    return process_flow(pkt)


def process_arp(pkt):
    """
    Updates ARP cache upon receiving ARP packets, only if the packet is not
    spoofed.

    """
    if not ((pkt.op == 1 or pkt.op == 2)):
        return

    if pkt.hwsrc == global_state.host_mac_addr:
        return

    if pkt.psrc == '0.0.0.0':
        return

    ip_addr = pkt.psrc
    mac_addr = pkt.hwsrc

    # Update the devices table
    has_updated = False
    with model.write_lock:
        with model.db:
            device = model.Device.get_or_none(mac_addr=mac_addr)
            if device is None:
                # Never seen this device before, so create one
                model.Device.create(mac_addr=mac_addr, ip_addr=ip_addr)
                has_updated = True
            else:
                # Update the IP address if different
                if device.ip_addr != ip_addr:
                    device.ip_addr = ip_addr
                    device.save()
                    has_updated = True

    # Update the ARP cache
    global_state.arp_cache.update(ip_addr, mac_addr)
    if has_updated:
        common.log(f'[Pkt Processor] Updated ARP cache: {ip_addr} -> {mac_addr}')


def process_dns(pkt):

    src_mac_addr = pkt[sc.Ether].src
    dst_mac_addr = pkt[sc.Ether].dst

    # Find the device that makes this DNS request or response
    if global_state.host_mac_addr == src_mac_addr:
        device_mac_addr = dst_mac_addr
    elif global_state.host_mac_addr == dst_mac_addr:
        device_mac_addr = src_mac_addr
    else:
        return

    # This device cannot be the gateway
    try:
        gateway_mac_addr = global_state.arp_cache.get_mac_addr(global_state.gateway_ip_addr)
    except KeyError:
        return
    if device_mac_addr == gateway_mac_addr:
        return

    # Parse hostname
    try:
        hostname = pkt[sc.DNSQR].qname.decode('utf-8').lower()
    except Exception:
        return

    # Remove trailing dot from hostname
    if hostname[-1] == '.':
        hostname = hostname[0:-1]

    # Parse DNS response to extract IP addresses in A records
    ip_set = set()
    if sc.DNSRR in pkt and pkt[sc.DNS].an:
        for ix in range(pkt[sc.DNS].ancount):
            # Extracts A-records
            if pkt[sc.DNSRR][ix].type == 1:
                # Extracts IPv4 addr in A-record
                ip = pkt[sc.DNSRR][ix].rdata
                if networking.is_ipv4_addr(ip):
                    ip_set.add(ip)
                    # Write to cache
                    with global_state.global_state_lock:
                        global_state.hostname_dict[ip] = hostname

    # If we don't have an IP address, that's fine. We'll still store the domain queried, setting the IP address to empty.
    if not ip_set:
        ip_set.add('')

    # Write to domain-IP mapping to database
    created = False
    with model.write_lock:
        with model.db:
            for ip_addr in ip_set:
                _, created = model.Hostname.get_or_create(
                    device_mac_addr=device_mac_addr,
                    hostname=hostname,
                    ip_addr=ip_addr,
                    data_source='dns'
                )

    if created:
        common.log(f'[Pkt Processor] DNS: Device {device_mac_addr}: {hostname} -> {ip_set}')


def process_flow(pkt):

    # Must have TCP or UDP layer
    if sc.TCP in pkt:
        protocol = 'tcp'
        layer = sc.TCP
    elif sc.UDP in pkt:
        protocol = 'udp'
        layer = sc.UDP
    else:
        return

    # Parse packet
    src_mac_addr = pkt[sc.Ether].src
    dst_mac_addr = pkt[sc.Ether].dst
    src_ip_addr = pkt[sc.IP].src
    dst_ip_addr = pkt[sc.IP].dst
    src_port = pkt[layer].sport
    dst_port = pkt[layer].dport

    # No broadcast
    if dst_mac_addr == 'ff:ff:ff:ff:ff:ff' or dst_ip_addr == '255.255.255.255':
        return

    inspector_host_mac_addr = global_state.host_mac_addr

    # Find the actual MAC address that the Inspector host pretends to be if this
    # is a local communication; otherwise, assume that Inspector pretends to be
    # the gateway
    if src_mac_addr == inspector_host_mac_addr:
        try:
            src_mac_addr = global_state.arp_cache.get_mac_addr(src_ip_addr)
        except KeyError:
            src_mac_addr = ''
    elif dst_mac_addr == inspector_host_mac_addr:
        try:
            dst_mac_addr = global_state.arp_cache.get_mac_addr(dst_ip_addr)
        except KeyError:
            dst_mac_addr = ''
    else:
        return

    # Save the flow into a temporary flow queue
    flow_key = (
        src_mac_addr, dst_mac_addr, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol
    )

    # todo: Check if stats updates in the dics
    flow_stat_dict = flow_dict.setdefault(flow_key, {
        'start_ts': time.time(),
        'end_ts': time.time(),
        'byte_count': 0,
        'pkt_count': 0
    })
    flow_stat_dict['end_ts'] = time.time()
    flow_stat_dict['byte_count'] += len(pkt)
    flow_stat_dict['pkt_count'] += 1


def write_pending_flows_to_db():
    """Write flows in the flow_dict into the database (Flow table)"""

    with model.write_lock:
        with model.db:
            for flow_key, flow_stat_dict in flow_dict.items():

                # Unpack the flow key
                src_mac_addr, dst_mac_addr, src_ip_addr, dst_ip_addr, src_port, dst_port, protocol = flow_key

                # Find the country in both directions
                src_country = ''
                dst_country = ''
                if src_mac_addr == '' and src_ip_addr != '':
                    src_country = friendly_organizer.get_country_from_ip_addr(src_ip_addr)
                if dst_mac_addr == '' and dst_ip_addr != '':
                    dst_country = friendly_organizer.get_country_from_ip_addr(dst_ip_addr)

                # Fill in the hostname information
                src_hostname = friendly_organizer.get_hostname_from_ip_addr(src_ip_addr, in_memory_only=True)
                dst_hostname = friendly_organizer.get_hostname_from_ip_addr(dst_ip_addr, in_memory_only=True)

                # Fill out the registered domain info and tracker company info per hostname
                src_reg_domain = ''
                dst_reg_domain = ''
                src_tracker_company = ''
                dst_tracker_company = ''
                if src_hostname:
                    src_reg_domain = friendly_organizer.get_reg_domain(src_hostname)
                    src_tracker_company = friendly_organizer.get_tracker_company(src_hostname)
                if dst_hostname:
                    dst_reg_domain = friendly_organizer.get_reg_domain(dst_hostname)
                    dst_tracker_company = friendly_organizer.get_tracker_company(dst_hostname)

                # Write to database
                model.Flow.create(
                    start_ts=flow_stat_dict['start_ts'],
                    end_ts=flow_stat_dict['end_ts'],
                    src_device_mac_addr=src_mac_addr,
                    dst_device_mac_addr=dst_mac_addr,
                    src_port=src_port,
                    dst_port=dst_port,
                    src_ip_addr=src_ip_addr,
                    dst_ip_addr=dst_ip_addr,
                    src_country=src_country,
                    dst_country=dst_country,
                    src_hostname=src_hostname,
                    dst_hostname=dst_hostname,
                    src_reg_domain=src_reg_domain,
                    dst_reg_domain=dst_reg_domain,
                    src_tracker_company=src_tracker_company,
                    dst_tracker_company=dst_tracker_company,
                    protocol=protocol,
                    byte_count=flow_stat_dict['byte_count'],
                    packet_count=flow_stat_dict['pkt_count']
                )

    common.log('[Pkt Processor] Wrote {} flows to database. Pending packet_queue size: {}'.format(
        len(flow_dict), global_state.packet_queue.qsize()
    ))

    # Clear the flow_dict
    flow_dict.clear()


def process_dhcp(pkt):

    # Must be a DHCP Request broadcast
    if pkt[sc.Ether].dst != 'ff:ff:ff:ff:ff:ff':
        return

    try:
        option_dict = dict(
            [t for t in pkt[sc.DHCP].options if isinstance(t, tuple)]
        )
    except Exception:
        return

    try:
        device_hostname = option_dict.setdefault('hostname', '').decode('utf-8')
        if device_hostname == '':
            return
    except Exception:
        return

    device_mac = pkt[sc.Ether].src

    # Ignore DHCP responses from this host
    if device_mac == global_state.host_mac_addr:
        return

    # Update the devices table
    with model.write_lock:
        with model.db:
            device = model.Device.get_or_none(mac_addr=device_mac)
            if device is None:
                # Never seen this device before, so create one
                model.Device.create(mac_addr=device_mac, ip_addr='', dhcp_hostname=device_hostname)
            else:
                # Update the hostname if different
                if device.dhcp_hostname != device_hostname:
                    device.dhcp_hostname = device_hostname
                    device.save()

    common.log(f'[Pkt Processor] DHCP: Device {device_mac}: {device_hostname}')


def process_client_hello(pkt):
    """Extracts the SNI field from the ClientHello packet."""

    # Make sure that the Inspector host should be the destination of this packet
    if pkt[sc.Ether].dst != global_state.host_mac_addr:
        return

    sni = extract_sni(pkt)
    if not sni:
        return

    sni = sni.lower()

    # Write the SNI hostname to the `hostname` table of the database
    created = False
    with model.write_lock:
        with model.db:
            _, created = model.Hostname.get_or_create(
                device_mac_addr=pkt[sc.Ether].src,
                hostname=sni,
                ip_addr=pkt[sc.IP].dst,
                data_source='sni'
            )

    # Write to local cache
    with global_state.global_state_lock:
        global_state.hostname_dict[pkt[sc.IP].dst] = sni

    if created:
        common.log(f'[Pkt Processor] TLS: Device {pkt[sc.Ether].src}: {sni}')



# Note: This fiunction proess packet for activity detection
# ==========================================================================================
# Process packet to burst; Input: packet; Output: none
# BUG: processing same packet twice: can be merged with process_packets, discuss with Danny
# BUG: process re-transmission and duplicate packets, potential cause of misclassification
# ==========================================================================================

def process_burst(pkt):
    # Note: Packets must have TCP or UDP layer 
    # Note: WE only consider packets which has either TCP layer or UDP layer 
    if sc.TCP in pkt:
        protocol = 'TCP'
        layer = sc.TCP
    elif sc.UDP in pkt:
        protocol = 'UDP'
        layer = sc.UDP
    else:
        return

    # =================================================================
    # Parse packet informations
    # =================================================================
    # frame_number = 0              # not useful for feature generation
    # time_delta = 0                # will be canculated lated
    # stream = 0                    # not useful for feature generation
    time_epoch = pkt.time           # packet current time, to be used to generate time_delta for consecutive packets
    frame_len = len(pkt)            # size of packet
    ip_proto = pkt[sc.IP].proto     # protocol number: 6 (TCP), 17 (UDP)  
    _ws_protocol = ''               # highest layer in the protocol
    try:
        highest_layer = pkt.lastlayer()
        _ws_protocol = getattr(highest_layer, 'name', str(highest_layer))
        # todo: check if highest layer captures the TLS versions; for now it is not 
    except: 
        _ws_protocol = protocol
    
    # todo: set empty for now; useful for removing re/duplicate transmission
    _ws_expert = ""                 


    # Get MAC, IP addresses, port numbers 
    src_mac_addr = pkt[sc.Ether].src
    dst_mac_addr = pkt[sc.Ether].dst
    src_ip_addr = pkt[sc.IP].src
    dst_ip_addr = pkt[sc.IP].dst
    src_port = pkt[layer].sport
    dst_port = pkt[layer].dport

    # Note: Ignoring broscasting messes
    # Note: Maynot appropriate for anomaly detection 
    if dst_mac_addr == 'ff:ff:ff:ff:ff:ff' or dst_ip_addr == '255.255.255.255':
        return
    
    # Note: validating correct ip_address
    # Note: Maynot appropriate for anomaly detection 
    if utils.validate_ip_address(src_ip_addr)==False or utils.validate_ip_address(dst_ip_addr)==False:
            return

    # Finding host MAC address
    inspector_host_mac_addr = global_state.host_mac_addr

    # Find the actual MAC address that the Inspector host pretends to be if this is a 
    # local communication; otherwise, assume that Inspector pretends to be the gateway
    if src_mac_addr == inspector_host_mac_addr:
        try:
            src_mac_addr = global_state.arp_cache.get_mac_addr(src_ip_addr)
        except KeyError:
            src_mac_addr = ''
    elif dst_mac_addr == inspector_host_mac_addr:
        try:
            dst_mac_addr = global_state.arp_cache.get_mac_addr(dst_ip_addr)
        except KeyError:
            dst_mac_addr = ''
    else:
        return

    # extract hostnames
    # Note: North Eastern (BehavIoT) use different method for finding the hostname
    # BehavIoT Method: look DNS, SNI for hostnames; if found: return else: use dig -x ip_address 
    # todo Ask Danny: change inmemory to False; ask NYU to find host name
    # Note: Jakaria changed the friendly_organizer.get_hostname_from_ip_addr() function
    src_hostname = friendly_organizer.get_hostname_from_ip_addr(src_ip_addr, in_memory_only=True)
    dst_hostname = friendly_organizer.get_hostname_from_ip_addr(dst_ip_addr, in_memory_only=True)


    # Note: Key is different from IoT Inspector: inspector use different sets of 7 elements, different order
    # Used to idenfy flow which current packets belong to
    flow_key = (ip_proto, src_ip_addr, src_port, dst_ip_addr, dst_port, src_mac_addr)
    hostname = dst_hostname.lower()

    #  check if local packet or incoming packet 
    if ipaddress.ip_address(dst_ip_addr).is_private and ipaddress.ip_address(src_ip_addr).is_private == False: # incoming packet 
        flow_key = (ip_proto, dst_ip_addr, dst_port, src_ip_addr, src_port, dst_mac_addr)
        hostname = src_hostname.lower()

    if ipaddress.ip_address(dst_ip_addr).is_private and ipaddress.ip_address(src_ip_addr).is_private: # incoming local packet
        if ipaddress.ip_address(dst_ip_addr) > ipaddress.ip_address(src_ip_addr):
            flow_key = (ip_proto, dst_ip_addr, dst_port, src_ip_addr, src_port, dst_mac_addr)
            hostname = src_hostname.lower()

    # todo: remove duplicate packets (behavIoT used WS comments to identify dupalicate packets);
    # get the start time for the burst (aka flow)
    burst_start_time = burst_dict_start_time.setdefault(flow_key, time_epoch)  

    # clean previously stored burst packets if threshold has been passed
    if (time_epoch - burst_start_time) > BURST_WRITE_INTERVAL:
        # clean temp dicts 
        pop_time = burst_dict_start_time.pop(flow_key, 0)                       # start time of burst 
        pop_burst = burst_dict_all_burst.pop((flow_key, burst_start_time), [])  # list if packets

        # writing burst in file/db
        process_pending_burst(flow_key, pop_time, pop_burst)

    # append the current packet with burst packets 
    burst_dict_all_burst.setdefault((flow_key, burst_start_time), []).append([time_epoch, frame_len, _ws_protocol, hostname, ip_proto, src_ip_addr, src_port, dst_ip_addr, dst_port, dst_mac_addr])

    # clear all the burst if current time pass the threshold
    for key in burst_dict_all_burst:
        if (time_epoch - key[1]) > BURST_WRITE_INTERVAL:
            # clean temp dicts 
            pop_time = burst_dict_start_time.pop(key[0], 0)
            pop_burst = burst_dict_all_burst.pop((key[0], key[1]), [])

            # writing burst in file/db
            process_pending_burst(key[0], pop_time, pop_burst)
    return 
    

# # define the expected features of a burst 
# cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
#              "skewLength", "kurtosisLength", "meanTBP", "varTBP", "medianTBP", "kurtosisTBP",
#              "skewTBP", "network_total", "network_in", "network_out", "network_external", "network_local",
#             "network_in_local", "network_out_local", "meanBytes_out_external",
#             "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local", "device", "state", "event", "start_time", "protocol", "hosts"]

# todo: check if this function needs to be runnin in a separate thread 
# todo: because it will need to run in a separate thread to write the burst features to the database
# process a burst from the queue to extract features
def process_pending_burst(flow_key, pop_time, pop_burst):
    # log the burst information
    # todo: remove log if not needed 
    common.log(f'[Writing Burst]: {flow_key} \t {pop_time} \t {pop_burst}')

    # create a header for storing the burst into a dataframe corresponding to burst element
    # [time_epoch, frame_len, _ws_protocol, hostname, ip_proto, src_ip_addr, src_port, dst_ip_addr, dst_port, dst_mac_addr]
    header = ["ts","frame_len","protocol","host", "trans_proto", "ip_src", "srcport", "ip_dst", "dstport","mac_addr"]

    # check number of packets in the burst discart if 
    # burst has only one packet
    if len(pop_burst) < 2: 
        return
    
    # ----------------------------------------------------
    # compute features from burst of packetes and flow key
    # ----------------------------------------------------
    pd_burst = pd.DataFrame(pop_burst, columns=header)
    pd_burst.frame_len = pd_burst.frame_len.astype(int)
    pd_burst.ts = pd_burst.ts.astype(float)

    # Calculate the time difference (delta) between consecutive rows and
    # Set the first value of time_delta to 0
    pd_burst['ts_delta'] = pd_burst['ts'].diff()
    pd_burst.loc[0, 'ts_delta'] = 0.0      
    pd_burst.ts_delta = pd_burst.ts_delta.astype(float)

    # compute_tbp_features
    start_time = pd_burst.ts.min()
    meanBytes = pd_burst.frame_len.mean()
    minBytes = pd_burst.frame_len.min()
    maxBytes = pd_burst.frame_len.max()
    medAbsDev = robust.mad(pd_burst.frame_len)
    skewL = skew(pd_burst.frame_len)
    kurtL = kurtosis(pd_burst.frame_len)

    # p = [10, 20, 30, 40, 50, 60, 70, 80, 90]
    # percentiles = np.percentile(pd_burst.frame_len, p)
    kurtT = kurtosis(pd_burst.ts_delta)
    skewT = skew(pd_burst.ts_delta)
    meanTBP = pd_burst.ts_delta.mean()
    varTBP = pd_burst.ts_delta.var()
    medTBP = pd_burst.ts_delta.median()

    # compute # of packet related features
    network_in = 0 # Network going to target device.
    network_out = 0 # Network going from target device 
    # network_both = 0 # Network going to/from target device.
    network_external = 0 # Network not going to just 192.168.10.248.
    network_local = 0
    network_in_local = 0 # 
    network_out_local = 0 #
    # anonymous_source_destination = 0
    network_total = 0
    meanBytes_out_external = 0 
    meanBytes_in_external = 0 
    meanBytes_out_local = 0 
    meanBytes_in_local = 0 

    # target devices meta information 
    my_device_mac = flow_key[-1]
    my_device_addr = flow_key[1]
    external_destination_addr = flow_key[3]
    local_destination_device = ''

    # todo: check if not needed ; updated values with known knowledge above 

    for j, m in zip(pd_burst.ip_dst, pd_burst.mac_addr):
        if m == my_device_mac:
            continue
        elif ipaddress.ip_address(j).is_private==True:  # router IPs
            local_destination_device = m
            break
    

    for i, j, f_len, k_host in zip(pd_burst.ip_src, pd_burst.ip_dst, pd_burst.frame_len, pd_burst.host):
        network_total += 1
        
        if ipaddress.ip_address(i).is_private==True and (ipaddress.ip_address(j).is_private==False): # source addr; outbound packet 
            network_out += 1
            network_external += 1
            meanBytes_out_external += f_len
            
        elif ipaddress.ip_address(j).is_private==True and (ipaddress.ip_address(i).is_private==False): # destation addr; inbound packet 
            network_in += 1
            network_external += 1
            meanBytes_in_external += f_len

        elif i == my_device_addr and (ipaddress.ip_address(j).is_private==True) : # local outgoing packet 
            network_out_local += 1
            network_local += 1
            meanBytes_out_local+= f_len

        elif (ipaddress.ip_address(i).is_private==True) and j == my_device_addr: # local inbound packet 
            network_in_local += 1
            network_local += 1
            meanBytes_in_local += f_len

        elif k_host == '(local network)': 
            network_local += 1           
        else:
            pass

    meanBytes_out_external = meanBytes_out_external/network_out if network_out else 0
    meanBytes_in_external = meanBytes_in_external/network_in if network_in else 0
    meanBytes_out_local = meanBytes_out_local/network_out_local if network_out_local else 0
    meanBytes_in_local = meanBytes_in_local/network_in_local if network_in_local else 0


    # host is either from the host column, or the destination IP if host doesn't exist
    hosts = set([ str(host) for i, host in enumerate(pd_burst.host.fillna("")) ])
    protocol = set([str(proto) for i, proto in enumerate(pd_burst.protocol.fillna(""))])

    if ('DNS' in protocol) or ('DHCP' in protocol) or ('NTP' in protocol) or ('SSDP' in protocol) or ('MDNS' in protocol):
        pass
    else:
        if pd_burst.trans_proto[0] == 6:
            protocol = set(['TCP'])
        elif pd_burst.trans_proto[0] == 17:
            protocol = set(['UDP'])
    if network_total == network_local: 
        # hosts = set(['local'])
        hosts = set([str(local_destination_device)])
    
    host_output = ";".join([x for x in hosts if x!= ""])
    # merge hostnames
    if host_output.startswith('ec') and (host_output.endswith('compute.amazonaws.com') or host_output.endswith('compute-1.amazonaws.com')):
            host_output = '*.compute.amazonaws.com'
    if host_output == '':
        if str(external_destination_addr) == '':
            common.log(f'[Creating Feature]: host error {my_device_mac} \t {external_destination_addr}')
            # print('Error:', device_name, state, event)
            # exit(1)   # todo Jakaria commented this line
        host_output = str(external_destination_addr)

    d = [ meanBytes, minBytes, maxBytes, medAbsDev, skewL, kurtL, meanTBP, varTBP, medTBP,
         kurtT, skewT, network_total, network_in, network_out, network_external, network_local,
         network_in_local, network_out_local, meanBytes_out_external,
         meanBytes_in_external, meanBytes_out_local, meanBytes_in_local, my_device_mac, 'unctrl', 'unctrl', start_time, ";".join([x for x in protocol if x!= ""]), host_output ]
    
    store_burst_in_db(d)

    return
        
    # todo: check datafrme before storing
    # todo: store data to somewhere
    # todo: debug Error processing packet: dictionary changed size during iteration, check the log file for detail of the error
    # make the dictionary operation lock safe
    # common.log(f'[Writing Feature]: {flow_key} \t {pop_time} \t {d}')

# store processed burst features (data) into database
# input: a data point
# output: None
def store_burst_in_db(data):
    # Note: for now storing in a queue, later store in database
    # make to lock safe
    """
    Adds a data to the data queue.
    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.burst_queue.put(data)


    # todo: read queue, for event prediction
    # d = global_state.burst_queue.get()
    # common.log(f'[Reading Feature]: Database {d}')