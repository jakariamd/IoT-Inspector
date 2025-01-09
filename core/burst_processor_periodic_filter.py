"""
===============================================================================
Title: Burst Processor Periodic Filter
Author: Md Jakaria
Date: Jan 2025
Description: This module processes periodic bursts and includes helper functions for burst filtering.
Reference: This code was inspired by and adapted from the work of Tianrui Hue on https://github.com/NEU-SNS/BehavIoT/tree/main.
===============================================================================
"""


import core.global_state as global_state
import core.common as common
from core.burst_processor import get_product_name_by_mac
from core.burst_processor import ttl_lru_cache
import traceback
from functools import lru_cache
import core.model as model
import time
import os
import pickle
import pandas as pd
import numpy as np
import scipy as sp

from core.utils import device_name_mapping, protocol_transform

# define the expected features of a burst 
# cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
#              "skewLength", "kurtosisLength", "meanTBP", "varTBP",
#              "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
#              "network_in", "network_out", "network_external", "network_local",
#             "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
#             "meanBytes_out_local", "meanBytes_in_local",
#             "device", "state", "event", "start_time", "protocol", "hosts"]



def periodic_filter_burst():

    burst = global_state.ss_burst_queue.get()

    try:
        periodic_filter_burst_helper(burst)

    except Exception as e:
        common.log('[Burst Periodic-filter] Error processing burst: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())


@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_mac_address_list():
    """Returns a list of all MAC addresses."""
    mac_addresses = []

    with model.db:

        query = model.Device.select(model.Device.mac_addr)

        for device in query:
            mac_addresses.append(device.mac_addr)

    return mac_addresses


@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_periods(device_name):
    # get device name from MAC address
    # device_name = get_product_name_by_mac(mac_address)

    device_name = device_name_mapping(device_name)

    if device_name == 'unknown':
        return ('unknown', 'unknown')
    
    # todo: write a function to map the device name to model file name 
    # if device_name == 'Amazon Plug':
    #     device_name = 'amazon-plug'
    # elif device_name == 'Amazon Echo':
    #     device_name = 'echodot4b'
    # elif device_name == 'Ring Camera':
    #     device_name = 'ring-camera'

    # Load periodic fingerprints
    model_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '..', 'models', 'freq_period', 'fingerprints', device_name + '.txt'
        )
    
    if os.path.exists(model_dir):
        with open(model_dir, 'r') as file:
            periodic_tuple = []
            host_set = set()

            for line in file:
                tmp = line.split()
                # print(tmp)
                try:
                    tmp_proto = tmp[0]
                    tmp_host = tmp[1]
                    tmp_period = tmp[2]
                except:
                    # print(tmp)# exit(1)
                    return ('unknown', 'unknown')
                
                if tmp_host == '#' or tmp_host  == ' ':
                    tmp_host = ''

                periodic_tuple.append((tmp_host, tmp_proto, tmp_period))
                host_set.add(tmp_host)

        return (periodic_tuple, host_set)
        
    return ('unknown', 'unknown')



# # todo: update function; remove [i]
# @lru_cache(maxsize=128)
# def protocol_transform(test_protocols):
#     # for i in range(len(test_protocols)):
#     if 'TCP' in test_protocols:
#         test_protocols = 'TCP'
#     elif 'MQTT' in test_protocols:
#         test_protocols = 'TCP'
#     elif 'UDP' in test_protocols:
#         test_protocols = 'UDP'
#     elif 'TLS' in test_protocols:
#         test_protocols = 'TCP'
#     if ';' in test_protocols:
#         tmp = test_protocols.split(';')
#         test_protocols = ' & '.join(tmp)
#     return test_protocols

# ====================================
# TODO: IMPLEMENT THE ENTIRE FUNCTION 
# ====================================

def periodic_filter_burst_helper(burst):
    # get device name from MAC address
    device_name = get_product_name_by_mac(burst[-6])

    # Get periods from fingerprinting files
    periodic_tuple, host_set = get_periods(device_name) 

    if periodic_tuple == 'unknown':
        common.event_log('[Burst Periodic-filter] Failed loading periodic events: ' + ' for device: ' + str(device_name) + " " + str(burst))
        return


    # test_data = burst
    test_feature = burst[:-6]
    # test_data_numpy = np.array(burst)
    test_feature = np.array(test_feature, dtype=float)
    test_protocols = burst[-2]
    test_hosts = burst[-1]
    test_protocols = protocol_transform(test_protocols)

    # common.event_log('[Burst Periodic-filter] Filtering burst for : ' + str(device_name) + " " + test_hosts + " " + test_protocols)   

    # process host
    if test_hosts!= '' and test_hosts!= None:
        try:
            tmp = test_hosts.split(';')
        except:
            # print(test_hosts) #exit(1)
            return
        test_hosts= tmp[0]

    if test_hosts == None:
        test_hosts== 'non'
    test_hosts = test_hosts.lower()   
    test_hosts = test_hosts.replace('?','')   


    # Filter local and DNS/NTP. 
    if test_protocols == 'DNS' or test_protocols == 'MDNS' or test_protocols == 'NTP' or test_protocols == 'SSDP' or test_protocols == 'DHCP':
        return 
    # else: filter_dns.append(True)


    # Filter local
    # todo update local mac list 
    local_mac_list = ['ff:ff:ff:ff:ff:ff', '192.168.1.1']
    mac_dic = get_mac_address_list()

    if test_hosts in mac_dic or test_hosts in local_mac_list or test_hosts=='multicast' or ':' in test_hosts:
        return

    # """
    # For each tuple: 
    # """

    aperiodic_event = True

    for tup in periodic_tuple:
        tmp_host = tup[0]
        tmp_proto = tup[1]
        if tmp_host == '':
            continue

        # todo: remove this hardcosing checking
        if tmp_host == 'n-devs.tplinkcloud.com':
            tmp_host_model = 'devs.tplinkcloud.com'
        else:
            tmp_host_model = tmp_host

        # common.event_log('[Burst Periodic-filter] Loading Model for ' + device_name + ' : ' + test_hosts + ' ' + test_protocols + ' ' + tmp_host + ' ' + tmp_proto)
        # check if filtering needed
        # todo: we can make this faster by using dictionary for periodic_tuple
        if tmp_host.startswith('*'):
            matched_suffix = test_hosts.endswith(tmp_host[2:])
        else:
            matched_suffix = False

        if (test_hosts == tmp_host or matched_suffix) and test_protocols == tmp_proto:
            filter_test = True  
        else:
            filter_test = False

        if filter_test == False:
            if (test_hosts.endswith('.'.join(tmp_host.split('.')[-3:]))) and test_protocols == tmp_proto:
                filter_test = True    

        # if filtering not needed
        if filter_test == False:
            continue

        # Note: update momel names perodically
        dname = device_name_mapping(device_name)

        model_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '..', 'models', 'filter_apr20', 'filter', dname + tmp_host_model + tmp_proto + '.model'
        )

        # common.event_log('[Burst Periodic-filter] Condition matched ' + test_hosts + ' ' + test_protocols + ' ' + tmp_host + ' ' + tmp_proto)
        """
        Load trained models
        """
        try:
            model = pickle.load(open(model_file, 'rb'))['trained_model']
        except Exception as e: 
            common.event_log('[Burst Periodic-filter] Model loading error: ' + str(e))
            continue
        
        try:
            y_new = dbscan_predict(model, test_feature)
            # common.event_log('[Burst Periodic-filter] DB_Scan Success ' + str (y_new))
        except Exception as e:
            common.event_log('[Burst Periodic-filter] DB_Scan Failed ' + str (e))


        # Do we want to filter it out? 
        if y_new >= 0:
            # periodic event 
            aperiodic_event = False
            break
    
    if aperiodic_event:
        store_processed_burst_in_db(burst)
        common.event_log('[Burst Periodic-filter] non-periodic event found ' + device_name + ' : ' + test_hosts + ' ' + test_protocols)

    return 


def dbscan_predict(dbscan_model, x_new, metric=sp.spatial.distance.euclidean):
    y_new = -1 
    # Find a core sample closer than EPS
    for i, x_core in enumerate(dbscan_model.components_):
        # print(metric(x_new, x_core))
        # common.event_log('[Burst Periodic-filter] DB_Scan: \n Feature = ' + str (x_new) + "\n Core = " + str(x_core))
        if metric(x_new, x_core) < (dbscan_model.eps): 
            # Assign label of x_core to x_new
            y_new = dbscan_model.labels_[dbscan_model.core_sample_indices_[i]]
            break

    return y_new


# store standardized processed burst features (data) into database
# input: a data point
# output: None
def store_processed_burst_in_db(data):
    # Note: for now storing in a queue, later store in database
    # make to lock safe
    """
    Adds a data to the data queue.
    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.filtered_burst_queue.put(data)

