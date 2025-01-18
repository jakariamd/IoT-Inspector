"""
===============================================================================
Title: Periodicity Inference
Author: Md Jakaria
Date: Jan 2025
Description: This module infers periodicity in network traffic.
Reference: This code was inspired by and adapted from the work of Tianrui Hue 
           on https://github.com/NEU-SNS/BehavIoT/tree/main.
===============================================================================
"""

import core.global_state as global_state
import core.common as common
import traceback
from utils import device_name_mapping, protocol_transform, host_transform

# define the expected features of a burst of an idle event 
# we expect a idle burst coming from the burst processor thread for 
# a device that is set idle by user
# TODO: update the @burst_processor.py to include the idle device 

cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", 
            "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]

# considering we have the feature for idle device 

def periodic_inference_burst():
    # TODO: get idle burst from idle burst queue
    burst = global_state.ss_burst_queue.get()

    try:
        periodic_inference_helper(burst)

    except Exception as e:
        common.log('[Periodic Inference] Error processing burst: ' + str(e) + \
                   ' for burst: ' + str(burst) + '\n' + traceback.format_exc())


def periodic_inference_helper(burst):
    """
    Helper function to infer periodicity in network traffic.
    Args:
        burst: A burst of network traffic.
    """
    # preprocessing, optional
    preprocessing = 1
    if preprocessing:
        protocol = protocol_transform(burst[-2])
        domain = host_transform(burst[-1])
        
        # for i in range(len(hosts)):
        #     if hosts[i] != '' and hosts[i] != None:
        #         tmp = hosts[i].split(';')
        #         hosts[i] = tmp[0]
        #     if hosts[i] == None:
        #         hosts[i] == 'non'
        #     hosts[i] = hosts[i].lower()
        #         # print(hosts[i])
        # domain_set = set(hosts)
        # print(domain_set)




