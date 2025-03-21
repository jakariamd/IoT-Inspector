"""
===============================================================================
Title: Burst Processor (Pre-Processor)
Author: Md Jakaria
Date: Jan 2025
Description: This module processes bursts to standardize feature.
 This is basically done in s4. 
Reference: This code was inspired by and adapted from the work of Tianrui Hue 
on https://github.com/NEU-SNS/BehavIoT/tree/main.
===============================================================================
"""

import core.global_state as global_state
import core.common as common
import traceback
from functools import lru_cache
import core.model as model
import time
import os
import pickle
import pandas as pd
import numpy as np

from core.model_selection import find_best_match


# define the expected features of a burst 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
            "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]


def process_burst():

    burst = global_state.burst_queue.get()

    try:
        process_burst_helper(burst)

    except Exception as e:
        common.log('[Burst Pre-Processor] Error processing burst: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())



# Define a cache with TTL support
def ttl_lru_cache(ttl_seconds, maxsize=128):
    def decorator(func):
        cache = lru_cache(maxsize=maxsize)(func)  # Create an LRU cache for the function
        cache_times = {}  # Dictionary to store cache times

        def wrapper(*args, **kwargs):
            # Check if the cache is valid based on TTL
            current_time = time.time()
            if args in cache_times and current_time - cache_times[args] > ttl_seconds:
                # Cache has expired; clear it and re-execute
                cache.cache_clear()
                cache_times[args] = current_time  # Update the cache timestamp
            elif args not in cache_times:
                cache_times[args] = current_time  # First time access
            
            return cache(*args, **kwargs)

        return wrapper
    return decorator


# """
# Fetches the product name of a device using its MAC address.
# Args:
#     mac_address (str): The MAC address of the device.
# Returns:
#     str: The product name of the device or 'Unknown Device' if not found.
# """

# Note: make the function efficient so that it cleans the cache periodically, like 10 mins 
@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_product_name_by_mac(mac_address):

    with model.db:
        # Query the database for the device with the specified MAC address
        device = model.Device.select(model.Device.product_name).where(
            model.Device.mac_addr == mac_address
        ).first()

        # Return the product name if the device exists, otherwise return a default value
        return device.product_name if device and device.product_name else 'Unknown Device'



# Fetches the ss and pca model from MAC address.
# Args:
#     mac_address (str): The MAC address of the device.
# Returns:
#     pickle model file 
# todo: write a function to map the device name to model file name 
# todo: update every 10 mins, or clean memory every 10 mis 
@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_ss_pca_model(device_name):
    # device_name = get_product_name_by_mac(mac_address)
    if device_name == 'Unknown Device':
        return "Model Unknown"

    # device_name = device_name_mapping(device_name)
    # Jakaria: removed hard coding
    _, model_name = find_best_match(device_name)
    print('[Burst Pre-Processor] device: ' + str(device_name) + ' model: ' + str(model_name))

    if model_name == 'unknown model_name':
        common.event_log('[Burst Processor] Model not found: ' + str(device_name))
        return "Model Unknown"

    # Load ss and pca file
    model_dir = os.path.join(
        common.get_project_directory(), 'models', 'SS_PCA', model_name + '.pkl'
        )
    
    # common.event_log('[Burst Pre-Processor] model file location: ' + str(model_dir))

    if os.path.exists(model_dir):
        with open(model_dir, 'rb') as file:
            return pickle.load(file)
        return "Model Unknown"
        
    return "Model Unknown"


# pre-process burst file with pre-trained SS and PCA model 
# Note: we are using latest model of sk_learn, but the models are traied on 1.3.0 version 
# mismatch of version, might lead to breaking code or invalid results. 
# todo: train ss/pca models with latest version of numpy, sklean 

def process_burst_helper(burst):
    # common.log('[Burst Pre-Processor] Before processing burst: ' + str(burst))

    # get device name from MAC address
    device_name = get_product_name_by_mac(burst[-6])

    # load data to a dataframe 
    X_feature = pd.DataFrame([burst], columns=cols_feat)
    X_feature = X_feature.drop(['device', 'state', 'event' ,'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)
    X_feature = np.array(X_feature)

    ss_pca_model = get_ss_pca_model(device_name)

    if ss_pca_model == "Model Unknown":
        common.event_log('[Burst Pre-Processor] Process unsuccessful: ' + str(device_name) + ' SS PCA not exist')
        return
    
    try:
        ss = ss_pca_model['ss']
        X_feature = ss.transform(X_feature)
    except Exception as e:
        common.log('[Burst Pre-Processor] Process failed, device name: ' + str(device_name) + " " + str(e))

    X_feature = np.append(X_feature, burst[-6:])

    # todo: send processed data to next step 
    common.log('[Burst Pre-Processor] Burst stored for: ' + str(device_name) + ' ' + burst[-1] + ' ' + burst[-2])

    store_processed_burst_in_db(X_feature)
    
    return 

# store standardized processed burst features (data) into database
# input: a data point, output: None
# TODO: incorporate idle device in the burst
# idea: create a different queue for idle device, and process them separately
def store_processed_burst_in_db(data):
    # Note: for now storing in a queue, later store in database
    # make to lock safe
    """
    Adds a data to the data queue.
    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return
    
    global_state.ss_burst_queue.put(data)
        

