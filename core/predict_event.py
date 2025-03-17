'''
================================================================================
Title: Predict Event
Author: Md Jakaria
Date: Jan 2025
Description: This module predicts events from preprocessed and filtered bursts.
Reference: This code was inspired by and adapted from the work of Tianrui Hue
on https://github.com/NEU-SNS/BehavIoT/tree/main.
================================================================================
'''

import core.global_state as global_state
import core.common as common
from core.burst_processor import get_product_name_by_mac
from core.burst_processor import ttl_lru_cache
import traceback
import os
import pickle
import numpy as np
from core.model_selection import find_best_match

from core.utils import protocol_transform



# define the expected features of a burst 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
            "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]


def predict_event():

    burst = global_state.filtered_burst_queue.get()

    try:
        predict_event_helper(burst)

    except Exception as e:
        common.event_log('[Predict-Event] Error: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())



def predict_event_helper(burst):
    dname = get_product_name_by_mac(burst[-6])


    X_test = burst[:-6]
    # test_data = pd.DataFrame([burst], columns=cols_feat)
    # X_test = test_data.drop(['device', 'state', 'event', 'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)
    # test_data_numpy = np.array(X_test)
    test_hosts = burst[-1]
    test_protocol = burst[-2]
    test_timestamp = burst[-3]
    test_protocol = protocol_transform(test_protocol)

    # # Jakaria: removed hard coding 
    # if test_hosts == 'n-devs.tplinkcloud.com':
    #     test_hosts = 'devs.tplinkcloud.com'

    # Jakaria: mapping not needed
    # dname = device_name_mapping(dname) 
    
    # Jakaria: removed hard-coding
    # if dname=='echodot4b':
    #     dname = 'echospot'
    """
    Predict
    """

    positive_label_set, list_models = get_list_of_models(dname)

    print('[Predict-Event] device: ' + str(dname) + ' positive_label_set: ' + str(positive_label_set))

    if positive_label_set == '' or len(positive_label_set) == 0:
        print('[Predict-Event] unknown event detected: ' + str(dname))
        
        return
    
    # comment if not running 
    X_test = np.array([X_test], dtype=float)
    predictions = []
    try:
        for trained_model in list_models:
            y_predicted = trained_model.predict(X_test) 
            y_proba = trained_model.predict_proba(X_test)
            predictions.append(y_predicted[0])
            common.event_log('[Predict-Event] predicting: ' + ' for device : ' + str(dname) + ' y_predicted: ' + str(y_predicted) + ' y_proba: ' + str(y_proba) + ' events: ' + str(positive_label_set))
    except Exception as e:
            common.event_log('[Predict-Event] predict error: ' + ' for device : ' + str(dname) + ' error: ' + str(e))
    # positive_label_set = list(positive_label_set)


    try: 
        event = str(list(positive_label_set)[predictions.index(1)])
        common.event_log('[Predict-Event] Success: ' + ' for device : ' + str(dname) + ' event: ' + event )
        store_events_in_db(burst[-6], burst[-3], event)
    except:
        common.event_log('[Predict-Event] Success: ' + ' for device : ' + str(dname) + ' event: periodic/unexpected event')
    return




# Fetches the event models model from MAC address.
# Args:
#     mac_address (str): The MAC address of the device.
# Returns:
#     pickle model file 
# todo: write a function to map the device name to model file name 
# todo: update every 10 mins, or clean memory every 10 mis 
@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_list_of_models(device_name):
    # device_name = get_product_name_by_mac(mac_address)

    positive_label_set = []
    list_models = []

    if device_name == 'unknown':
        common.event_log('[Predict Event] device not found: ' + str(device_name))
        return ('', '')
    
    _, model_name = find_best_match(device_name)
    if model_name == 'unknown model_name':
        common.event_log('[Predict Event] device not found: ' + str(device_name))
        return ('', '')
    print('[Predict Event] device: ' + str(device_name) + ' model: ' + str(model_name))
    
    # Load event models
    model_dir = os.path.join(
        common.get_project_directory(), 'models', 'binary', 'rf', model_name
        )
    
    if not os.path.exists(model_dir):
        common.event_log('[Predict Event] event model not found: ' + str(model_dir))
        return ('', '')
    
    for f1 in os.listdir(model_dir):
        # positive_label_set.append('_'.join(f1.split('_')[1:-1]))
        positive_label_set.append('_'.join(f1.split('.')[0].split('_')[1:]))

        list_models.append(pickle.load(open(os.path.join(model_dir, f1), 'rb')))
    
    positive_label_set = set(positive_label_set)

    return (positive_label_set, list_models)



def store_events_in_db(device, time, event):
    # Note: for now storing in a queue, later store in database
    # make to lock safe
    """
    Adds a data to the data queue.
    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.filtered_event_queue.setdefault(device, []).append((time, event))

