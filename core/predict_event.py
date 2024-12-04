import core.global_state as global_state
import core.common as common
from core.burst_processor import get_product_name_by_mac
from core.burst_processor import ttl_lru_cache
from functools import lru_cache
import traceback
from functools import lru_cache
import core.model as model
import time
import os
import pickle
import pandas as pd
import numpy as np



# define the expected features of a burst 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
            "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]


def predict_event():

    burst = global_state.ss_burst_queue.get()

    try:
        predict_event_helper(burst)

    except Exception as e:
        common.event_log('[Predict-Event] Error: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())


# cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
            #  "skewLength", "kurtosisLength", "meanTBP", "varTBP",
            #  "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
            #  "network_in", "network_out", "network_external", "network_local",
            # "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
            # "meanBytes_out_local", "meanBytes_in_local",
            # "device", "state", "event", "start_time", "protocol", "hosts"]
def predict_event_helper(burst):
    dname = get_product_name_by_mac(burst[-6])


    X_test = burst[:-6]
    # test_data = pd.DataFrame([burst], columns=cols_feat)
    # X_test = test_data.drop(['device', 'state', 'event', 'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)
    test_data_numpy = np.array(X_test)
    test_hosts = burst[-1]
    test_protocol = burst[-2]
    test_timestamp = burst[-3]
    test_protocol = protocol_transform(test_protocol)

    # if dname.startswith('tplink'):
    #     for i in range(len(test_hosts)):
    #         if test_hosts[i] == 'n-devs.tplinkcloud.com':
    #             test_hosts[i] = 'devs.tplinkcloud.com'


    """
    Predict
    """

    positive_label_set, list_models = get_list_of_models(burst[-6])

    if positive_label_set == '':
        return
    
    # comment if not running 
    # X_test = np.array([X_test])

    # for trained_model in list_models:
    #     y_predicted = trained_model.predict(X_test) 
    #     y_proba = trained_model.predict_proba(X_test)
    #     common.event_log('[Predict-Event] predicting: ' + ' for device : ' + str(dname) + ' event: ' + str(y_predicted) + ' event: ' + str(y_proba) )
    positive_label_set = list(positive_label_set)

    if 'Plug' in dname:
        positive_label_set = ['-'.join(reversed(positive_label_set))]
        
    common.event_log('[Predict-Event] Success: ' + ' for device : ' + str(dname) + ' event: ' + str(positive_label_set[-1]))
    return




# Fetches the event models model from MAC address.
# Args:
#     mac_address (str): The MAC address of the device.
# Returns:
#     pickle model file 
# todo: write a function to map the device name to model file name 
# todo: update every 10 mins, or clean memory every 10 mis 
@ttl_lru_cache(ttl_seconds=300, maxsize=128)
def get_list_of_models(mac_address):
    device_name = get_product_name_by_mac(mac_address)

    positive_label_set = []
    list_models = []

    if device_name == 'Unknown Device':
        common.event_log('[Predict Event] device not found: ' + str(device_name))
        return ('', '')
    
    
    # todo: write a function to map the device name to model file name 
    if device_name == 'Amazon Plug':
        device_name = 'amazon-plug'
    elif device_name == 'Amazon Echo':
        device_name = 'echospot'
    elif device_name == 'Ring Camera':
        device_name = 'ring-camera'

    # Load event models
    model_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '..', 'models', 'binary', 'rf', device_name
        )
    
    if not os.path.exists(model_dir):
        common.event_log('[Predict Event] event model not found: ' + str(model_dir))
        return ('', '')
    
    for f1 in os.listdir(model_dir):
        positive_label_set.append('_'.join(f1.split('_')[1:-1]))

        list_models.append(pickle.load(open(os.path.join(model_dir, f1), 'rb')))
    
    positive_label_set = set(positive_label_set)

    return (positive_label_set, list_models)



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
