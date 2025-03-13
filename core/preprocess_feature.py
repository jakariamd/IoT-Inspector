'''
Title: Preprocess Feature
Author: Md Jakaria
Date: Feb 2025
Description: This module preprocesses the feature of idle device. 
Features are standardized and normalized.
Reference: This code was inspired by and adapted from the work of Tianrui Hue
on https://github.com/NEU-SNS/BehavIoT/tree/main.
'''

import os
import pandas as pd
import core.common as common
import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle

# define the path to save the model
model_path = os.path.join(common.get_project_directory(), 'models', 'SS_PCA')
data_path = os.path.join(common.get_project_directory(), 'idle-data-std')

# define the expected features of a burst
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
                "skewLength", "kurtosisLength", "meanTBP", "varTBP",
                "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
                "network_in", "network_out", "network_external", "network_local",
                "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
                "meanBytes_out_local", "meanBytes_in_local",
                "device", "state", "event", "start_time", "protocol", "hosts"]

def preprocess_feature(device_mac_addr):
    # Preprocess the feature of idle device
    # get the idle data 
    idle_file_path = os.path.join(common.get_project_directory(),
                                       'idle-data', device_mac_addr + '.csv')
    
    # Check if the idle file exists
    if not os.path.exists(idle_file_path):
        common.log(f'[Pre-process Feature] Idle file not found for device: {device_mac_addr}')
        return

    # Read the idle data from the CSV file
    try:
        idle_data = pd.read_csv(idle_file_path)
        common.log(f'[Pre-process Feature] Successfully read idle data for device: {device_mac_addr}')
    except Exception as e:
        common.log(f'[Pre-process Feature] Error reading idle data for device: {device_mac_addr}: {str(e)}')
        return
    
    # # Split the data into training and testing data
    # split_time = np.max(idle_data['start_time']) - (
    #         np.max(idle_data['start_time']) - np.min(idle_data['start_time'])) / 5
    
    # train_idle_data = idle_data.loc[(idle_data['start_time'] < split_time)]  # 80% of the data
    # test_idle_data = idle_data.loc[(idle_data['start_time'] >= split_time)]

    # Split the data into training and testing data based on number of rows 80-20%
    # in original code, the split is based on time
    split_index = int(len(idle_data) * 0.8)
    
    train_idle_data = idle_data.iloc[:split_index]  # 80% of the data
    test_idle_data = idle_data.iloc[split_index:]  # 20% of the data

    if len(train_idle_data) == 0 or len(test_idle_data) == 0:
        print('Not enough idle data points for: ', device_mac_addr, len(train_idle_data), len(test_idle_data))
        return

    # Drop the unnecessary columns
    train_idle_feature = train_idle_data.drop(
        ['device', 'state', 'event', 'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)
    test_idle_feature = test_idle_data.drop(
        ['device', 'state', 'event', 'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)


    print('train test idle: ', device_mac_addr, len(train_idle_data), len(test_idle_data))
    
    # Convert the data to numpy array
    X_feature = np.array(train_idle_feature)

    # Standardize the feature
    ss = StandardScaler()
    train_idle_std = ss.fit_transform(X_feature)
    test_idle_std = ss.transform(test_idle_feature)


    # Save ss and pca
    saved_dictionary = dict({'ss': ss})  # ,'pca':pca
    if not os.path.exists(model_path):
        os.makedirs(model_path)
        print('Creating model directory: ', model_path)
    pickle.dump(saved_dictionary, open("%s/%s.pkl" % (model_path, device_mac_addr), "wb"))

    # Save the standardized data
    X_idle_std = pd.DataFrame(train_idle_std, columns=cols_feat[:-6])
    X_idle_std['device'] = np.array(train_idle_data.device)
    X_idle_std['state'] = np.array(train_idle_data.state)
    X_idle_std['event'] = np.array(train_idle_data.event)
    X_idle_std['start_time'] = np.array(train_idle_data.start_time)
    X_idle_std['protocol'] = np.array(train_idle_data.protocol)
    X_idle_std['hosts'] = np.array(train_idle_data.hosts)

    test_idle_std = pd.DataFrame(test_idle_std, columns=cols_feat[:-6])
    test_idle_std['device'] = np.array(test_idle_data.device)
    test_idle_std['state'] = np.array(test_idle_data.state)
    test_idle_std['event'] = np.array(test_idle_data.event)
    test_idle_std['start_time'] = np.array(test_idle_data.start_time)
    test_idle_std['protocol'] = np.array(test_idle_data.protocol)
    test_idle_std['hosts'] = np.array(test_idle_data.hosts)

    # Save the standardized data
    train_idle_std_file = os.path.join(data_path, device_mac_addr + '_train.csv')
    test_idle_std_file = os.path.join(data_path, device_mac_addr + '_test.csv')
    if not os.path.exists(data_path):
        os.makedirs(data_path)
        print('Creating data directory: ', data_path)
    
    X_idle_std.to_csv(train_idle_std_file, index=False)
    test_idle_std.to_csv(test_idle_std_file, index=False)
