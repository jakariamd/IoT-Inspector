'''
Predict labels for new samples using a trained DBSCAN model.
'''

import pickle
import scipy as sp
import numpy as np
import os
import pandas as pd
from sklearn.cluster import DBSCAN
from core import utils
from core.burst_processor import get_product_name_by_mac
from sklearn.preprocessing import StandardScaler
import sys
import core.common as common

input_file_path = os.path.join(common.get_project_directory(), 'idle-data-std')

model_dir = os.path.join(
    common.get_project_directory(),
    'models',
    'filter_apr20',
    'filter'
    )

fingerprint_file_dir = os.path.join(
    common.get_project_directory(),
    'models',
    'freq_period',
    'fingerprints'
)


def dbscan_predict(dbscan_model, X_new, metric=sp.spatial.distance.euclidean):
    # Result is noise by default  euclidean_distances
    y_new = np.ones(shape=len(X_new), dtype=int)*-1 

    # Iterate all input samples for a label
    for j, x_new in enumerate(X_new):
        # Find a core sample closer than EPS
        for i, x_core in enumerate(dbscan_model.components_):

            if metric(x_new, x_core) < (dbscan_model.eps): # np.reshape(x_new, (1,-1)), np.reshape(x_core,(1,-1))
                # Assign label of x_core to x_new
                y_new[j] = dbscan_model.labels_[dbscan_model.core_sample_indices_[i]]
                break

    return y_new

def train_periodic_models(device_mac_addr):
    """
    Train periodic models for a device using idle data.
    """
    

    dname = get_product_name_by_mac(device_mac_addr).lower().replace(' ', '-')

    print('Training %s ' % (dname))
    # train_data = pd.read_csv(train_data_file)
    # Load idle data for the device
    train_data = pd.read_csv(os.path.join(input_file_path, f'{device_mac_addr}_train.csv'))
    
    if train_data.empty:
        print(f'[Train Periodic Models] No idle data found for: {dname}')
        return

    num_data_points = len(train_data)
    if num_data_points < 10:
        print('  Not enough data points for %s' % dname)
        # return
    print('\t#Total data points: %d ' % num_data_points)

    """
    Get periods from fingerprinting files
    """
    periodic_tuple = []
    tmp_host_set = set()
    try:
        fingerprint_file = os.path.join(fingerprint_file_dir, f'{dname}.txt')
        with open(fingerprint_file, 'r') as file:
            for line in file:
                tmp = line.split()
                try:
                    tmp_proto = tmp[0]
                    tmp_host = tmp[1]
                    tmp_period = tmp[2]
                except:
                    print(tmp)
                    exit(1)
                if tmp_host == '#' or tmp_host  == ' ':
                    tmp_host = ''

                periodic_tuple.append((tmp_host, tmp_proto, tmp_period))
                tmp_host_set.add((tmp_host,tmp_proto))

    except:
        print( '[Periodic Filter Training] unable to read fingerprint file: ', fingerprint_file)
        return
    print(dname, periodic_tuple)
    
    """
    Preprocess training data
    """

    X_feature = train_data.drop(['device', 'state', 'event','start_time', 'protocol', 'hosts'], axis=1).fillna(-1)

    protocols = train_data['protocol'].fillna('').values
    hosts = train_data['hosts'].fillna('').values
    # protocols = utils.protocol_transform_list(protocols)
    
    for i in range(len(hosts)):
        if hosts[i] != '' and hosts[i] != None:
            try:
                tmp = hosts[i].split(';')
            except:
                print(hosts[i])
                exit(1)
            hosts[i] = tmp[0]
        if hosts[i] == None:
            hosts[i] == 'non'
        hosts[i] = hosts[i].lower().replace('?','')   # remove '?'
            # print(hosts[i])

    # y_labels = np.array(train_data.state)
    X_feature = np.array(X_feature)
    print('X_feature.shape:',X_feature.shape)
    


    """
    Load and preprocess testing data
    """
    test_data_file = os.path.join(input_file_path, f'{device_mac_addr}_test.csv')

    test_data = pd.read_csv(test_data_file)
    test_feature = test_data.drop(['device', 'state', 'event', 'start_time', 'protocol', 'hosts'], axis=1).fillna(-1)
    test_data_numpy = np.array(test_data)
    test_feature = np.array(test_feature)
    test_protocols = test_data['protocol'].fillna('').values
    test_hosts = test_data['hosts'].fillna('').values
    # test_protocols = utils.protocol_transform(test_protocols)

    
    for i in range(len(test_hosts)):
        if test_hosts[i] != '' and test_hosts[i] != None:
            try:
                tmp = test_hosts[i].split(';')
            except:
                print(test_hosts[i])
                exit(1)
            test_hosts[i] = tmp[0]
        if test_hosts[i] == None:
            test_hosts[i] == 'non'
        test_hosts[i] = test_hosts[i].lower().replace('?','')   # remove '?'

    events = test_data['event'].fillna('').values
    len_test_before = len(test_feature)
    num_of_event = len(set(events))
    y_labels_test = test_data['state'].fillna('').values

    """
    # filter out local and DNS/NTP packets
    """
    print('\ttesting data len: ', len_test_before)
    filter_dns = []
    for i in range(len(test_feature)):
        if (test_hosts[i] == 'multicast' or test_protocols[i] == 'DNS' or test_protocols[i] == 'MDNS' 
            or test_protocols[i] == 'NTP' or test_protocols[i] == 'SSDP' or test_protocols[i] == 'DHCP'):
            filter_dns.append(False)
        else:
            filter_dns.append(True)
    test_feature = test_feature[filter_dns]
    test_hosts = test_hosts[filter_dns]
    test_protocols = test_protocols[filter_dns]
    events = events[filter_dns]
    y_labels_test = y_labels_test[filter_dns]
    test_data_numpy = test_data_numpy[filter_dns]

    print('\ttesting data after DNS/NTP etc filter: ', len(test_feature))
    
    ret_results = []
    res_left = 0
    res_filtered = 0
    ## For each tuple: 
    for tup in periodic_tuple:
        tmp_host = tup[0]
        tmp_proto = tup[1]

        print('------%s------' %dname)
        print(tmp_proto, tmp_host)
        

        filter_l = []
        for i in range(len(X_feature)):
            if tmp_host.startswith('*'):
                matched_suffix = hosts[i].endswith(tmp_host[2:])
            else:
                matched_suffix = False
            if (hosts[i] == tmp_host or matched_suffix) and protocols[i] == tmp_proto:
                filter_l.append(True)
            else:
                filter_l.append(False)
        X_feature_part = X_feature[filter_l]
        print('\ttrain feature part:',len(X_feature_part))
        x_zero_feature_flag = 0
        if len(X_feature_part) == 0:
            x_zero_feature_flag = 1
        if len(X_feature_part) > 5000:
            X_feature_part = X_feature_part[:5000]


        """
        ML algorithms
        """

        if not os.path.exists(model_dir):
            # os.system('mkdir -pv %s' % model_dir)
            os.makedirs(model_dir, exist_ok=True)
        # model_file = os.path.join(model_dir, dname + tmp_host + tmp_proto +".model")
        # todo Jakaria edited the above line
        model_file = os.path.join(model_dir,
                                  dname.replace('*', '') +
                                  tmp_host.replace(':', '-') +
                                  tmp_proto +".model")

        """
        Two steps
            1. Train 
            2. Test 
            3. Evaluate 
        """
        X_feature_part = pd.DataFrame(X_feature_part)
        if len(X_feature_part) == 0:
            print('\t Not enough training data for %s' % tmp_host)
            continue
        print("\t predicting by trained_model")
        print('\t Test len before:',len(test_feature))
        filter_test = []
        matched_suffix = False
        for i in range(len(test_feature)):
            
            if tmp_host.startswith('*'):
                matched_suffix = test_hosts[i].endswith(tmp_host[2:])
                if matched_suffix==False and tmp_host=='*.compute.amazonaws.com':
                    if test_hosts[i].endswith('.compute-1.amazonaws.com'):
                        matched_suffix =True
            else:
                matched_suffix = False
            if (test_hosts[i] == tmp_host or matched_suffix) and test_protocols[i] == tmp_proto:
                filter_test.append(True)    # for current (host + protocol)
            else:
                filter_test.append(False)
        test_feature_part = test_feature[filter_test]

        if len(test_feature_part) == 0:
            filter_test = []
            for i in range(len(test_feature)):
                if (test_hosts[i].endswith('.'.join(tmp_host.split('.')[-3:]))) and test_protocols[i] == tmp_proto:
                    filter_test.append(True)    # for current (host + protocol)
                else:
                    filter_test.append(False)

        events_part = events[filter_test]
        y_labels_test_part = y_labels_test[filter_test]
        ## todo DBSCAN todo Jakaria hard coding
        ## eps obtained from validation sets
        eps = utils.get_eps_by_device(dname)

        model = DBSCAN(eps=eps,min_samples=5)
        if x_zero_feature_flag == 0:
            y_train = model.fit_predict(X_feature_part)
        else: 
            y_train = model.fit_predict(test_feature_part)

        
        if len(test_feature_part) == 0:
            print('test feature matched host/proto == 0') 
            model_dictionary = dict({'trained_model':model})
            # pickle.dump(model_dictionary, open(model_file, 'wb'))
            # todo Jakaria edited the above line
            pickle.dump(model_dictionary,
                        open(model_file.replace('*','').replace(':', '-'), 'wb')
                        )
            model = 0
            continue
        print(test_feature_part.shape)


        y_new = dbscan_predict(model,test_feature_part)

        count_left = 0
        event_after = set()
        events_tmp = set()
        state_after = set()
        filter_list = []

        print('Training set average prediction: ',len(y_train), np.mean(y_train),np.var(y_train), np.mean(y_train) - 2 * np.var(y_train), np.count_nonzero(y_train==-1)) # np.count_nonzero(y_train==-1))#)
        print('testing set average prediction: ',len(y_new), np.mean(y_new), np.var(y_new), np.mean(y_new) - 2 * np.var(y_new), np.count_nonzero(y_train==-1) ) #np.count_nonzero(y_new==-1))

        for i in range(len(y_new)):
            if y_new[i] < 0: 
                event_after.add(events_part[i])
                state_after.add(y_labels_test_part[i])
                count_left += 1
                filter_list.append(True)

            else:
                filter_list.append(False)   # periodic traffic
        # activity_feature = test_feature_part[filter_list]
        if len(filter_list) != len(y_new):
            exit(1)
        count_tmp = 0
        for i in range(len(filter_test)):
            if filter_test[i] == False:
                filter_test[i] = True

            elif filter_test[i] == True: # true, (proto, host)
                if filter_list[count_tmp] == False: # filter
                    filter_test[i] = False
                count_tmp += 1
            else:
                exit(1)
        
        if len(filter_test) != len(test_feature):
            exit(1)


        test_feature = test_feature[filter_test]
        test_hosts = test_hosts[filter_test]
        test_protocols = test_protocols[filter_test]
        events = events[filter_test]
        y_labels_test = y_labels_test[filter_test]
        test_data_numpy = test_data_numpy[filter_test]
        
        res_left += count_left
        res_filtered += test_feature_part.shape[0] - count_left
        print("count_left" , count_left, test_feature_part.shape[0] , count_left/test_feature_part.shape[0])
        print('Test len after:',len(test_feature))
        print('-------------')

        """
        Save the model / logs
        """
        model_dictionary = dict({'trained_model':model})
        # pickle.dump(model_dictionary, open(model_file, 'wb'))
        # todo Jakaria edited the above line
        pickle.dump(model_dictionary,
                    open(model_file.replace('*','').replace(':', '-'), 'wb')
                    )
        model = 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python periodic_filter_training.py <device_mac_addr>")
        sys.exit(1)
    
    device_mac_addr = sys.argv[1]
    train_periodic_models(device_mac_addr)

