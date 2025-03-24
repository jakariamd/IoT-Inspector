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
import collections
import os
import pandas as pd
import numpy as np
import core.common as common
import traceback
# import matplotlib.pyplot as plt
from scipy.fft import fft, ifft, fftfreq
from statsmodels import api as sm
import re
from core.burst_processor import get_product_name_by_mac
# import core.global_state as global_state
# from core.utils import device_name_mapping, protocol_transform, host_transform


# define the expected features of a burst of an idle event 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", 
            "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]


# output the periodicity inference result to the periodicity-inference folder
file_path = os.path.join(common.get_project_directory(), 'models', 'freq_period', '1s')

# output directory for the fingerprint generation
out_dir = os.path.join(common.get_project_directory(), 'models', 'freq_period', 'fingerprints')
non_dir = os.path.join(common.get_project_directory(), 'models', 'freq_period', 'nonperiod')

def periodic_inference(device_mac_addr):
    # get the idle data 
    idle_file_path = os.path.join(common.get_project_directory(),
                                       'idle-data', device_mac_addr + '.csv')
    
    # Check if the idle file exists
    if not os.path.exists(idle_file_path):
        common.log(f'[Periodic Inference] Idle file not found for device: {device_mac_addr}')
        return

    # Read the idle data from the CSV file
    try:
        idle_data = pd.read_csv(idle_file_path)
        common.log(f'[Periodic Inference] Successfully read idle data for device: {device_mac_addr}')
    except Exception as e:
        common.log(f'[Periodic Inference] Error reading idle data for device: {device_mac_addr}: {str(e)}')
        return
    
    # Call the helper function to infer periodicity in network traffic
    common.log(f'[Periodic Inference] Inferring periodicity for device: {device_mac_addr}')
    periodic_inference_helper(device_mac_addr, idle_data)
    common.log(f'[Periodic Inference] Done inferring periodicity for device: {device_mac_addr}')

    # Call finger_print generation function to generate the fingerprint
    common.log(f'[Fingerprint Generation] Generating fingerprint for device: {device_mac_addr}')
    fingerprint_generation(device_mac_addr)
    common.log(f'[Fingerprint Generation] Done generating fingerprint for device: {device_mac_addr}')

    


def fingerprint_generation(device_mac_addr):
    # get frequency period file path
    freq_period_file_path = os.path.join(common.get_project_directory(),
                                       'freq_period', '1s', device_mac_addr.replace(':', '_') + '.txt')
    
    # Check if the frequency period file exists
    if not os.path.exists(freq_period_file_path):
        common.log(f'[Fingerprint Generation] Frequency period file not found for device: {device_mac_addr}')
        return
    
    # Read the frequency period data from the txt file
    try:
        with open(freq_period_file_path, 'r') as file:
            freq_period_data = file.readlines()
            common.log(f'[Fingerprint Generation] Successfully read frequency period data for device: {device_mac_addr}')
    except Exception as e:
        common.log(f'[Fingerprint Generation] Error reading frequency period data for device: {device_mac_addr}: {str(e)}')
        return
    
    # Create the output directory if it does not exist
    os.makedirs(out_dir, exist_ok=True)

    # find product name from mac address
    device_name = get_product_name_by_mac(device_mac_addr)
    if device_name == 'Unknown Device':
        device_name = 'unknown-device'
    device_name = device_name.lower().replace(' ', '-')

    # Open the output file for writing using a with statement
    output_file_path = os.path.join(out_dir, device_name + '.txt')
    with open(output_file_path, 'w+') as out_file:
        # Process the frequency period data
        output_dic = {}

        for line in freq_period_data:
            if line == '\n':
                continue

            if line.startswith('No'): # No period detected  
                continue
            elif line != '\n': # Period detected
                protocol = line.split()[0]
                domain_name = line.split()[1]
                tmp_period = [int(x) for x in re.findall(r'best: (\d+(?:, \d+)*)', line)[0].split(', ')]

                output_dic[(protocol, domain_name)] = tmp_period
        
        for key in output_dic.keys():
            # Store key and value in the output file
            out_file.write('%s %s %s \n' % (key[0], key[1], ' '.join(map(str, output_dic[key]))))

  
        # Remove last new line at the end of the file
        out_file.seek(0, os.SEEK_END) 
        out_file.seek(out_file.tell() - 1, os.SEEK_SET)
        out_file.truncate()

def periodic_inference_helper(device_mac_addr, data):
    """
    Helper function to infer periodicity in network traffic.
    Args:
        data: A pandas DataFrame containing the idle data.
    """

    # get data from the idle data
    nums = data['network_total'].values
    times = data['start_time'].values
    protocols = data['protocol'].values
    hosts = data['hosts'].fillna('').values
    X_feature = data.drop(['device', 'state', 'event','start_time','protocol', 'hosts'], axis=1).fillna(-1)
    if len(times) == 0:
        return
    
    # preprocessing, optional
    preprocessing = 1
    if preprocessing:
        for i in range(len(protocols)):
            if 'TCP' in protocols[i]:
                protocols[i] = 'TCP'
            elif 'UDP' in protocols[i]:
                protocols[i] = 'UDP'
            elif 'TLS' in protocols[i]:
                protocols[i] = 'TLS'
            if ';' in protocols[i]:
                tmp = protocols[i].split(';')
                protocols[i] = ' & '.join(tmp)
                # print(protocols[i])
        protocol_set = set(protocols)
        print(f'[Peridicity Inference] Protocol Set: {protocol_set}')
        
        for i in range(len(hosts)):
            if hosts[i] != '' and hosts[i] != None:
                tmp = hosts[i].replace('?', '').split(';')
                hosts[i] = tmp[0]
            if hosts[i] == None:
                hosts[i] == 'non'
            hosts[i] = hosts[i].lower()
                # print(hosts[i])
        domain_set = set(hosts)
        print(f'[Peridicity Inference] Domain Set: {domain_set}')
    # pre-processing end

    """
    Set Sampling Rate. In IMC23 paper, the sampling rate is set as 1 and 7200
    """
    sampling_rate = 1 # second
    binary = True # True: not consider the volumn of the flows 
    if sampling_rate!= 1:
        times = list(map(lambda x:round(x/sampling_rate), times)) # sampling rate
    times = list(map(int,times))
    max_time = np.max(times)
    min_time = np.min(times)
    print(f'[Peridicity Inference] Max Time: {max_time}, Min Time: {min_time}')

    # create a folder for storing the periodicity inference result
    os.makedirs('%s' % (file_path), exist_ok=True)
    
    """
    Iterate each protocol and domain pair 
    """
    for cur_protocol in protocol_set:
        # if cur_protocol != 'TCP':
        #     continue
        cur_domain_set = set()
        for i in range(len(times)):
            if protocols[i]== cur_protocol:
                cur_domain_set.add(hosts[i])

        """
        merge domain names with the same suffix
        """
        for i in cur_domain_set.copy():
            matched = 0
            if len(i.split('.')) >= 4:
                suffix = '.'.join([i.split('.')[-3], i.split('.')[-2], i.split('.')[-1]])
                for j in cur_domain_set.copy():
                    if j == i or j.startswith('*'):
                        continue
                    elif j.endswith(suffix):
                        matched = 1
                        
                        cur_domain_set.remove(j)
                if matched == 1:
                    cur_domain_set.remove(i)
                    cur_domain_set.add('*.'+suffix)

        for cur_domain in cur_domain_set:
            domain_count = {}
            count_dic ={}
            filter_feature = []
            for i in range(len(times)):
                if cur_domain.startswith('*'):
                    matched_suffix = hosts[i].endswith(cur_domain[2:])
                else:
                    matched_suffix = False
                if protocols[i]== cur_protocol and (matched_suffix or hosts[i] == cur_domain) : #  
                    if cur_domain in domain_count:
                        domain_count[cur_domain] += 1
                    else:
                        domain_count[cur_domain] = 1
                    
                    # if protocols[i]== 'GQUIC':
                    if times[i] in count_dic:
                        if binary:
                            count_dic[times[i]] += 1
                        else:
                            count_dic[times[i]] += nums[i]
                    else:
                        if binary:
                            count_dic[times[i]] = 1
                        else:
                            count_dic[times[i]] = nums[i]
                        

                    filter_feature.append(True)
                else:
                    filter_feature.append(False)
            
            domain_count2 = len(count_dic.keys())

            if count_dic == {}:
                continue

            '''
            min time = start time
            '''
            min_time_tmp = min_time
            # min_time_tmp = np.min(list(count_dic.keys()))
            while(min_time_tmp <= max_time):
                if min_time_tmp not in count_dic:
                    count_dic[min_time_tmp] = 0
                min_time_tmp += 1 

            requestOrdered = dict(collections.OrderedDict(sorted(count_dic.items(), key=lambda t: t[0])))
            x = list(requestOrdered.keys())
            x_min_tmp = x[0]
            x = list(map(lambda x:x-x_min_tmp,x))
            y = list(requestOrdered.values())

            count=0
            time_list =  []
            if domain_count2 < 30:
                for i in y:
                    if i > 0:
                        time_list.append(count)
                    count+=1

            """
            Frequency analysis
            """
            # N = 800
            N = len(x)  # number of signal points
            # sample spacing
            # T = 1.0 / ( N) 
            T = N / N
            # sampling frequency 
            f_s = 1/T
            yf = fft(y)

            # permutation 100 times to set threshold
            p_max_list = []
            for i in range(100):
                y_shuffle = np.random.permutation(y).tolist()
                p_max_list.append(np.max(np.abs(fft(y_shuffle)[1:N//2]).tolist()))
            threshold_99 = sorted(p_max_list)[-6]

            if sampling_rate >= 600:
                threshold_99 = sorted(p_max_list)[-11]
            
            tmp_list = []
            tmp_list_yf = []
            for i in range(len(yf[0:N//2])):
                if i == 0 or i == 1  or i ==len(yf)-1: # or i < N/10000
                    continue
                if np.abs(yf[i]) > threshold_99:
                    tmp_list.append(i)
                    tmp_list_yf.append(np.abs(yf[i]))

            period = []
            period_tmp_list = []
            if len(tmp_list) >0:
                for i in range(len(tmp_list)):
                    if sampling_rate >600 or round(N/tmp_list[i]) >= 10:
                        if len(period) == 0:
                            period.append(round(N/tmp_list[i]))
                            period_tmp_list.append(tmp_list[i])
                        else:
                            if round(N/tmp_list[i]) != period[-1]:
                                period.append(round(N/tmp_list[i]))
                                period_tmp_list.append(tmp_list[i])
        
            
            """
            Then, we use autocorrelation to validate the period candidates and 
            identify the true period for each pattern. The periods that have a
            significant autocorrelation score are chosen as the final periods
            of the signal. 
            """
            acf = sm.tsa.acf(y, nlags=len(y),fft=True)
        
            autocorrelation = []
            if len(period) == 0:
                pass
                # period.append(60)
            else:
                for i in range(len(period)):
                    tmp_range = [max(round(N/(period_tmp_list[i]-1)),period[i]+1), min(round(N/(period_tmp_list[i]+1)),period[i]-1)]

                    j = tmp_range[0]
                    while (j >= tmp_range[1]):
                        if j >= len(acf):
                            break
                        auto_tmp = acf[j]
                        if auto_tmp >= 3.315/np.sqrt(N):
                            autocorrelation.append(((j,auto_tmp))) # '%d:%d ' % 
                        j-=1
                autocorrelation = set(autocorrelation)
                autocorrelation = sorted(autocorrelation,key=lambda x:x[1], reverse = True)
            
            # special case that has only few data points: 
            if not any(autocorrelation) and domain_count2 <= 6 and domain_count2 >= 4:
                # autocorrelation = []
                time_diff = [abs(time_list[i + 1] - time_list[i]) for i in range(len(time_list)-1)]
                diff_diff = [abs(time_diff[i + 1] - time_diff[i]) for i in range(len(time_diff)-1)]
                res = [x for x in diff_diff if x <= 3600/sampling_rate]
                if len(res)==len(diff_diff):
                    autocorrelation.append((np.mean(time_diff),0))

            # print('--------------------------------------------------------')
            
            with open('%s/%s.txt' % (file_path, device_mac_addr.replace(':', '_')), 'a+') as file:
                    if len(period) > 0 and any(autocorrelation): # and len(acf_burst) > 1
                        file.write('\n%s %s # %d: ' %(cur_protocol,cur_domain,domain_count[cur_domain]))
                        file.write(' best: %d'% (list(autocorrelation)[0][0]  ))
                        if len(list(autocorrelation)) > 1:
                            file.write(', %d'% (list(autocorrelation)[1][0]  ))
                        
                
                    else:
                        file.write('\nNo period detected %s %s # %d ' %(cur_protocol,cur_domain, domain_count[cur_domain]))

