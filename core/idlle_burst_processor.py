"""
===============================================================================
Title: Idle Burst Processor
Author: Md Jakaria
Date: Jan 2025
Description: This module processes idle bursts, checks if the device info 
and save the data in file
===============================================================================
"""

import core.global_state as global_state
import core.common as common
import traceback
import os
import csv

# define the expected features of a burst 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP",
             "medianTBP", "kurtosisTBP", "skewTBP", "network_total",
             "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external",
            "meanBytes_out_local", "meanBytes_in_local",
            "device", "state", "event", "start_time", "protocol", "hosts"]


def process_idle_burst():
    """
    Process idle burst and save the data in file
    """

    burst = global_state.idle_burst_queue.get()

    try:
        process_idle_burst_helper(burst)

    except Exception as e:
        common.log('[Idle Burst Processor] Error processing burst: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())

def process_idle_burst_helper(burst):
    """
    Helper function to process idle burst and save the data in file
    Args:
        burst: A burst of network traffic.
    """
    # get the device mac address
    device = burst[-6]
    # create a csv file to store the data in the user-data/idle-data folder
    file_path = os.path.join(common.get_project_directory(), 'idle-data', device + '.csv')
    print('Processing idle burst for device: ', burst[-6])
    # check if the file exists
    if not os.path.exists(file_path):
        # create the file and write the header
        with open(file_path, 'w') as f:
            print('Creating new idle file for device: ', burst[-6])
            f.write(','.join(cols_feat) + '\n')
    

    # Write the burst data in the file
    with open(file_path, 'a', newline='') as f:
        print('Writing idle burst for device: ', burst[-6])
        writer = csv.writer(f)
        writer.writerow(burst)
