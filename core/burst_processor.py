import core.global_state as global_state
import core.common as common
import traceback

# import time
# import scapy.all as sc
# import core.model as model
# import core.networking as networking
# from core.tls_processor import extract_sni
# import core.friendly_organizer as friendly_organizer

# # Jakaria: import additional libraries
# import core.utils as utils
# import ipaddress
# import pandas as pd
# import numpy as np
# from scipy.stats import kurtosis
# from scipy.stats import skew
# from statsmodels import robust


# define the expected features of a burst 
cols_feat = [ "meanBytes", "minBytes", "maxBytes", "medAbsDev",
             "skewLength", "kurtosisLength", "meanTBP", "varTBP", "medianTBP", "kurtosisTBP",
             "skewTBP", "network_total", "network_in", "network_out", "network_external", "network_local",
            "network_in_local", "network_out_local", "meanBytes_out_external",
            "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local", "device", "state", "event", "start_time", "protocol", "hosts"]



def process_burst():

    burst = global_state.burst_queue.get()

    try:
        process_burst_helper(burst)

    except Exception as e:
        common.log('[Burst Pre-Processor] Error processing burst: ' + str(e) + ' for burst: ' + str(burst) + '\n' + traceback.format_exc())


def process_burst_helper(burst):

    common.log('[Burst Pre-Processor] Success processing burst: ' + str(burst))
    return 