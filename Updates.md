This file is created by Jakaria 
Description: To track the update of integrating the event detecting ML models to the IoT Inspector


1. Checking if all features are collected
    File names: 
    1. s1_decode_dns_tls.py
        description: find ip-hostname tuples from DNS/TLS packets 
        Input: raw pcap files 
        Output: Dictionary of Device-name -> IP -> [(hostname, epoch-time)]

        Data extracted by IoT Inspector: 
        device_mac_addr -> can be transcribed to -> device names
        hostname, ip_addr reg_domain, is_advertising, data_source 

        Comment: IoT Inspector collects all features but the epoch time

    2. s1_decode_idle.py 
        description: decode pcap files to burst based on given threshold. (decode only pcap files for idle devices)
        Input: Pcap files 
        Output: list of burst based on given threshold.
        Sample output: 
        frame_num	    ts	        ts_delta	frame_len	protocol	streamID	ip_src	        ip_dst	        srcport	dstport	trans_proto	mac_addr	            host
        1	            1630688436	0	        85	        TLSv1.2	    0	        192.168.10.166	34.202.208.195	60385	443	    6	        22:ef:03:1a:97:b9       a1piwaqdydua5q.iot.us-east-1.amazonaws.com

        Comment:    
            Probably we have to collect this separately based on get_feature file....
            Maps hostname multiple ways: including: SNI, DNS, ipaddress (local, multicast), WHOIS (command: dig -x)

    3. s1_decode_activity.py 
        description: same as s1_decode_idle.py but for pcap files for activity devices

    4. s1_decode_unctrl.py 
        description: same as s1_decode_idle.py but for pcap files for unctrl devices

    5. s2_get_features.py
        Description: create features for ML model from decoded packets 
        INPUT: intermediate decoded files from s1
        OUTPUT: features for models, with device and state labels 

        feature: [ "meanBytes", "minBytes", "maxBytes", "medAbsDev", "skewLength", "kurtosisLength", "meanTBP", "varTBP", "medianTBP", "kurtosisTBP",
        "skewTBP", "network_total", "network_in", "network_out", "network_external", "network_local", "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local",  "device", "state", "event", "start_time", "remote_ip", "remote_port" ,"trans_protocol", "raw_protocol", "protocol", "hosts"]

    6. s2_get_features_unctrl.py
        Descn: same as s2_get_features.py but for un-controlled traffic
    

    7. periodicity_inference.py: 
        Descn: This script appears to analyze time-series network traffic data to detect periodic patterns from idle traffic. 
        input: features from s2_get_features
        output: list of peridic burst in this format: 
        protocol    domain          #   num_burst:     best:   correlations/repetations(seconds)
        TCP         example.com     #   120:           best:    60, 120
        No period detected NTP ntp1.dlink.com # 32 

    8. fingerprint_generation.py
        Descn: The code appears to analyze and process network traffic data stored in .txt files, determining whether traffic is periodic or non-periodic, and organizing the data into separate output files based on the classification
        
        input: list of peridic/non-periodic bursts
        
        output: fingerprints of periodic burst 
        protocol domain_name list_of_periods
        TCP wl.amazon-dss.com 86452 172800 

        # use fingerprint data from https://github.com/NEU-SNS/BehavIoT/tree/main/event_inference/period_extraction/freq_period/fingerprints

        non-periodic bursts: 
        No period detected TCP softwareupdates.amazon.com # 10 


    9. 








