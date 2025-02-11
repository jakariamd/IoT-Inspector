This file is created by Jakaria  
Description: To track the update of integrating the event detecting ML models to the IoT Inspector

## Updates

### 1. Checking if all features are collected

#### File names:

1. **s1_decode_dns_tls.py**
    - **Description:** Find IP-hostname tuples from DNS/TLS packets.
    - **Input:** Raw pcap files.
    - **Output:** Dictionary of Device-name -> IP -> [(hostname, epoch-time)].
    - **Data extracted by IoT Inspector:** 
        - device_mac_addr -> can be transcribed to -> device names
        - hostname, ip_addr, reg_domain, is_advertising, data_source
    - **Comment:** IoT Inspector collects all features but the epoch time.

2. **s1_decode_idle.py**
    - **Description:** Decode pcap files to burst based on a given threshold (1s). It splits a pcap file into small txt files, each representing a burst of packets. This burst of packets will be transformed into features in s2.
    - **Input:** Pcap files.
    - **Output:** List of bursts based on the given threshold.
    - **Sample output:**
        ```
        frame_num    ts          ts_delta    frame_len   protocol    streamID    ip_src          ip_dst          srcport dstport trans_proto mac_addr            host
        1            1630688436  0           85          TLSv1.2     0           192.168.10.166  34.202.208.195  60385   443     6           22:ef:03:1a:97:b9   amazonaws.com
        ```
    - **Comment:** 
        - Probably we have to collect this separately based on the get_feature file.
        - Maps hostname in multiple ways: including SNI, DNS, IP address (local, multicast), WHOIS (command: dig -x).

3. **s1_decode_activity.py**
    - **Description:** Same as s1_decode_idle.py but for pcap files for activity devices.

4. **s1_decode_unctrl.py**
    - **Description:** Same as s1_decode_idle.py but for pcap files for uncontrolled devices.

5. **s2_get_features.py**
    - **Description:** Create features for ML model from decoded packets.
    - **Input:** Intermediate decoded files from s1.
    - **Output:** Features for models, with device and state labels.
    - **Features:** 
        ```
        ["meanBytes", "minBytes", "maxBytes", "medAbsDev", "skewLength", "kurtosisLength", "meanTBP", "varTBP", "medianTBP", "kurtosisTBP",
        "skewTBP", "network_total", "network_in", "network_out", "network_external", "network_local", "network_in_local", "network_out_local", "meanBytes_out_external", "meanBytes_in_external", "meanBytes_out_local", "meanBytes_in_local", "device", "state", "event", "start_time", "remote_ip", "remote_port", "trans_protocol", "raw_protocol", "protocol", "hosts"]
        ```

6. **s2_get_features_unctrl.py**
    - **Description:** Same as s2_get_features.py but for uncontrolled traffic.

7. **periodicity_inference.py**
    - **Description:** This script analyzes time-series network traffic data to detect periodic patterns from idle traffic.
    - **Input:** Features from s2_get_features.
    - **Output:** List of periodic bursts in this format:
        ```
        protocol    domain          #   num_burst:     best:   correlations/repetitions(seconds)
        TCP         example.com     #   120:           best:    60, 120
        No period detected NTP ntp1.dlink.com # 32
        ```

8. **fingerprint_generation.py**
    - **Description:** The code analyzes and processes network traffic data stored in .txt files, determining whether traffic is periodic or non-periodic, and organizing the data into separate output files based on the classification.
    - **Input:** List of periodic/non-periodic bursts.
    - **Output:** Fingerprints of periodic bursts.
        ```
        protocol domain_name list_of_periods
        TCP wl.amazon-dss.com 86452 172800
        ```
        - Use fingerprint data from [BehavIoT](https://github.com/NEU-SNS/BehavIoT/tree/main/event_inference/period_extraction/freq_period/fingerprints).
        - Non-periodic bursts:
        ```
        No period detected TCP softwareupdates.amazon.com # 10
        ```

9. **(Add any additional updates here)**is file is created by Jakaria 
Description: To track the update of integrating the event detecting ML models to the IoT Inspector



