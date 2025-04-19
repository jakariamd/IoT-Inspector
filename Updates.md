This file is created by Jakaria  
Description: To track the update of integrating the event detecting ML models to the IoT Inspector

## Updates

#### 1. Checking if all features are collected

##### File names:

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

9. **(Add any additional updates here)** is file is created by Jakaria 
Description: To track the update of integrating the event detecting ML models to the IoT Inspector






## Mapping - NEU Project 

## 0. Input files
##### generate input: full path to PCAPs
To generate a list of file paths for the PCAP files in your dataset, use the following command in your terminal:
```
find /your-dataset-path > inputs/202x/xxx.txt 
```
<span style="color:red">***Note: Not needed***</span>

## 1. Decoding
#### hostname-IP mapping extraction from DNS and TLS 
To generate the hosename-IP mapping files, run `pipeline/s1_decode_dns_tls.py`.
```
python pipeline/s1_decode_dns_tls.py inputs/2021/idle_dns.txt
python pipeline/s1_decode_dns_tls.py inputs/2021/activity_dns.txt
```

<span style="color:red">***Note: This part is automatically done in packet processor***</span>

<span style="color:purple">***has some todo, please take a look core/packet_processors***</span>

#### Run decoding
decode frames 
TODO: s1_decode_idle.py used hard coding, remove hard coding 
```
python pipeline/s1_decode_idle.py inputs/2021/idle-2021.txt data/idle-2021-decoded/ 8
python pipeline/s1_decode_activity.py inputs/2021/train.txt data/train-decoded/ 8
python pipeline/s1_decode_activity.py inputs/2021/test.txt data/test-decoded/ 8
```
<span style="color:red">***Note: Decoding is implemented in core/packet-processor***</span>

## 2. Feature extraction
```
python pipeline/s2_get_features.py data/idle-2021-decoded/ data/idle-2021-features/
python pipeline/s2_get_features.py data/train-decoded/ data/train-features/
python pipeline/s2_get_features.py data/test-decoded/ data/test-features/
```
renamed the file location "data/train-features-by-jakaria/" because the directory already had the folder name "data/train-features"

<span style="color:red">***Note: Decoding is implemented in core/packet-processor***</span>

<span style="color:purple">***TODO: Run decoding and feature extraction in different thread***</span>

####routine dataset
```
python pipeline/s1_decode_dns_tls.py inputs/2021/routine_dns.txt
python pipeline/s1_decode_activity.py inputs/2021/routine-dataset.txt data/routine-decoded/ 
python pipeline/s2_get_features.py data/routine-decoded/ data/routine-features/
```
<span style="color:red">**TBA**</span>

####uncontrolled dataset. *Note that uncontrolled dataset is not included in our public datasets due to IRB constraints*)
CAN'T BE RUN 
```
python1 pipeline/s1_decode_dns_tls.py inputs/2022/uncontrolled_dns.txt
python1 pipeline/s1_decode_unctrl.py inputs/2022/uncontrolled_dataset.txt data/uncontrolled_decoded/  
```
CAN'T RUN

### 3. Periodic traffic extraction
#RUNNING -> FILE CREATED
```
cd period_extraction
python period_extraction/periodicity_inference.py
python period_extraction/fingerprint_generation.py  
cd ..
```
<span style="color:red">**Implemented in core/periodicity_inference.py**</span>

### 4. Preprocessing (standerdization and PCA)
#### Files created 
```
python pipeline/s4_preprocess_feature_new.py -i data/idle-2021-features/ -o data/idle/        
```

<span style="color:red">**Implemented in core/preprocess_feature_new.py**</span>

#### preprocessing transform-only on uncontrolled datasets
```
can't be run; data not available
# python pipeline/s4_preprocess_feature_applyonly.py -i data/uncontrolled-features/ -o data/uncontrolled/
```
<span style="color:red">**Implemented in core/burst_porcessor.py**</span>


### 5. Periodic event inference and filtering 
#### train
```
python pipeline/s5_periodic_filter.py -i data/idle-2021-train-std/ -o model/filter_apr20   
```
<span style="color:red">**Implemented in core/periodic_filter_training.py**</span>

#### activity dataset  

Filter out periodic events from activity datasets for better user event classificaition performance.
```
python pipeline/s5_filter_by_periodic.py -i train -o model/filter 
python pipeline/s5_filter_by_periodic.py -i test -o model/filter
```
<span style="color:red">**Implemented in core/periodic_filter_training.py**</span>

#### routine and uncontrolled dataset
Filters for routine and uncontrolled datasets. It uses both timing information and trained ML models for filtering
```
python pipeline/s5_periodic_time_filter.py -i data/routines-std/ -o model/time_filter
python pipeline/s5_filter_by_periodic_after_time.py -i routines -o model/filter
# python3 pipeline/s5_filter_by_periodic_after_time.py -i uncontrolled -o model/filter_may1
# python3 pipeline/s5_filter_by_periodic_after_time.py -i uncontrolled02 -o model/filter_may1
```

### 6. Activity (user event) inference
We've provided two options for user event inference: with and without hostnames. Based on our observations in the paper, 
the hostnames remain unchanged for most user events. However, there could be exceptions due to behavior changes or 
incomplete hostname-IP mappings. Therefore, we've implemented both methods. 
```
python pipeline/s6_activity_fingerprint.py -i data/train-filtered-std/ -o model/fingerprint/
python pipeline/s6_binary_model_whostname.py -i data/train-filtered-std/ -o model/binary 
python pipeline/s6_binary_predict_whostname.py -i data/routines-filtered-std/ -o model/binary
```
or
```
python3 pipeline/s6_binary_model.py -i data/train-filtered-std/ -o model/binary
python3 pipeline/s6_binary_predict.py -i data/routines-filtered-std/ -o model/binary
```
# Periodic model score
####generate periodic event (background traffic) deviation scores from datasets
```
python3 pipeline/periodic_deviation_score.py -i data/idle-half-train-std/ -o model/time_score_newT_train_idle
python3 pipeline/periodic_score_analysis.py model/time_score_newT_train_idle model/time_score_newT_test_idle
```



