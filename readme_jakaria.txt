
Amazon plug is on 192.168.1.166 and the host pc is on 192.168.1.119

sudo tcpdump -i en0 -w amazon_plug.pcap -v 'host 192.168.1.166 and not arp and host not 192.168.1.119'