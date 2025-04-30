"""
Captures and analyzes packets from the network.

"""
import scapy.all as sc
import core.global_state as global_state
import core.common as common
from scapy.all import sniff, IP, TCP, send


WINDOWS_TEXT = '\n' * 20 + """
==================================================
            IoT Inspector is running
==================================================

To quit IoT Inspector, simply close this window.


"""



def start_packet_collector():

    # Show the WINDOWS_TEXT if we are running on Windows
    if common.get_os() == 'windows':
        print(WINDOWS_TEXT)

    sc.load_layer('tls')

    # Continuously sniff packets for 30 second intervals
    sc.sniff(
        prn=block_traffic,
        iface=global_state.host_active_interface,
        stop_filter=lambda _: not global_state.is_running,
        filter=f'(not arp and host not {global_state.host_ip_addr}) or arp', # Avoid capturing packets to/from the host itself, except ARP, which we need for discovery -- this is for performance improvement
        timeout=30
    )

def block_traffic(packet):
    target_ip = "192.168.1.166"
    if packet.haslayer(IP) and (packet[IP].src == target_ip or packet[IP].dst == target_ip):
        print(f"Blocking packet: {packet.summary()}")
        if packet.haslayer(TCP):
            rst_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / TCP(
                sport=packet[TCP].dport,
                dport=packet[TCP].sport,
                flags="R"
            )
            send(rst_packet, verbose=False)
    else:
        add_packet_to_queue(packet)


def add_packet_to_queue(pkt):
    """
    Adds a packet to the packet queue.

    """
    with global_state.global_state_lock:
        if not global_state.is_inspecting:
            return

    global_state.packet_queue.put(pkt)