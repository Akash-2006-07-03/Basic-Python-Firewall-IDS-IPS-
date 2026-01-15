import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")


def read_ip_file(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as file:
        return set(line.strip() for line in file if line.strip())

def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80:
            payload = packet[Raw].load
            return b"GET /scripts/root.exe" in payload
    return False

def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, "firewall.log")

    with open(log_file, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Whitelist
    if src_ip in whitelist_ips:
        return

    # Blacklist
    if src_ip in blacklist_ips:
        if src_ip not in blocked_ips:
            os.system(f"iptables -A OUTPUT -s {src_ip} -j DROP")
            log_event(f"Blocked BLACKLIST IP: {src_ip}")
            blocked_ips.add(src_ip)
        return

    # Nimda signature detection
    if is_nimda_worm(packet):
        if src_ip not in blocked_ips:
            print(f"[!] Nimda detected from {src_ip}")
            os.system(f"iptables -A OUTPUT -s {src_ip} -j DROP")
            log_event(f"Blocked NIMDA IP: {src_ip}")
            blocked_ips.add(src_ip)
        return

    # DoS detection
    packet_count[src_ip] += 1
    now = time.time()
    interval = now - start_time[0]

    if interval >= 1:
        for ip, count in packet_count.items():
            rate = count / interval
            if rate > THRESHOLD and ip not in blocked_ips:
                print(f"[!] DoS detected from {ip} ({rate:.2f} pkt/s)")
                os.system(f"iptables -A OUTPUT -s {ip} -j DROP")
                log_event(f"Blocked DOS IP: {ip}, rate={rate:.2f}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = now


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(iface="lo", prn=packet_callback, store=False)
