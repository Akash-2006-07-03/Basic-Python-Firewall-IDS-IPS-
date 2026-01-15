from scapy.all import IP, TCP, Raw, send

def send_nimda_packet(target_ip):
    payload = b"GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n"
    packet = IP(dst=target_ip)/TCP(dport=80)/Raw(load=payload)
    send(packet, verbose=False)

if __name__ == "__main__":
    send_nimda_packet("10.229.171.152")
