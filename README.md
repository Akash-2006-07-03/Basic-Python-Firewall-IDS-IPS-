<h3>🛡️ Basic Python Firewall (IDS/IPS)</h3>

This project is a host-based firewall built using Python and Scapy.
It implements whitelist/blacklist filtering, signature-based intrusion detection (Nimda), and rate-based DoS detection, with automatic blocking using iptables.

<h3>🔹 Features</h3>

Whitelist & blacklist support

Nimda signature detection

DoS (TCP SYN flood) detection

Automatic IP blocking

Event logging

<h3>🔹 Files</h3>

firewall.py – Main firewall engine

whitelist.txt, blacklist.txt – IP rules

nimda_packet_sender.py – Nimda attack simulator

packet_flooder.py – DoS attack simulator

logs/ – Firewall logs

<h3>🔹 Run</h3>
sudo python3 firewall.py

<h3>🔹 Purpose</h3>

Demonstrates core firewall, IDS, and IPS concepts and serves as a foundation for an advanced adaptive firewall project.
