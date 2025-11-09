# test_dos_flood.py
from scapy.all import send, IP, TCP, conf


VICTIM_IP = "10.111.254.131"
ATTACKER_INTERFACE = "Wi-Fi"
PACKET_COUNT = 50  # This is > your threshold of 30


conf.iface = ATTACKER_INTERFACE 

print(f"Sending {PACKET_COUNT} flood packets to {VICTIM_IP}...")

packet = IP(dst=VICTIM_IP) / TCP(dport=80, flags="S")
send(packet, count=PACKET_COUNT, verbose=False)

print("Flood sent. Check your NIPS for 'Traffic Anomaly' and 'HIGH-ALERT' state.")
