# test_port_scan.py
from scapy.all import sr1, IP, TCP, conf


VICTIM_IP = "10.111.254.131"
ATTACKER_INTERFACE = "Wi-Fi"
conf.iface = ATTACKER_INTERFACE


# 16 ports, which is > your threshold of 15
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445,
                 1433, 1521, 3306, 3389, 5900, 8080]

print(f"Running scan of {len(PORTS_TO_SCAN)} ports on {VICTIM_IP}...")

for port in PORTS_TO_SCAN:
    print(f"Scanning port {port}...")
    packet = IP(dst=VICTIM_IP) / TCP(dport=port, flags="S")
    
    sr1(packet, timeout=1, verbose=False) 

print("Scan complete. Check NIPS for 'Vertical Port Scan' alert.")
