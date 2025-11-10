# test_port_scan.py
from scapy.all import srp1, IP, TCP, Ether, conf

# --- CONFIG ---
VICTIM_IP = "10.149.253.56"
VICTIM_MAC = "E8-FB-1C-59-E1-FF"
ATTACKER_INTERFACE = "Wi-Fi"
# --- END CONFIG ---

conf.iface = ATTACKER_INTERFACE
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445,
                 1433, 1521, 3306, 3389, 5900, 8080]

print(f"Running L2 scan of {len(PORTS_TO_SCAN)} ports on {VICTIM_IP} ({VICTIM_MAC})...")
for port in PORTS_TO_SCAN:
    print(f"Scanning port {port}...")
    packet = Ether(dst=VICTIM_MAC.replace("-", ":")) / IP(dst=VICTIM_IP) / TCP(dport=port, flags="S")
    srp1(packet, iface=ATTACKER_INTERFACE, timeout=1, verbose=False) 
print("Scan complete. Check NIPS for 'Vertical Port Scan' alert.")