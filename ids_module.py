# ids_module.py
# Author: Person 1 - Core Packet Sniffer + Intrusion Detection

# --- Imports ---
from scapy.all import sniff, IP, TCP, ARP
import datetime
import time

# --- Configuration Thresholds ---
# Feel free to adjust these values based on your network's normal behavior.

# Port Scan: How many different ports accessed by one IP before it's flagged.
PORT_SCAN_THRESHOLD = 15

# Traffic Anomaly: How many packets from one IP in a given time window is suspicious.
TIME_WINDOW = 10  # in seconds
PACKET_THRESHOLD = 30

# --- Data Structures for Detection ---

# Tracks port scan attempts: { 'source_ip': {port1, port2, ...} }
port_scan_tracker = {}

# Stores the trusted IP-to-MAC address mapping: { 'ip_address': 'mac_address' }
arp_table = {}

# Counts packets from each IP for anomaly detection: { 'source_ip': packet_count }
traffic_monitor = {}
last_check_time = time.time()


# --- Detection Logic ---

def detect_port_scan(packet):
    """
    Identifies port scanning by tracking connection attempts (TCP SYN packets)
    from a single source IP to multiple destination ports.
    """
    if TCP in packet and packet[TCP].flags == "S":  # "S" is the SYN flag for a new connection
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Initialize tracker for this IP if it's new
        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = set()

        # Add the accessed port to the set for that IP
        port_scan_tracker[src_ip].add(dst_port)

        # If the number of unique ports exceeds our threshold, raise an alert
        if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_message = (
                f"ALERT: Potential Port Scan Detected!\n"
                f"  - Timestamp: {timestamp}\n"
                f"  - Attack Type: Port Scan\n"
                f"  - Source IP:   {src_ip}\n"
                f"  - Details:     Accessed {len(port_scan_tracker[src_ip])} unique ports."
            )
            print(f"\n{'='*40}\n{alert_message}\n{'='*40}\n")
            # Reset after alerting to avoid repeated messages for the same scan
            port_scan_tracker[src_ip] = set()


def detect_arp_spoof(packet):
    """
    Detects ARP spoofing by checking if an IP address suddenly claims a new
    MAC address, which contradicts our learned ARP table.
    """
    # An ARP "is-at" reply (op=2) is used for the attack
    if ARP in packet and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        # If we have this IP in our table but the MAC is different, it's a spoof
        if sender_ip in arp_table and arp_table[sender_ip] != sender_mac:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_message = (
                f"ALERT: Potential ARP Spoofing Detected!\n"
                f"  - Timestamp: {timestamp}\n"
                f"  - Attack Type: ARP Spoof\n"
                f"  - IP Address:  {sender_ip}\n"
                f"  - Details:     IP was at {arp_table[sender_ip]}, but is now claiming to be at {sender_mac}."
            )
            print(f"\n{'='*40}\n{alert_message}\n{'='*40}\n")

        # Update our table with the most recent mapping
        arp_table[sender_ip] = sender_mac


def detect_traffic_anomaly(packet):
    """
    Monitors for an unusually high volume of packets from a single source IP
    within a short time window, which could indicate a DoS flood attack.
    """
    global last_check_time  # Use the global variable to track time

    if IP in packet:
        src_ip = packet[IP].src
        traffic_monitor[src_ip] = traffic_monitor.get(src_ip, 0) + 1

    current_time = time.time()
    # Check if the time window has elapsed
    if current_time - last_check_time > TIME_WINDOW:
        for ip, count in traffic_monitor.items():
            if count > PACKET_THRESHOLD:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_message = (
                    f"ALERT: Traffic Anomaly Detected!\n"
                    f"  - Timestamp:   {timestamp}\n"
                    f"  - Attack Type:   Potential DoS Flood\n"
                    f"  - Source IP:     {ip}\n"
                    f"  - Details:       Received {count} packets in the last {TIME_WINDOW} seconds."
                )
                print(f"\n{'='*40}\n{alert_message}\n{'='*40}\n")

        # Reset for the next time window
        traffic_monitor.clear()
        last_check_time = current_time


# --- Main Sniffer Function ---

# --- Main Sniffer Function ---

def packet_callback(packet):
    """
    This is the main callback function that Scapy will execute for each
    packet sniffed. It safely orchestrates the detection logic.
    """
    # First, handle ARP packets, which do NOT have an IP layer.
    # We must check for this separately.
    if ARP in packet:
        detect_arp_spoof(packet)
        return  # Stop processing this packet since it's not IP-based

    # Next, handle all IP-based packets.
    # The other detectors rely on the presence of an IP layer.
    if IP in packet:
        detect_traffic_anomaly(packet)
        detect_port_scan(packet)
    
    # Any packet that is not ARP or IP will be ignored by our logic.

# The start_sniffer() and if __name__ == "__main__": parts remain the same.


def start_sniffer():
    """
    Starts the main packet sniffer.
    """
    print("🚀 Network Guard IDS starting up...")
    print("Sniffing for network intrusions. Press Ctrl+C to stop.")
    try:
        # 'prn' specifies the callback function
        # 'store=0' prevents Scapy from storing packets in memory
        sniff(iface="Wi-Fi", prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
    finally:
        print("\n🛑 Network Guard IDS shutting down.")


if __name__ == "__main__":
    start_sniffer()