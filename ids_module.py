# ids_module.py
from scapy.all import sniff, IP, TCP, ARP, Ether, sendp, get_if_hwaddr, conf
import datetime
import time
import firewall_manager


MY_INTERFACE = "Wi-Fi"          # Correct from your ipconfig
MY_GATEWAY_IP = "10.79.232.31"  # Correct from your ipconfig
MY_IP = "10.79.232.131"         # Correct from your ipconfig



NORMAL_PORT_SCAN_THRESHOLD = 15
NORMAL_PACKET_THRESHOLD = 30
HIGH_PORT_SCAN_THRESHOLD = 3
HIGH_PACKET_THRESHOLD = 10
DISTRIBUTED_SCAN_THRESHOLD = 20
DISTRIBUTED_TIME_WINDOW = 10
TIME_WINDOW = 10
HIGH_ALERT_COOLDOWN = 600


threat_state = {"level": "NORMAL", "high_alert_until": 0.0}
arp_alert_cooldown = {} 
port_scan_tracker = {}
arp_table = {}
traffic_monitor = {}
last_check_time = time.time()
port_access_tracker = {}
last_distributed_check = time.time()


def set_high_alert():
    global threat_state
    if threat_state["level"] == "NORMAL":
        print("\n" + "!"*50)
        print(" THREAT DETECTED! Entering HIGH-ALERT state.")
        print(f"   Adaptive thresholds are now active for {HIGH_ALERT_COOLDOWN}s.")
        print("!"*50 + "\n")
    threat_state["level"] = "HIGH"
    threat_state["high_alert_until"] = time.time() + HIGH_ALERT_COOLDOWN
    print(f"[STATE] High-Alert timer reset. Cooldown until {time.ctime(threat_state['high_alert_until'])}")

def check_threat_level():
    global threat_state
    if threat_state["level"] == "HIGH" and time.time() > threat_state["high_alert_until"]:
        print("\n" + "*"*50)
        print(" COOLDOWN COMPLETE. Returning to NORMAL state.")
        print("*"*50 + "\n")
        threat_state["level"] = "NORMAL"



def detect_port_scan(packet):
    if threat_state["level"] == "HIGH": current_threshold = HIGH_PORT_SCAN_THRESHOLD
    else: current_threshold = NORMAL_PORT_SCAN_THRESHOLD
    
    if TCP in packet and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip not in port_scan_tracker: port_scan_tracker[src_ip] = set()
        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > current_threshold:
            alert("Vertical Port Scan", src_ip, f"Accessed {len(port_scan_tracker[src_ip])} ports (Threshold: {current_threshold}).")
            
            
            if src_ip == "127.0.0.1" or src_ip == MY_GATEWAY_IP or src_ip == MY_IP:
                print(f"[NIPS] Port scan from local IP {src_ip} detected. Ignoring.")
            else:
                print(f"[NIPS] External port scan from {src_ip} detected. Taking action.")
                firewall_manager.block_ip(src_ip)
                set_high_alert()
            
            
            port_scan_tracker[src_ip] = set() 

def detect_distributed_scan(packet):
    global last_distributed_check
    if TCP in packet and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if dst_port not in port_access_tracker: port_access_tracker[dst_port] = set()
        port_access_tracker[dst_port].add(src_ip)

    current_time = time.time()
    if current_time - last_distributed_check > DISTRIBUTED_TIME_WINDOW:
        for port, ips in port_access_tracker.items():
            if len(ips) > DISTRIBUTED_SCAN_THRESHOLD:
                alert("Distributed Scan", f"Port {port}", f"Accessed by {len(ips)} IPs in {DISTRIBUTED_TIME_WINDOW}s.")
                set_high_alert()
        port_access_tracker.clear()
        last_distributed_check = current_time

def detect_arp_spoof(packet):
    """
    Detects ARP spoofing, alerts ONCE, and then continuously
    sends prevention packets without flooding the console.
    """
    global arp_alert_cooldown
    
    if ARP in packet and packet[ARP].op == 2: 
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc

        
        if sender_ip not in arp_table:
           
            print("\n" + "#"*70)
            print(f"####  [ARP LEARNED] New Host: {sender_ip} is at {sender_mac}  ####")
            print("#  Run the spoofer AGAIN with a NEW MAC to trigger the REAL alert.  #")
            print("#"*70 + "\n")
            arp_table[sender_ip] = sender_mac # Add to trusted table
            return
            
        
        if arp_table[sender_ip] != sender_mac:
            
            
          
            current_time = time.time()
            if current_time > arp_alert_cooldown.get(sender_ip, 0):
                
                alert(
                    "ARP Spoofing",
                    sender_ip,
                    f"IP was at {arp_table[sender_ip]}, but now claims {sender_mac}."
                )
                
                
                arp_alert_cooldown[sender_ip] = current_time + 60 
                
                
                set_high_alert()
            
           
            try:
                true_gateway_mac = arp_table.get(MY_GATEWAY_IP)
                if sender_ip == MY_GATEWAY_IP and true_gateway_mac:
                    correction_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst="255.255.255.255", psrc=MY_GATEWAY_IP, hwsrc=true_gateway_mac)
                    sendp(correction_packet, iface=MY_INTERFACE, verbose=False)
            except Exception as e:
                
                pass 


def detect_traffic_anomaly(packet):
    """
    Monitors for an unusually high volume of packets (DoS).
    """
    global last_check_time
    check_threat_level()
    if threat_state["level"] == "HIGH": current_threshold = HIGH_PACKET_THRESHOLD
    else: current_threshold = NORMAL_PACKET_THRESHOLD

    if IP in packet:
        src_ip = packet[IP].src
        traffic_monitor[src_ip] = traffic_monitor.get(src_ip, 0) + 1

    current_time = time.time()
    if current_time - last_check_time > TIME_WINDOW:
        for ip, count in traffic_monitor.items():
            if count > current_threshold:
                alert("Traffic Anomaly (DoS)", ip, f"Received {count} packets in {TIME_WINDOW}s (Threshold: {current_threshold}).")
                
                
                if ip == "127.0.0.1" or ip == MY_GATEWAY_IP or ip == MY_IP:
                    print(f"[NIPS] High traffic from local IP {ip} detected. Ignoring.")
                else:
                    print(f"[NIPS] External threat from {ip} detected. Taking action.")
                    firewall_manager.block_ip(ip)
                    set_high_alert()

        traffic_monitor.clear()
        last_check_time = current_time



def alert(attack_type, source, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_message = (
        f"ALERT: {attack_type} Detected!\n"
        f"    - Timestamp: {timestamp}\n"
        f"   - Source:    {source}\n"
        f"   - Details:   {details}"
    )
    print(f"\n{'='*50}\n{alert_message}\n{'='*50}\n")

def packet_callback(packet):
    """
    Main callback function.
    To test ARP spoofing, add a '#' before 'detect_traffic_anomaly'
    to temporarily mute it.
    """
    if ARP in packet:
        detect_arp_spoof(packet)
        return
    if IP in packet:
        detect_traffic_anomaly(packet) 
        detect_port_scan(packet)
        detect_distributed_scan(packet)

def start_sniffer():
    print(" Network Guard NIPS starting up...")
    print(f"Sniffing on interface: {MY_INTERFACE}")
    print(f"Defending Gateway: {MY_GATEWAY_IP}")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=MY_INTERFACE, prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
    finally:
        
        firewall_manager.cleanup_all_blocks()
        print("\n Network Guard NIPS shutting down.")

if __name__ == "__main__":
    firewall_manager.check_admin_privileges()
    start_sniffer()
