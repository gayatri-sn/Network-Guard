# ids_module.py — Unified IDS + DLP Dashboard Integration (updated)
from scapy.all import sniff, IP, TCP, ARP
import datetime
import time
import csv
import os
import firewall_manager

# Use absolute base dir so both mitmproxy and Flask reference the same files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DLP_FILE = os.path.join(BASE_DIR, "dlp_events.csv")

CSV_HEADER = [
    "Timestamp", "Source_IP", "Destination_IP",
    "Data_Type", "Matched_Content", "Source_URL", "SourceType"
]

# Try to use the encrypted logger if present (preferred)
try:
    import encrypted_logger  # type: ignore
    ENCRYPTED_LOGGER_AVAILABLE = True
except Exception:
    ENCRYPTED_LOGGER_AVAILABLE = False

# --- Configuration (change to your values) ---
MY_INTERFACE = "Wi-Fi"            # replace with your interface name (ipconfig / ifconfig)
MY_GATEWAY_IP = "10.149.253.151"  # default gateway
MY_IP = "10.149.253.56"           # your own IP

# --- Thresholds ---
NORMAL_PORT_SCAN_THRESHOLD = 15
NORMAL_PACKET_THRESHOLD = 30
HIGH_PORT_SCAN_THRESHOLD = 3
HIGH_PACKET_THRESHOLD = 10
DISTRIBUTED_SCAN_THRESHOLD = 20
DISTRIBUTED_TIME_WINDOW = 10
TIME_WINDOW = 10
HIGH_ALERT_COOLDOWN = 600

# --- Global State ---
threat_state = {"level": "NORMAL", "high_alert_until": 0.0}
arp_alert_cooldown = {}
port_scan_tracker = {}
arp_table = {}
traffic_monitor = {}
port_access_tracker = {}
last_check_time = time.time()
last_distributed_check = time.time()


# --- Helper: ensure plaintext CSV exists with header ---
def ensure_plain_csv():
    try:
        if not os.path.exists(DLP_FILE):
            with open(DLP_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
            print(f"[IDS] Created plaintext dashboard file: {DLP_FILE}")
    except Exception as e:
        print(f"[IDS ERROR] Could not create {DLP_FILE}: {e}")


# --- Unified Logging Function ---
def write_dashboard_log(timestamp, src_ip, dst_ip, dtype, matched, source_url):
    """
    Preferred: append to encrypted logger storage.
    Fallback: append to plaintext dlp_events.csv so the web UI still sees alerts.
    The last column SourceType should be 'IDS' for IDS events.
    This function mirrors entries into the plaintext CSV regardless of encrypted logger presence,
    so the dashboard alert stream (which watches the plaintext file) will pick them up.
    """
    # sanitize / truncate matched content to avoid huge CSV fields
    try:
        if matched is None:
            matched = ""
        matched_str = str(matched)
        if len(matched_str) > 800:
            matched_str = matched_str[:800] + "..."  # truncate to safe length
    except Exception:
        matched_str = "[unserializable-match]"

    # Attempt encrypted logging first (if available)
    if ENCRYPTED_LOGGER_AVAILABLE:
        try:
            encrypted_logger.write_encrypted_log(timestamp, src_ip, dst_ip, dtype, matched_str, source_url)
            print(f"[DASHBOARD LOG] (enc) {dtype} from {src_ip}")
        except Exception as e:
            print(f"[DASHBOARD LOG ERROR] encrypted_logger failed: {e}")

    # Mirror to plaintext CSV so the dashboard alert stream can read it
    try:
        ensure_plain_csv()
        with open(DLP_FILE, "a", newline="", encoding="utf-8", errors="ignore") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, dtype, matched_str, source_url, "IDS"])
        # (Do not call encryption here; encrypted_logger already handles encryption if present.
        # If you want sync encryption, you can call proxy_inspector.encrypt_dlp_file or use encrypted_logger)
        print(f"[DASHBOARD LOG] (plain) {dtype} appended to {DLP_FILE}")
    except Exception as e:
        print(f"[DASHBOARD LOG ERROR] Failed to write plaintext dashboard log: {e}")


# --- Adaptive State Management ---
def set_high_alert():
    global threat_state
    if threat_state["level"] == "NORMAL":
        print("\n" + "!" * 50)
        print("🚨 THREAT DETECTED! Entering HIGH-ALERT state.")
        print(f"   Adaptive thresholds active for {HIGH_ALERT_COOLDOWN}s.")
        print("!" * 50 + "\n")
    threat_state["level"] = "HIGH"
    threat_state["high_alert_until"] = time.time() + HIGH_ALERT_COOLDOWN
    print(f"[STATE] High-Alert active until {time.ctime(threat_state['high_alert_until'])}")


def check_threat_level():
    global threat_state
    if threat_state["level"] == "HIGH" and time.time() > threat_state["high_alert_until"]:
        print("\n" + "*" * 50)
        print("✅ COOLDOWN COMPLETE. Returning to NORMAL state.")
        print("*" * 50 + "\n")
        threat_state["level"] = "NORMAL"


# --- Detection Logic ---
def detect_port_scan(packet):
    if threat_state["level"] == "HIGH":
        current_threshold = HIGH_PORT_SCAN_THRESHOLD
    else:
        current_threshold = NORMAL_PORT_SCAN_THRESHOLD

    try:
        if TCP in packet and packet[TCP].flags == "S":
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            port_scan_tracker.setdefault(src_ip, set()).add(dst_port)

            if len(port_scan_tracker[src_ip]) > current_threshold:
                details = f"Accessed {len(port_scan_tracker[src_ip])} ports (Threshold: {current_threshold})."
                alert("Vertical Port Scan", src_ip, details)

                if src_ip not in [MY_IP, MY_GATEWAY_IP, "127.0.0.1"]:
                    try:
                        firewall_manager.block_ip(src_ip)
                    except Exception as e:
                        print(f"[FIREWALL ERROR] Could not block {src_ip}: {e}")
                    set_high_alert()
                # reset tracker for that IP
                port_scan_tracker[src_ip] = set()
    except Exception as e:
        print(f"[ERROR] detect_port_scan: {e}")


def detect_distributed_scan(packet):
    global last_distributed_check
    try:
        if TCP in packet and packet[TCP].flags == "S":
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            port_access_tracker.setdefault(dst_port, set()).add(src_ip)

        current_time = time.time()
        if current_time - last_distributed_check > DISTRIBUTED_TIME_WINDOW:
            for port, ips in port_access_tracker.items():
                if len(ips) > DISTRIBUTED_SCAN_THRESHOLD:
                    details = f"Port {port} accessed by {len(ips)} IPs in {DISTRIBUTED_TIME_WINDOW}s."
                    alert("Distributed Scan", f"Port {port}", details)
                    set_high_alert()
            port_access_tracker.clear()
            last_distributed_check = current_time
    except Exception as e:
        print(f"[ERROR] detect_distributed_scan: {e}")


def detect_arp_spoof(packet):
    global arp_alert_cooldown
    try:
        if ARP in packet and packet[ARP].op == 2:
            sender_ip = packet[ARP].psrc
            sender_mac = packet[ARP].hwsrc

            if sender_ip not in arp_table:
                print(f"[ARP LEARNED] {sender_ip} → {sender_mac}")
                arp_table[sender_ip] = sender_mac
                return

            if arp_table[sender_ip] != sender_mac:
                now = time.time()
                if now > arp_alert_cooldown.get(sender_ip, 0):
                    details = f"IP was at {arp_table[sender_ip]}, now claims {sender_mac}."
                    alert("ARP Spoofing", sender_ip, details)
                    arp_alert_cooldown[sender_ip] = now + 60
                    set_high_alert()
    except Exception as e:
        print(f"[ERROR] detect_arp_spoof: {e}")


def detect_traffic_anomaly(packet):
    global last_check_time
    try:
        check_threat_level()
        threshold = HIGH_PACKET_THRESHOLD if threat_state["level"] == "HIGH" else NORMAL_PACKET_THRESHOLD

        if IP in packet:
            src_ip = packet[IP].src
            traffic_monitor[src_ip] = traffic_monitor.get(src_ip, 0) + 1

        now = time.time()
        if now - last_check_time > TIME_WINDOW:
            for ip, count in list(traffic_monitor.items()):
                if count > threshold:
                    details = f"Received {count} packets in {TIME_WINDOW}s (Threshold: {threshold})."
                    alert("Traffic Anomaly (DoS)", ip, details)

                    if ip not in [MY_IP, MY_GATEWAY_IP, "127.0.0.1"]:
                        try:
                            firewall_manager.block_ip(ip)
                        except Exception as e:
                            print(f"[FIREWALL ERROR] Could not block {ip}: {e}")
                        set_high_alert()
            traffic_monitor.clear()
            last_check_time = now
    except Exception as e:
        print(f"[ERROR] detect_traffic_anomaly: {e}")


# --- ALERT HANDLER ---
def alert(attack_type, source, details):
    """
    Called when the IDS detects something noteworthy.
    Writes to unified dashboard storage so your web UI picks it up.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Try to extract src/dst if `source` looks like an IP or 'Port X'
    src_ip = str(source)
    dst_ip = "-"
    # Console output
    print(f"\n{'=' * 50}\nALERT: {attack_type} Detected!\n  Timestamp: {timestamp}\n  Source: {source}\n  Details: {details}\n{'=' * 50}\n")

    # Write to dashboard (attempt encrypted logger + plaintext mirror)
    try:
        write_dashboard_log(timestamp, src_ip, dst_ip, attack_type, details, "IDS")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to write dashboard log: {e}")


# --- Packet Sniffer ---
def packet_callback(packet):
    try:
        if ARP in packet:
            detect_arp_spoof(packet)
            return
        if IP in packet:
            # Core detectors
            detect_traffic_anomaly(packet)
            detect_port_scan(packet)
            detect_distributed_scan(packet)
    except Exception as e:
        print(f"[ERROR] Exception handling packet: {e}")


def start_sniffer():
    print("🚀 Network Guard NIPS starting up...")
    print(f"Sniffing on interface: {MY_INTERFACE}")
    print(f"Defending Gateway: {MY_GATEWAY_IP}")
    print("Press Ctrl+C to stop.")
    ensure_plain_csv()
    try:
        sniff(iface=MY_INTERFACE, prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
        firewall_manager.cleanup_all_blocks()
        print("\n🛑 Network Guard NIPS shutting down.")


if __name__ == "__main__":
    # check admin privileges if required by firewall_manager
    try:
        firewall_manager.check_admin_privileges()
    except Exception as e:
        print(f"[WARN] Could not verify admin privileges: {e}")
    start_sniffer()
