# Network-Guard
Network Guard is a lightweight, real-time monitoring tool that functions as both a mini Intrusion Detection System (IDS) and a Data Loss Prevention (DLP) system.
# To run this module:
 1) Open it in vs code admin
 2) After opening, run this .\venv\Scripts\activate
 3) Then run python ids_module.py
# For detection:
🧪 How to Test
All tests must be run from a separate "Attacker" PC (or a Virtual Machine in Bridged Mode) on the same network. All test scripts must also be run as Administrator.

Test 1: DoS Flood
On Attacker PC: Run test_dos_flood.py.

Expected NIPS Output:

ALERT: Traffic Anomaly (DoS) Detected!

[FIREWALL] 🛡️ Blocking IP address...

🚨 THREAT DETECTED! Entering HIGH-ALERT state.

Test 2: Vertical Port Scan
On Victim PC: Restart the NIPS (to reset to NORMAL state).

On Attacker PC: Run test_port_scan.py.

Expected NIPS Output:

ALERT: Vertical Port Scan Detected! (after 16 ports)

[FIREWALL] 🛡️ Blocking IP address...

🚨 THREAT DETECTED! Entering HIGH-ALERT state.

Test 3: ARP Spoofing
On Victim PC: Mute detect_traffic_anomaly in packet_callback and restart the NIPS. Wait for it to "learn" the real gateway.

On Attacker PC: Run test_arp_spoof.py (or test_arp_direct.py).

Expected NIPS Output:

ALERT: ARP Spoofing Detected! (will print one time)

The NIPS will then silently send "Fact-Checker" packets to fight the attack without flooding your console..py in another terminal
