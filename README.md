# Network-Guard
Network Guard is a lightweight, real-time monitoring tool that functions as both a mini Intrusion Detection System (IDS) and a Data Loss Prevention (DLP) system.
# To run this module:
 1) Open it in vs code admin
 2) After opening, run this .\venv\Scripts\activate
 3) Then run python ids_module.py
# For detection:
## Test 1: Port Scanning Detection 🕵️
Goal: To trigger the ALERT: Potential Port Scan Detected! message.  <br>
Tool (Phone App): Install Fing app
Steps: <br>
Download and open the Fing app on your phone. <br>
The app will automatically scan your network. You should see a list of devices. Find your computer in the list (it might be identified by its name, like "HP-Laptop" or just by the IP 10.70.5.42). <br>
Tap on your computer in the list. <br>
Scroll down and find the option that says "Find open ports" or "Scan Ports" and tap it. <br>
The app will now scan your computer.
 <br>
Expected Result:
Look at your computer's terminal window. As your phone scans the ports, your Python script will detect the activity and print the alert! 🚨 <br>
ALERT: Potential Port Scan Detected!
  - Timestamp: 2025-10-11 14:55:12
  - Attack Type: Port Scan
  - Source IP:   [Your phone's IP address]
  - Details:     Accessed 16 unique ports.

## Test 2: Traffic Anomaly (DoS Flood) Detection 🌊
Goal: To trigger the ALERT: Traffic Anomaly Detected! message. <br>
Tool (Phone App):Use Fing App <br>
Steps: <br>
Open the network utility app on your phone. <br>
Find the "Ping" or "Packet Generator" feature. <br>
Enter your PC's IP address: 10.70.5.42. <br>
Look for settings to control the ping. You want to make it as fast as possible: <br>
Set the Interval to 0 or the lowest possible value. <br>
Set the Count or Number of Packets to a very high number or "infinite" (∞). <br>
Start the ping flood. <br>
 <br>
Expected Result:
Your phone will send a huge number of packets to your PC. After the 10-second window in your script passes, it will count the packets and trigger the traffic anomaly alert. 🚨
 <br>

ALERT: Traffic Anomaly Detected!
  - Timestamp:   2025-10-11 14:58:30
  - Attack Type:   Potential DoS Flood
  - Source IP:     [Your phone's IP address]
  - Details:       Received 125 packets in the last 10 seconds.


## Test 3: ARP Spoofing Detection 🎭
Goal: To trigger the ALERT: Potential ARP Spoofing Detected! message. <br>
Steps: <br>
run the arp_spoofer_test.py in another terminal
