# Network-Guard
Network Guard is a lightweight, real-time monitoring tool that functions as both a mini Intrusion Detection System (IDS) and a Data Loss Prevention (DLP) system.
Step1
python -c "from scapy.all import conf; print(conf.ifaces)"
Local Testing: Software Loopback Interface 1 (IP: 127.0.0.1). This is a virtual interface used when your computer talks to itself, like when your browser sends data to the localhost:8000 test server. This is the one you need to use for the test.
# dlp.py (last line)
sniff(iface="Software Loopback Interface 1", prn=inspect_packet, store=0)
sudo python dlp.py
python server.py
host the html locally in  http://localhost:8000
and submit a sample test
note credit card number should begin with 4
