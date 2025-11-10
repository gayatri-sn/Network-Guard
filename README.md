**Network Guard – Real-Time IDS & DLP Security Framework**

Network Guard is a modular network security system that integrates an Intrusion Detection System (IDS) and a Data Leak Prevention (DLP) module under a unified Flask-based dashboard.
It provides real-time alerting, encrypted log management, and intuitive visualization of network threats and data leaks.

**Key Features**

**Intrusion Detection System (IDS):**

- Detects port scans, ARP spoofing, and DoS/flood attacks using Scapy.

- Automatically blocks offending IPs via OS-level firewall control.

- Logs events with timestamps, IPs, and detected attack types.

**Data Leak Prevention (DLP):**

- Monitors outbound data for sensitive information (Emails, Credit Cards, Phone Numbers, GPS Coordinates).

- Integrates with an HTTP/HTTPS proxy for live packet inspection.

- Generates structured alerts for outgoing sensitive payloads.

**Encryption & Logging:**

- All events are logged in plaintext (dlp_events.csv) and encrypted (encrypted_logs.csv) using Fernet AES encryption.

- Decryption occurs only within Flask; no plaintext exposure on disk.

**Unified Flask Dashboard:**

- Live alert streaming via Server-Sent Events (SSE).

- Color-coded alerts: Red IDS Alerts and Blue DLP Alerts.

- Historical log viewing with decrypted and highlighted sensitive data.


**How It Works**

- IDS module (ids_module.py) captures live packets and detects anomalies (DoS, ARP spoofing, port scans).

- DLP module (proxy_inspector.py) scans HTTP traffic for sensitive data using regex.

- Both modules log events → dlp_events.csv.

- Encryption layer (crypto.py, encrypted_logger.py) encrypts logs into encrypted_logs.csv.

- Flask app (app.py) streams live alerts to the frontend and decrypts logs for viewing.

- Frontend (index.html, logs.html) visualizes real-time and historical data with dynamic color-coding.

🖥️ Running the Project
1. Clone the Repository
git clone https://github.com/gayatri-sn/Network-Guard.git
cd Network-Guard

2. Generate Encryption Key (if not exists)
python crypto.py

3. Run the Flask Dashboard
python app.py

Dashboard runs at → http://127.0.0.1:5000

4. Start IDS Module (command prompt/ powershell as admin)
python ids_module.py

5. Run the Proxy Inspector (DLP)
mitmweb -s proxy.py

**Dashboard Preview**
Page	Description
/	Live alerts feed (real-time IDS & DLP events)
/logs	Decrypted log viewer (color-coded entries)

IDS Alerts — Intrusion/Attack detections
DLP Alerts — Sensitive data transmission detections

**Testing**

Use the following simulation scripts to test individual modules:

test_port_scan.py → triggers port scan detection

test_dos_flood.py → simulates DoS attack

test_arp_direct.py → checks ARP spoof detection

test_form.html → tests DLP regex detection via HTTP POST





 C:\Users\gayat\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages

 "C:\Users\gayat\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\mitmweb.exe"