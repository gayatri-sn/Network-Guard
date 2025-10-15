# proxy_inspector.py (Final Version with De-duplication)

import re
import csv
import os
from datetime import datetime
from urllib.parse import unquote_plus
import time

REGEX_PATTERNS = {
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    'Phone Number': r'\b(?:(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}|(?<!\d)\d{10}(?!\d))\b',
    'GPS Coordinate': r'\b[-+]?(?:[1-8]?\d\.\d{2,}|90\.0{2,}),\s*[-+]?(?:180\.0{2,}|(?:(?:1[0-7]\d)|(?:[1-9]?\d))\.\d{2,})\b'
}
PROCESSING_ORDER = ['Credit Card', 'Email', 'Phone Number', 'GPS Coordinate']


# --- 2. CREATE THE CACHE AND SET EXPIRATION ---
RECENTLY_SEEN = {} # A dictionary to store recent findings
CACHE_EXPIRATION_SECONDS = 15 # Ignore duplicates for 15 seconds


# CSV and Alert functions
LOG_FILE = 'dlp_events.csv'
def setup_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source_IP', 'Destination_IP', 'Data_Type', 'Matched_Content', 'Source_URL'])
    print(f"[*] Logging DLP events to {LOG_FILE}")
def log_to_csv(flow, data_type, matched_content):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src_ip = flow.client_conn.address[0] if flow.client_conn else 'N/A'
    dst_ip = flow.server_conn.address[0] if flow.server_conn else 'N/A'
    url = flow.request.pretty_url
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, data_type, matched_content, url])
def alert(flow, data_type, matched_content, context):
    url = flow.request.pretty_url
    print(f"🚨 DLP ALERT! Detected {data_type}: '{matched_content}'")
    print(f"   Context: ...{context}...")
    print(f"   Source URL: {url}\n")


# --- MITMPROXY ADDON ---
class DLPInspector:
    def response(self, flow):
        # exclusion logic and content type checks
        content_type = flow.response.headers.get("Content-Type", "")
        if "text" in content_type or "json" in content_type or "javascript" in content_type:
            content = flow.response.get_text()
            if not content: return
            searchable_payload = unquote_plus(content)

            for data_type in PROCESSING_ORDER:
                pattern = REGEX_PATTERNS[data_type]
                for match in re.finditer(pattern, searchable_payload):
                    matched_text = match.group(0)
                    
                    # --- 3. IMPLEMENT THE DE-DUPLICATION CHECK ---
                    current_time = time.time()
                    # Create a unique key: (the data itself, the destination domain)
                    cache_key = (matched_text, flow.request.host)

                    # If we've seen this exact key recently, skip it
                    if cache_key in RECENTLY_SEEN and current_time - RECENTLY_SEEN[cache_key] < CACHE_EXPIRATION_SECONDS:
                        continue # Go to the next match, ignoring this duplicate
                    
                    # If it's new, log it and update the cache with the current time
                    RECENTLY_SEEN[cache_key] = current_time
                    # --- END OF DE-DUPLICATION LOGIC ---
                    
                    start = max(0, match.start() - 25)
                    end = min(len(searchable_payload), match.end() + 25)
                    context_snippet = searchable_payload[start:end].replace('\n', ' ')
                    
                    alert(flow, data_type, matched_text, context_snippet)
                    log_to_csv(flow, data_type, matched_text)
                    
                    searchable_payload = searchable_payload.replace(matched_text, '*' * len(matched_text), 1)

setup_csv()
addons = [DLPInspector()]