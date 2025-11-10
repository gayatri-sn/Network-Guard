# proxy_inspector.py — DLP module with Encryption + Unified Dashboard Logging (updated)
import re
import os
import csv
import time
from datetime import datetime
from urllib.parse import unquote_plus

# --- Base paths (use absolute paths to avoid working-dir mismatches) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "dlp_events.csv")
ENCRYPTED_LOG_FILE = os.path.join(BASE_DIR, "encrypted_logs.csv")

# Optional encrypted logger (keeps backward compatibility)
try:
    import encrypted_logger  # type: ignore
    ENCRYPTED_LOGGER_AVAILABLE = True
except Exception:
    ENCRYPTED_LOGGER_AVAILABLE = False

# --- REGEX PATTERNS ---
REGEX_PATTERNS = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "Phone Number": r"\b(?:(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}|(?<!\d)\d{10}(?!\d))\b",
    "GPS Coordinate": r"\b[-+]?(?:[1-8]?\d\.\d{2,}|90\.0{2,}),\s*[-+]?(?:180\.0{2,}|(?:(?:1[0-7]\d)|(?:[1-9]?\d))\.\d{2,})\b",
}

PROCESSING_ORDER = ["Credit Card", "Email", "Phone Number", "GPS Coordinate"]

# --- De-duplication Cache ---
RECENTLY_SEEN = {}
CACHE_EXPIRATION_SECONDS = 15  # Ignore duplicates for 15 seconds

# --- CSV header ---
CSV_HEADER = [
    "Timestamp",
    "Source_IP",
    "Destination_IP",
    "Data_Type",
    "Matched_Content",
    "Source_URL",
    "SourceType",
]

# --- Encryption helpers (Fernet via crypto.py) ---
from crypto import load_key, encrypt_data, generate_key, KEY_FILE  # type: ignore


def ensure_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    key = load_key()
    if not key:
        raise RuntimeError("Failed to load Fernet key")
    return key


def encrypt_dlp_file():
    """
    Read LOG_FILE (plaintext), encrypt its bytes and atomically write
    to ENCRYPTED_LOG_FILE. If no plaintext file exists, do nothing.
    """
    if not os.path.exists(LOG_FILE):
        # nothing to encrypt yet
        return

    try:
        key = ensure_key()
        with open(LOG_FILE, "rb") as f:
            plain = f.read()

        encrypted = encrypt_data(plain, key)
        tmp = ENCRYPTED_LOG_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted)
        os.replace(tmp, ENCRYPTED_LOG_FILE)
        print(f"[ENCRYPT] {ENCRYPTED_LOG_FILE} updated ({len(plain)} bytes encrypted).")
    except Exception as e:
        print(f"[ENCRYPT ERROR] Failed to encrypt DLP file: {e}")


# --- CSV setup and logging ---
def setup_csv():
    """Create the plaintext fallback CSV if needed."""
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
        print(f"[*] Logging DLP events to {LOG_FILE}")
    except Exception as e:
        print(f"[SETUP ERROR] Could not create {LOG_FILE}: {e}")


def mirror_to_plain_csv(timestamp, src_ip, dst_ip, data_type, matched_content, url):
    """
    Append a plaintext copy of the event to LOG_FILE so dashboards/watchers using
    the plaintext file can pick up alerts in real-time.
    """
    try:
        file_exists = os.path.exists(LOG_FILE)
        with open(LOG_FILE, "a", newline="", encoding="utf-8", errors="ignore") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(CSV_HEADER)
            writer.writerow([timestamp, src_ip, dst_ip, data_type, matched_content, url, "DLP"])
        # Update encrypted copy as well so decrypted logs page matches plaintext
        try:
            encrypt_dlp_file()
        except Exception as e:
            print(f"[ENCRYPT ERROR] while mirroring to plaintext: {e}")
        print(f"[DLP MIRROR] Appended to {LOG_FILE}")
    except Exception as e:
        print(f"[DLP ERROR] Failed to write to {LOG_FILE}: {e}")


def log_event(timestamp, src_ip, dst_ip, data_type, matched_content, url):
    print(f"[DEBUG] log_event() called for {data_type} from {src_ip}")

    try:
        if ENCRYPTED_LOGGER_AVAILABLE:
            # Use custom encrypted logger (producer). Keep that behavior,
            # but also mirror plaintext for dashboard alert feed.
            try:
                encrypted_logger.write_encrypted_log(
                    timestamp, src_ip, dst_ip, data_type, matched_content, url
                )
                print(f"[DLP LOGGED - ENC_LOGGER] {data_type} from {src_ip}")
            except Exception as e:
                print(f"[ENCRYPTED_LOGGER ERROR] {e}")

            # Mirror to plaintext CSV so dashboard alert stream has data.
            try:
                mirror_to_plain_csv(timestamp, src_ip, dst_ip, data_type, matched_content, url)
            except Exception as e:
                print(f"[DLP ERROR] Mirror to plaintext failed: {e}")

        else:
            # Fallback: write plaintext CSV and immediately update encrypted file.
            try:
                file_exists = os.path.exists(LOG_FILE)
                with open(LOG_FILE, "a", newline="", encoding="utf-8", errors="ignore") as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow(CSV_HEADER)
                    writer.writerow([timestamp, src_ip, dst_ip, data_type, matched_content, url, "DLP"])
            except Exception as e:
                print(f"[DLP ERROR] Could not write plaintext log: {e}")

            # Immediately encrypt the plaintext log so encrypted_logs.csv reflects latest entries.
            try:
                encrypt_dlp_file()
            except Exception as e:
                print(f"[ENCRYPT ERROR] {e}")

            print(f"[DLP LOGGED] {data_type} detected ({matched_content}) from {src_ip}")
    except Exception as e:
        print(f"[DLP ERROR] Could not log event: {e}")


# --- Terminal alert helper ---
def alert(flow, data_type, matched_content, context):
    """Print alert to terminal (keeps the original textual alert)."""
    try:
        url = flow.request.pretty_url
    except Exception:
        url = "N/A"
    print("\n" + "=" * 70)
    print(f"🚨 DLP ALERT! Detected {data_type}: '{matched_content}'")
    print(f"   Context: ...{context}...")
    print(f"   Source URL: {url}")
    print("=" * 70 + "\n")


# --- mitmproxy addon class ---
class DLPInspector:
    def response(self, flow):
        try:
            content_type = flow.response.headers.get("Content-Type", "")
            # quick content-type filter
            if not any(x in content_type for x in ["text", "json", "javascript"]):
                return

            content = flow.response.get_text()
            if not content:
                return

            searchable_payload = unquote_plus(content)

            for data_type in PROCESSING_ORDER:
                pattern = REGEX_PATTERNS[data_type]
                for match in re.finditer(pattern, searchable_payload):
                    matched_text = match.group(0)
                    current_time = time.time()

                    # dedupe by (matched_text, host)
                    cache_key = (matched_text, flow.request.host)
                    if cache_key in RECENTLY_SEEN and current_time - RECENTLY_SEEN[cache_key] < CACHE_EXPIRATION_SECONDS:
                        continue
                    RECENTLY_SEEN[cache_key] = current_time

                    # context snippet
                    start = max(0, match.start() - 25)
                    end = min(len(searchable_payload), match.end() + 25)
                    context_snippet = searchable_payload[start:end].replace("\n", " ")

                    # gather metadata
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    src_ip = flow.client_conn.address[0] if hasattr(flow, "client_conn") and flow.client_conn else "N/A"
                    dst_ip = flow.server_conn.address[0] if hasattr(flow, "server_conn") and flow.server_conn else "N/A"
                    url = flow.request.pretty_url if hasattr(flow.request, "pretty_url") else "N/A"

                    # alert + log
                    alert(flow, data_type, matched_text, context_snippet)
                    log_event(timestamp, src_ip, dst_ip, data_type, matched_text, url)

                    # replace first occurrence in the searchable payload copy (optional)
                    searchable_payload = searchable_payload.replace(matched_text, "*" * len(matched_text), 1)

        except Exception as e:
            print(f"[DLP ERROR] Exception during scan: {e}")


# --- Initialization ---
setup_csv()
addons = [DLPInspector()]
