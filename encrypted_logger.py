# encrypted_logger.py
import os
import csv
import io
from datetime import datetime
from crypto import KEY_FILE, load_key, encrypt_data, decrypt_data

# file on disk that stores the encrypted CSV bytes
ENCRYPTED_LOG_FILE = "encrypted_logs.csv"
# temporary in-memory name used while composing CSV
TEMP_HEADER = ["Timestamp", "Source_IP", "Destination_IP", "Data_Type", "Matched_Content", "Source_URL"]

def init_encrypted_file():
    """Create an encrypted file with header if it doesn't exist."""
    if os.path.exists(ENCRYPTED_LOG_FILE):
        return
    key = load_key()
    if key is None:
        raise FileNotFoundError(f"{KEY_FILE} not found. Generate key first.")
    # create CSV bytes with header
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(TEMP_HEADER)
    plain = buf.getvalue().encode("utf-8")
    enc = encrypt_data(plain, key)
    with open(ENCRYPTED_LOG_FILE, "wb") as f:
        f.write(enc)
    print("[encrypted_logger] Created encrypted log file with header.")

def read_decrypted_rows():
    """Return (header, rows) from the encrypted log file; returns (header, []) if empty."""
    key = load_key()
    if key is None:
        raise FileNotFoundError(f"{KEY_FILE} not found. Generate key first.")
    if not os.path.exists(ENCRYPTED_LOG_FILE):
        return (TEMP_HEADER, [])
    with open(ENCRYPTED_LOG_FILE, "rb") as f:
        encrypted = f.read()
    plain = decrypt_data(encrypted, key)              # bytes -> decrypted bytes
    decoded = plain.decode("utf-8")
    reader = csv.reader(io.StringIO(decoded))
    try:
        header = next(reader)
    except StopIteration:
        return (TEMP_HEADER, [])
    rows = list(reader)
    return (header, rows)

def write_encrypted_rows(header, rows):
    """Given header and rows (list of lists), encrypt and write to disk."""
    key = load_key()
    if key is None:
        raise FileNotFoundError(f"{KEY_FILE} not found. Generate key first.")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    plain = buf.getvalue().encode("utf-8")
    enc = encrypt_data(plain, key)
    with open(ENCRYPTED_LOG_FILE, "wb") as f:
        f.write(enc)

def write_encrypted_log(timestamp: str, src_ip: str, dst_ip: str, data_type: str, matched_content: str, source_url: str):
    """Append a single log row into the encrypted file (reads -> append -> write)."""
    # ensure file exists (with header)
    if not os.path.exists(ENCRYPTED_LOG_FILE):
        init_encrypted_file()

    header, rows = read_decrypted_rows()
    row = [timestamp, src_ip, dst_ip, data_type, matched_content, source_url]
    rows.append(row)
    write_encrypted_rows(header, rows)
    # small console hint for producers
    print(f"[encrypted_logger] Logged event: {data_type} from {src_ip}")
