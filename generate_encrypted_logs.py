# generate_encrypted_logs.py
import os
from crypto import load_key, encrypt_data, generate_key, KEY_FILE

SRC = "dlp_events.csv"
DST = "encrypted_logs.csv"

if not os.path.exists(KEY_FILE):
    generate_key()

key = load_key()
if not key:
    raise SystemExit("failed to load key")

with open(SRC, "rb") as f:
    data = f.read()

enc = encrypt_data(data, key)
with open(DST, "wb") as f:
    f.write(enc)

print("Encrypted", SRC, "→", DST)
