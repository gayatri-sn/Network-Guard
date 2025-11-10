import os
import time
import csv
from io import StringIO
from flask import Flask, render_template, Response, jsonify, request
from crypto import load_key, decrypt_data, KEY_FILE
from cryptography.fernet import Fernet

app = Flask(__name__)

# ===============================================================
#  FILE PATHS
# ===============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_LOG_FILE = os.path.join(BASE_DIR, "encrypted_logs.csv")   # For decrypted logs page
PLAINTEXT_LOG_FILE = os.path.join(BASE_DIR, "dlp_events.csv")       # For live alerts
KEY = load_key() if os.path.exists(KEY_FILE) else None


# ===============================================================
#  HELPER FUNCTIONS
# ===============================================================
def decrypt_csv_file(filepath):
    """Decrypts the entire encrypted CSV file and returns parsed data."""
    if not os.path.exists(filepath):
        return {"error": f"Encrypted log file not found: {filepath}", "header": [], "data": []}

    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
        if not KEY:
            return {"error": "Encryption key not found", "header": [], "data": []}

        decrypted_bytes = decrypt_data(encrypted_data, KEY)
        decrypted_string = decrypted_bytes.decode("utf-8")

        csv_file = StringIO(decrypted_string)
        csv_reader = csv.reader(csv_file)
        header = next(csv_reader)
        data = list(csv_reader)
        return {"error": None, "header": header, "data": data}
    except Exception as e:
        return {"error": f"Decryption failed: {e}", "header": [], "data": []}


def tail_plain_csv(file_path):
    """Continuously yield new lines appended to the plaintext CSV (for live alert streaming)."""
    if not os.path.exists(file_path):
        yield f"data: ⚠️ Log file not found: {file_path}\n\n"
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield f"data: {line.strip()}\n\n"


# ===============================================================
#  ROUTES
# ===============================================================
@app.route("/")
def home():
    """Main dashboard page showing live unified alerts."""
    return render_template("index.html")


@app.route("/logs")
def logs():
    """Decrypted logs page (reads encrypted CSV)."""
    logs_data = decrypt_csv_file(ENCRYPTED_LOG_FILE)
    return render_template("logs.html", **logs_data)


# ===============================================================
#  SERVER-SENT EVENTS (LIVE ALERT STREAM)
# ===============================================================
def generate_unified_alerts():
    """
    Streams both DLP and IDS alerts from the plaintext log file (dlp_events.csv).
    The frontend JS splits color and formatting info from each SSE message.
    """
    if not os.path.exists(PLAINTEXT_LOG_FILE):
        yield f"data: ⚠️ No log file found: {PLAINTEXT_LOG_FILE}\n\n"
        return

    with open(PLAINTEXT_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            try:
                parts = next(csv.reader([line]))
                if len(parts) < 7:
                    continue

                timestamp, src, dst, dtype, matched, url, source = parts
                source = source.strip().upper()

                if source == "IDS":
                    color = "red"
                    emoji = "🛡️"
                    prefix = "[IDS ALERT]"
                else:
                    color = "blue"
                    emoji = "🧩"
                    prefix = "[DLP ALERT]"

                msg = f"{emoji} [{timestamp}] {dtype} - {matched} (Src: {src} → {dst})"
                yield f"data: {color.upper()}::{prefix} {msg}\n\n"
            except Exception as e:
                yield f"data: ⚠️ Stream error: {e}\n\n"
                time.sleep(1)


@app.route("/stream_alerts")
def stream_alerts():
    """SSE endpoint for live unified alerts (now reading from plaintext file)."""
    return Response(generate_unified_alerts(), mimetype="text/event-stream")


# ===============================================================
#  IDS ALERT INGESTION ENDPOINT (optional)
# ===============================================================
@app.route("/ingest_alert", methods=["POST"])
def ingest_alert():
    """
    Receives alerts from ids_module.py as JSON and encrypts them into the unified encrypted log.
    This is optional — IDS already logs via encrypted_logger if running locally.
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    try:
        if not KEY:
            return jsonify({"status": "error", "message": "Encryption key not found"}), 500

        fernet = Fernet(KEY)
        line = ",".join([
            data.get("timestamp", ""),
            data.get("source_ip", ""),
            "-",
            data.get("data_type", ""),
            data.get("details", ""),
            "-",
            "IDS"
        ])
        encrypted_line = fernet.encrypt(line.encode("utf-8"))

        with open(ENCRYPTED_LOG_FILE, "ab") as f:
            f.write(encrypted_line + b"\n")

        print(f"[IDS] Logged encrypted alert: {data.get('data_type')}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[ERROR] Failed to write IDS alert: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# ===============================================================
#  MAIN ENTRY POINT
# ===============================================================
if __name__ == "__main__":
    if not KEY:
        print("=" * 70)
        print("⚠️ Missing secret.key — please run crypto.py to generate one.")
        print("=" * 70)

    print("🚀 Flask Dashboard running → http://127.0.0.1:5000")
    app.run(debug=True)
