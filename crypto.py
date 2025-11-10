import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

def generate_key():
    """Generates a new Fernet key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print(f"Encryption key generated and saved to {KEY_FILE}")

def load_key():
    """Loads the Fernet key from the file."""
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Error: {KEY_FILE} not found. Please run generate_encrypted_logs.py first.")
        return None

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts bytes data using the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts bytes data using the provided key."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data

if __name__ == '__main__':
    if not os.path.exists(KEY_FILE):
        generate_key()
        print("Key generated successfully for use in app.py and generate_encrypted_logs.py.")
    else:
        print(f"Key already exists at {KEY_FILE}. Skipping generation.")
