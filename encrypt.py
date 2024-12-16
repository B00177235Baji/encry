from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import json
import time

# Constants
SALT_SIZE = 16  # Size of salt in bytes
KEY_SIZE = 16   # AES-128 = 16 bytes
ITERATIONS = 100000  # PBKDF2 iterations

def derive_key(password, salt):
    """Derive AES key using PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def pad(data):
    """Apply PKCS7 padding."""
    padding_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    """Remove PKCS7 padding."""
    padding_length = data[-1]
    if padding_length > AES.block_size:
        raise ValueError("Invalid padding length")
    return data[:-padding_length]

def encrypt(plaintext, password):
    """Encrypt plaintext using AES with integrity check."""
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC)  # Use CBC mode
    ciphertext = cipher.encrypt(pad(plaintext))
    
    # HMAC for integrity
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(cipher.iv + ciphertext)
    
    # Combine salt, IV, ciphertext, and HMAC
    result = base64.b64encode(salt + cipher.iv + ciphertext + hmac.digest())
    return result

def decrypt(encrypted, password):
    """Decrypt ciphertext and verify integrity."""
    encrypted = base64.b64decode(encrypted)
    salt = encrypted[:SALT_SIZE]
    iv = encrypted[SALT_SIZE:SALT_SIZE + AES.block_size]
    ciphertext = encrypted[SALT_SIZE + AES.block_size:-SHA256.digest_size]
    received_hmac = encrypted[-SHA256.digest_size:]
    
    # Derive the same key
    key = derive_key(password.encode(), salt)
    
    # Verify HMAC
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + ciphertext)
    hmac.verify(received_hmac)
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

if _name_ == "_main_":
    print("Select input type:")
    print("a) Manual string input")
    print("b) File encryption")
    print("c) JSON data")
    print("d) Binary file (e.g., image)")
    choice = input("Enter your choice (a/b/c/d): ").strip().lower()

    password = input("Enter a strong password: ").strip()

    if choice == "a":
        data = input("Enter the string to encrypt: ").encode()
    elif choice == "b":
        file_path = input("Enter the path to the file: ").strip()
        with open(file_path, "rb") as f:
            data = f.read()
    elif choice == "c":
        json_data = input("Enter JSON data (e.g., {'key':'value'}): ").strip()
        data = json.dumps(json.loads(json_data)).encode()  # Convert JSON to bytes
    elif choice == "d":
        binary_path = input("Enter the path to the binary file (e.g., image.jpg): ").strip()
        with open(binary_path, "rb") as f:
            data = f.read()
    else:
        print("Invalid choice. Exiting.")
        exit()

    # Encryption
    start_time = time.time()
    encrypted_data = encrypt(data, password)
    encryption_time = time.time() - start_time
    print(f"\nEncrypted Data: {encrypted_data.decode()} (in {encryption_time:.6f} seconds)")

    # Decryption
    start_time = time.time()
    decrypted_data = decrypt(encrypted_data, password)
    decryption_time = time.time() - start_time
    print(f"\nDecrypted Data: {decrypted_data.decode()} (in {decryption_time:.6f} seconds)")
