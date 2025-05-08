from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json
import os

def pad(data):
    """PKCS#7 padding for AES-CBC."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS#7 padding."""
    if len(data) == 0 or data[-1] > 16:
        raise ValueError("Invalid padding!")
    return data[:-data[-1]]

def encrypt_metadata(metadata_dict, public_key):
    """
    Encrypts metadata using hybrid encryption (AES-256-CBC + RSA-OAEP).
    Args:
        metadata_dict: Dictionary to encrypt.
        public_key: RSA public key (PEM format).
    Returns:
        (iv + ciphertext, encrypted_aes_key)
    """
    # Convert metadata to JSON bytes
    metadata_json = json.dumps(metadata_dict).encode('utf-8')

    # Generate random AES key and IV
    aes_key = get_random_bytes(32)  # AES-256 (32 bytes)
    iv = get_random_bytes(16)       # AES block size = 16 bytes

    # Encrypt data with AES-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(metadata_json))

    # Encrypt AES key with RSA-OAEP
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return iv + ciphertext, encrypted_aes_key

def decrypt_metadata(encrypted_data, encrypted_aes_key, private_key):
    """
    Decrypts metadata encrypted by `encrypt_metadata`.
    Args:
        encrypted_data: IV + AES ciphertext.
        encrypted_aes_key: RSA-encrypted AES key.
        private_key: RSA private key (PEM format).
    Returns:
        Decrypted metadata dictionary.
    """
    # Decrypt AES key with RSA-OAEP
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Decrypt data with AES-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher_aes.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded)

    return json.loads(decrypted.decode('utf-8'))