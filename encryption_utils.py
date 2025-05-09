from Crypto.Cipher import AES, PKCS1_OAEP  
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import json

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]] if data else data

def encrypt_metadata(metadata_dict, public_key_pem):
    """Encrypt using AES-256-CBC + RSA-OAEP"""
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(json.dumps(metadata_dict).encode()))
    
    rsa_key = RSA.import_key(public_key_pem)  # Accepts PEM string
    encrypted_key = PKCS1_OAEP.new(rsa_key).encrypt(aes_key)
    
    return iv + ciphertext, encrypted_key

def decrypt_metadata(encrypted_data, encrypted_key, private_key_pem):
    """Decrypt hybrid encrypted data"""
    rsa_key = RSA.import_key(private_key_pem)
    aes_key = PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key)
    
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    decrypted = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext))
    
    return json.loads(decrypted.decode())