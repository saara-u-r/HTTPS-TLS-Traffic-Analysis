from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import os

AES_KEY_FILE = "aes_key.enc"
RSA_PUBLIC_KEY_FILE = "rsa_public.pem"
RSA_PRIVATE_KEY_FILE = "rsa_private.pem"

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(RSA_PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key)
    with open(RSA_PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key)

def encrypt_packet_data(data):
    if not os.path.exists(RSA_PUBLIC_KEY_FILE):
        generate_rsa_keys()

    with open(RSA_PUBLIC_KEY_FILE, 'rb') as f:
        public_key = RSA.import_key(f.read())

    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key + cipher_aes.nonce + tag + ciphertext).decode()
