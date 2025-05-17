from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

RSA_PRIVATE_KEY_FILE = "rsa_private.pem"

def decrypt_block_data(encrypted_data_b64):
    with open(RSA_PRIVATE_KEY_FILE, 'rb') as f:
        private_key = RSA.import_key(f.read())

    data = base64.b64decode(encrypted_data_b64)

    enc_aes_key = data[:256]
    nonce = data[256:272]
    tag = data[272:288]
    ciphertext = data[288:]
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
