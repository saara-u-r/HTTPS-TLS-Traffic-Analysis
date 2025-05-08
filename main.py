import rsa
from blockchain import Blockchain
from encryption_utils import encrypt_metadata, decrypt_metadata

# Generate RSA keys
(public_key, private_key) = rsa.newkeys(2048)

tls_chain = Blockchain()

# Sample TLS sessions
session1 = {
    "client_ip": "192.168.1.2",
    "server_ip": "172.217.160.78",
    "tls_version": "TLS 1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "certificate_fingerprint": "F4:23:91:A3..."
}
session2 = {
    "client_ip": "192.168.1.3",
    "server_ip": "142.250.185.14",
    "tls_version": "TLS 1.2",
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "certificate_fingerprint": "E1:AB:94:77..."
}

# Encrypt and add blocks
for session in [session1, session2]:
    enc_data, enc_key = encrypt_metadata(session, public_key)
    tls_chain.add_block(enc_data, enc_key, private_key)

# Audit chain
for block in tls_chain.chain[1:]:
    print(f"🔏 Block #{block.index}")
    print(f"✅ Signature Valid: {block.verify_signature(public_key)}")
    print(f"🔓 Decrypted Metadata: {decrypt_metadata(block.encrypted_data, block.encrypted_sym_key, private_key)}\n")

tls_chain.export_to_json()
