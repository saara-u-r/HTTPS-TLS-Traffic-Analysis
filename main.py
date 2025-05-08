import rsa
from blockchain import Blockchain
import json

def encrypt_metadata(data, public_key):
    """Encrypt TLS session metadata."""
    data_str = json.dumps(data).encode()
    return rsa.encrypt(data_str, public_key)

def decrypt_metadata(encrypted_data, private_key):
    """Decrypt TLS session metadata."""
    try:
        decrypted = rsa.decrypt(encrypted_data, private_key)
        return json.loads(decrypted.decode())
    except:
        return "Decryption failed"

if __name__ == "__main__":
    # Step 1: Key generation (512-bit for demo, use 2048+ in real use)
    public_key, private_key = rsa.newkeys(512)

    # Step 2: Initialize blockchain
    tls_chain = Blockchain()

    # Step 3: Simulated TLS metadata
    session1 = {
        "client_ip": "192.168.1.2",
        "server_ip": "172.217.167.78",
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

    # Step 4: Encrypt data before storing
    enc1 = encrypt_metadata(session1, public_key)
    enc2 = encrypt_metadata(session2, public_key)

    # Step 5: Add encrypted data to blockchain
    tls_chain.add_block(enc1, private_key)
    tls_chain.add_block(enc2, private_key)

    # Step 6: Verify & Audit
    print("\n📜 Blockchain Audit:\n")
    for block in tls_chain.chain:
        print(f"Block #{block.index}")
        print(f"Hash: {block.hash}")
        is_valid = block.verify_signature(public_key)
        print(f"Signature Valid: {is_valid}")
        if isinstance(block.data, bytes):
            decrypted = decrypt_metadata(block.data, private_key)
            print("Decrypted Metadata:", decrypted)
        else:
            print("Data:", block.data)
        print("-" * 60)

    # Step 7: Export chain
    tls_chain.export_to_json()
