from Crypto.PublicKey import RSA
from blockchain import Blockchain
from encryption_utils import encrypt_metadata, decrypt_metadata

# Generate keys (using pycryptodome)
key = RSA.generate(2048)
public_key_pem = key.publickey().export_key()  # PEM format
private_key_pem = key.export_key()             # PEM format

tls_chain = Blockchain()

# Sample sessions
sessions = [
    {
        "client_ip": "192.168.1.2",
        "server_ip": "172.217.160.78",
        "tls_version": "TLS 1.3"
    },
    {
        "client_ip": "192.168.1.3",
        "server_ip": "142.250.185.14",
        "tls_version": "TLS 1.2"
    }
]

# Process sessions
for session in sessions:
    enc_data, enc_key = encrypt_metadata(session, public_key_pem)
    tls_chain.add_block(enc_data, enc_key, private_key_pem)  # Ensure blockchain.py uses PEM keys

# Verify chain
for block in tls_chain.chain[1:]:
    print(f"Block #{block.index}: {decrypt_metadata(block.encrypted_data, block.encrypted_sym_key, private_key_pem)}")