from tls_capture import capture_tls_sessions
from blockchain import Blockchain
from encryption_utils import decrypt_metadata  
from Crypto.PublicKey import RSA  

# Generate keys
key = RSA.generate(2048)
public_key_pem = key.publickey().export_key()  
private_key_pem = key.export_key()             

# Initialize blockchain
tls_chain = Blockchain()

# Capture and process packets
for enc_data, enc_key in capture_tls_sessions(public_key_pem):  
    tls_chain.add_block(enc_data, enc_key, private_key_pem)