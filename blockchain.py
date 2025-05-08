import hashlib
import json
import time
import rsa
import os
from cryptography.fernet import Fernet

# Setup encryption key
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # Encrypted TLS metadata
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        self.signature = None

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def sign_block(self, private_key):
        message = f'{self.index}{self.timestamp}{self.data}{self.previous_hash}'.encode()
        self.signature = rsa.sign(message, private_key, 'SHA-256')

    def verify_signature(self, public_key):
        try:
            message = f'{self.index}{self.timestamp}{self.data}{self.previous_hash}'.encode()
            rsa.verify(message, self.signature, public_key)
            return True
        except rsa.VerificationError:
            return False

    def decrypt_data(self):
        try:
            decrypted = fernet.decrypt(self.data.encode()).decode()
            return json.loads(decrypted)
        except Exception as e:
            return f"[Decryption failed] {e}"

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_data_dict, private_key):
        encrypted_data = fernet.encrypt(json.dumps(new_data_dict).encode()).decode()
        prev_block = self.get_latest_block()
        new_block = Block(
            index=prev_block.index + 1,
            timestamp=time.time(),
            data=encrypted_data,
            previous_hash=prev_block.hash
        )
        new_block.sign_block(private_key)
        self.chain.append(new_block)

    def is_chain_valid(self, public_key):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            if curr.hash != curr.calculate_hash():
                return False
            if curr.previous_hash != prev.hash:
                return False
            if not curr.verify_signature(public_key):
                return False
        return True

    def export_to_json(self, filename="blockchain_log.json"):
        export_data = []
        for block in self.chain:
            export_data.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'data': block.data,
                'decrypted_data': block.decrypt_data() if isinstance(block, Block) else None,
                'previous_hash': block.previous_hash,
                'hash': block.hash,
                'signature': block.signature.hex() if block.signature else None
            })
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=4)
        print(f"Blockchain exported to {os.path.abspath(filename)}")

# Example usage
if __name__ == "__main__":
    (public_key, private_key) = rsa.newkeys(512)
    tls_chain = Blockchain()

    # Add encrypted TLS metadata blocks
    tls_chain.add_block({
        "client_ip": "192.168.1.2",
        "server_ip": "172.217.167.78",
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "certificate_fingerprint": "F4:23:91:A3..."
    }, private_key)

    tls_chain.add_block({
        "client_ip": "192.168.1.3",
        "server_ip": "142.250.185.14",
        "tls_version": "TLS 1.2",
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "certificate_fingerprint": "E1:AB:94:77..."
    }, private_key)

    # Print full chain
    for block in tls_chain.chain:
        print(f"\n🔐 Block #{block.index}")
        print(f"Encrypted Data: {block.data}")
        print(f"Decrypted Data: {block.decrypt_data()}")
        print(f"Hash: {block.hash}")
        print(f"Signature Valid: {block.verify_signature(public_key)}")

    tls_chain.export_to_json()
