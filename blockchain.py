import hashlib
import json
import time
import rsa

class Block:
    def __init__(self, index, timestamp, encrypted_data, encrypted_sym_key, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.encrypted_data = encrypted_data  # Encrypted TLS session metadata
        self.encrypted_sym_key = encrypted_sym_key  # AES key encrypted with RSA
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        self.signature = None

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'encrypted_data': self.encrypted_data.hex(),
            'encrypted_sym_key': self.encrypted_sym_key.hex(),
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def sign_block(self, private_key):
        message = f'{self.index}{self.timestamp}{self.encrypted_data.hex()}{self.encrypted_sym_key.hex()}{self.previous_hash}'.encode()
        self.signature = rsa.sign(message, private_key, 'SHA-256')

    def verify_signature(self, public_key):
        try:
            message = f'{self.index}{self.timestamp}{self.encrypted_data.hex()}{self.encrypted_sym_key.hex()}{self.previous_hash}'.encode()
            rsa.verify(message, self.signature, public_key)
            return True
        except rsa.VerificationError:
            return False

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), b"Genesis", b"Genesis", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, encrypted_data, encrypted_sym_key, private_key):
        prev_block = self.get_latest_block()
        new_block = Block(
            index=prev_block.index + 1,
            timestamp=time.time(),
            encrypted_data=encrypted_data,
            encrypted_sym_key=encrypted_sym_key,
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
                'encrypted_data': block.encrypted_data.hex(),
                'encrypted_sym_key': block.encrypted_sym_key.hex(),
                'previous_hash': block.previous_hash,
                'hash': block.hash,
                'signature': block.signature.hex() if block.signature else None
            })
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=4)
