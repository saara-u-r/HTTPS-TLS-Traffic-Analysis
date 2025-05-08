from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json

class Block:
    def __init__(self, index, encrypted_data, encrypted_key, previous_hash):
        self.index = index
        self.encrypted_data = encrypted_data
        self.encrypted_sym_key = encrypted_key
        self.previous_hash = previous_hash
        self.signature = None

    def hash(self):
        """Generate SHA-256 hash of the block's contents (excluding signature)."""
        block_contents = {
            'index': self.index,
            'encrypted_data': self.encrypted_data.hex() if isinstance(self.encrypted_data, bytes) else self.encrypted_data,
            'encrypted_sym_key': self.encrypted_sym_key.hex() if isinstance(self.encrypted_sym_key, bytes) else self.encrypted_sym_key,
            'previous_hash': self.previous_hash
        }
        return SHA256.new(json.dumps(block_contents, sort_keys=True).encode()).hexdigest()

    def sign_block(self, private_key_pem):
        """Sign block using RSA-PKCS#1.5."""
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(self.hash().encode())
        self.signature = pkcs1_15.new(key).sign(h)

    def verify_signature(self, public_key_pem):
        """Verify signature."""
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(self.hash().encode())
        try:
            pkcs1_15.new(key).verify(h, self.signature)
            return True
        except (ValueError, TypeError):
            return False

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """Create the first block in the chain."""
        genesis = Block(0, "Genesis", "0", "0")
        genesis.signature = "Genesis"  # No signing for genesis block
        return genesis

    def add_block(self, encrypted_data, encrypted_key, private_key_pem):
        """Add a new block to the chain."""
        previous_hash = self.chain[-1].hash()
        block = Block(len(self.chain), encrypted_data, encrypted_key, previous_hash)
        block.sign_block(private_key_pem)
        self.chain.append(block)