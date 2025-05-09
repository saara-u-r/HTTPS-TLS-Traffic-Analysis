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
        self.nonce = 0
        self.signature = None

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "data": self.encrypted_data.hex(),
            "key": self.encrypted_sym_key.hex(),
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return SHA256.new(block_string).hexdigest()

    def mine_block(self, difficulty=2):
        while self.calculate_hash()[:difficulty] != "0" * difficulty:
            self.nonce += 1

    def sign_block(self, private_key_pem):
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(self.calculate_hash().encode())
        self.signature = pkcs1_15.new(key).sign(h)

    def verify(self, public_key_pem):
        if self.calculate_hash()[:2] != "00":
            return False
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(self.calculate_hash().encode())
        try:
            pkcs1_15.new(key).verify(h, self.signature)
            return True
        except:
            return False

class Blockchain:  # THIS CLASS MUST BE PRESENT
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        genesis = Block(0, "Genesis", "0", "0")
        genesis.signature = "Genesis"
        return genesis

    def add_block(self, encrypted_data, encrypted_key, private_key_pem):
        previous_hash = self.chain[-1].calculate_hash()
        block = Block(len(self.chain), encrypted_data, encrypted_key, previous_hash)
        block.mine_block()
        block.sign_block(private_key_pem)
        self.chain.append(block)