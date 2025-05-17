from blockchain import Blockchain
from decryptor import decrypt_block_data

def view_decrypted_blockchain(blockchain):
    for block in blockchain.chain:
        print("\n=== BLOCK ===")
        print(f"Index: {block.index}")
        print(f"Timestamp: {block.timestamp}")
        print(f"Hash: {block.hash}")
        print(f"Previous Hash: {block.previous_hash}")
        
        if block.index == 0:
            print("Genesis Block (no encrypted data)")
            continue

        try:
            data = decrypt_block_data(block.data)
            print(f"Decrypted Data: {data}")
        except Exception as e:
            print(f"Could not decrypt: {e}")


if __name__ == "__main__":
    blockchain = Blockchain()
    blockchain.load_chain("blockchain.txt")  # ✅ Load persisted blockchain
    view_decrypted_blockchain(blockchain)
