from blockchain import Blockchain
from decryptor import decrypt_block_data
import json

OUTPUT_FILE = "decrypted_blockchain.txt"

def view_decrypted_blockchain(blockchain, save_to_file=True):
    output_lines = []

    for block in blockchain.chain:
        block_output = []
        block_output.append("\n=== BLOCK ===")
        block_output.append(f"Index: {block.index}")
        block_output.append(f"Timestamp: {block.timestamp}")
        block_output.append(f"Hash: {block.hash}")
        block_output.append(f"Previous Hash: {block.previous_hash}")
        
        if block.index == 0:
            block_output.append("Genesis Block (no encrypted data)")
        else:
            try:
                data = decrypt_block_data(block.data)
                session_info = json.loads(data)

                for key, value in session_info.items():
                    if isinstance(value, dict):
                        block_output.append(f"{key}:")
                        for sub_key, sub_value in value.items():
                            block_output.append(f"  {sub_key}: {sub_value}")
                    else:
                        block_output.append(f"{key}: {value}")
            except Exception as e:
                block_output.append(f"Could not decrypt: {e}")

        # Print and collect output
        for line in block_output:
            print(line)
        output_lines.extend(block_output)

    if save_to_file:
        with open(OUTPUT_FILE, "w") as f:
            f.write("\n".join(output_lines))
        print(f"\n✅ Decrypted blockchain saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    blockchain = Blockchain()
    blockchain.load_chain("blockchain.txt")
    view_decrypted_blockchain(blockchain)
