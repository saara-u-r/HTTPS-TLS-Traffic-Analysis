def print_block(block):
    print("\n=== NEW BLOCK ADDED ===")
    print(f"Index: {block.index}")
    print(f"Timestamp: {block.timestamp}")
    print(f"Hash: {block.hash}")
    print(f"Previous Hash: {block.previous_hash}")
    print(f"Encrypted Data: {block.data}")
    print("=======================\n")
