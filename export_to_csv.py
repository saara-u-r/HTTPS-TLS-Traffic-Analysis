import csv
import json
import os
from blockchain import Blockchain
from decryptor import decrypt_block_data

CSV_FILE = "sessions.csv"
BLOCKCHAIN_FILE = "blockchain.txt"

# Define all expected output columns
CSV_COLUMNS = [
    "Stream ID", "Start Time", "End Time", "Duration (s)",
    "Source", "Destination", "Resolved Hostname", "Packet Count",
    "Country", "City", "Organization", "Region", "Continent",
    "TLS Record Version", "TLS Handshake Type", "TLS Version",
    "TLS Cipher Suite", "TLS SNI (Server Name)", "TLS Supported Groups",
    "TLS EC Point Formats", "TLS Key Share Group", "TLS Session ID",
    "TLS Random", "TLS ALPN"
]

def flatten_session(session):
    flat = {}
    flat["Stream ID"] = session.get("Stream ID", "N/A")
    flat["Start Time"] = session.get("Start Time", "N/A")
    flat["End Time"] = session.get("End Time", "N/A")
    flat["Duration (s)"] = session.get("Duration (s)", "N/A")
    flat["Source"] = session.get("Source", "N/A")
    flat["Destination"] = session.get("Destination", "N/A")
    flat["Resolved Hostname"] = session.get("Resolved Hostname", "N/A")
    flat["Packet Count"] = session.get("Packet Count", "N/A")

    geo = session.get("GeoIP", {})
    flat["Country"] = geo.get("Country", "N/A")
    flat["City"] = geo.get("City", "N/A")
    flat["Organization"] = geo.get("Organization", "N/A")
    flat["Region"] = geo.get("Region", "N/A")
    flat["Continent"] = geo.get("Continent", "N/A")

    tls = session.get("TLS Metadata", {})
    flat["TLS Record Version"] = tls.get("TLS Record Version", "N/A")
    flat["TLS Handshake Type"] = tls.get("TLS Handshake Type", "N/A")
    flat["TLS Version"] = tls.get("TLS Version", "N/A")
    flat["TLS Cipher Suite"] = tls.get("TLS Cipher Suite", "N/A")
    flat["TLS SNI (Server Name)"] = tls.get("TLS SNI (Server Name)", "N/A")
    flat["TLS Supported Groups"] = tls.get("TLS Supported Groups", "N/A")
    flat["TLS EC Point Formats"] = tls.get("TLS EC Point Formats", "N/A")
    flat["TLS Key Share Group"] = tls.get("TLS Key Share Group", "N/A")
    flat["TLS Session ID"] = tls.get("TLS Session ID", "N/A")
    flat["TLS Random"] = tls.get("TLS Random", "N/A")
    flat["TLS ALPN"] = tls.get("TLS ALPN", "N/A")

    return flat

def load_existing_stream_ids(csv_path):
    if not os.path.exists(csv_path):
        return set()
    existing_ids = set()
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing_ids.add(row.get("Stream ID"))
    return existing_ids

def export_to_csv():
    blockchain = Blockchain()
    blockchain.load_chain(BLOCKCHAIN_FILE)

    existing_ids = load_existing_stream_ids(CSV_FILE)
    new_rows = []

    for block in blockchain.chain:
        if block.index == 0:
            continue  # skip genesis block
        try:
            decrypted = decrypt_block_data(block.data)
            session = json.loads(decrypted)
            stream_id = str(session.get("Stream ID", "N/A"))
            if stream_id in existing_ids:
                continue
            row = flatten_session(session)
            new_rows.append(row)
        except Exception as e:
            print(f"[!] Failed to process block {block.index}: {e}")

    if not new_rows:
        print("✅ No new sessions to export.")
        return

    write_header = not os.path.exists(CSV_FILE)

    with open(CSV_FILE, "a", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerows(new_rows)

    print(f"✅ Exported {len(new_rows)} new session(s) to {CSV_FILE}")

if __name__ == "__main__":
    export_to_csv()
