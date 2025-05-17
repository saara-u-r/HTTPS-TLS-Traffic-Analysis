import pyshark
from encryptor import encrypt_packet_data
from blockchain import Blockchain
from visualizer import print_block

blockchain = Blockchain()

def capture_tls_packets(interface='Wi-Fi'):
    print("Starting TLS packet capture...")
    capture = pyshark.LiveCapture(interface=interface, display_filter="tls")

    for packet in capture.sniff_continuously():
        try:
            ip_layer = packet.ip if 'IP' in packet else packet.ipv6
            src = ip_layer.src
            dst = ip_layer.dst
            protocol = packet.highest_layer
            length = packet.length
            info = packet.tls.record_content_type if hasattr(packet.tls, 'record_content_type') else "N/A"
            timestamp = packet.sniff_time.isoformat()

            display = {
                "Time": timestamp,
                "Source": src,
                "Destination": dst,
                "Protocol": protocol,
                "Length": length,
                "Info": info
            }

            # Prepare data for encryption
            data_str = str(display)
            encrypted_data = encrypt_packet_data(data_str)

            # Add to blockchain
            block = blockchain.add_block(encrypted_data)
            print_block(block)
            blockchain.save_chain("blockchain.txt")  #Save the updated chain

        except Exception as e:
            print("Error parsing packet:", e)

if __name__ == "__main__":
    capture_tls_packets()
