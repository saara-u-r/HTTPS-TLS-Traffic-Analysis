import pyshark
from encryptor import encrypt_packet_data
from blockchain import Blockchain
from visualizer import print_block
import geoip2.database
import json

blockchain = Blockchain()
reader = geoip2.database.Reader("GeoLite2-City.mmdb")  # Path to your MaxMind DB

def get_geo_info(ip):
    try:
        response = reader.city(ip)
        return {
            "Country": response.country.name,
            "City": response.city.name,
            "Organization": response.traits.autonomous_system_organization,
            "Continent": response.continent.name,
            "Region": response.subdivisions[0].name if response.subdivisions else None
        }
    except Exception as e:
        return {
            "Country": "Unknown",
            "City": "Unknown",
            "Organization": "Unknown",
            "Continent": "Unknown",
            "Region": "Unknown"
        }

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

            geo_info = get_geo_info(dst)

            session_info = {
                "Time": timestamp,
                "Source": src,
                "Destination": dst,
                "Protocol": protocol,
                "Length": length,
                "Info": info,
                "GeoIP": geo_info
            }

            encrypted_data = encrypt_packet_data(json.dumps(session_info))
            block = blockchain.add_block(encrypted_data)
            print_block(block)
            blockchain.save_chain("blockchain.txt")

        except Exception as e:
            print("Error parsing packet:", e)

if __name__ == "__main__":
    capture_tls_packets()
