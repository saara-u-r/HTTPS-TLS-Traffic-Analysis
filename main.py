import pyshark
import threading
import time
import socket
import ipaddress
from encryptor import encrypt_packet_data
from blockchain import Blockchain
from visualizer import print_block
import geoip2.database
import json

blockchain = Blockchain()
reader = geoip2.database.Reader("GeoLite2-City.mmdb")

# DNS A/AAAA cache: ip → (domain, timestamp)
dns_cache = {}
DNS_TTL_SECONDS = 60

# Active session tracker: stream_id → session dict
stream_sessions = {}
SESSION_TIMEOUT = 5  # seconds of inactivity

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
    except:
        return {
            "Country": "Unknown",
            "City": "Unknown",
            "Organization": "Unknown",
            "Continent": "Unknown",
            "Region": "Unknown"
        }

def reverse_dns_lookup(ip):
    try:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            return "Private IP"
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def safe_extract(layer, attr):
    try:
        return getattr(layer, attr)
    except:
        return "N/A"

def extract_tls_metadata(tls_layer):
    return {
        "TLS Record Version": safe_extract(tls_layer, "record_version"),
        "TLS Handshake Type": safe_extract(tls_layer, "handshake_type"),
        "TLS Version": safe_extract(tls_layer, "handshake_version"),
        "TLS Cipher Suite": safe_extract(tls_layer, "handshake_ciphersuite"),
        "TLS SNI (Server Name)": safe_extract(tls_layer, "handshake_extensions_server_name"),
        "TLS Supported Groups": safe_extract(tls_layer, "handshake_extensions_supported_group"),
        "TLS EC Point Formats": safe_extract(tls_layer, "handshake_extensions_ec_point_format"),
        "TLS Key Share Group": safe_extract(tls_layer, "handshake_extensions_key_share_group"),
        "TLS Session ID": safe_extract(tls_layer, "handshake_session_id"),
        "TLS Random": safe_extract(tls_layer, "handshake_random"),
        "TLS ALPN": safe_extract(tls_layer, "handshake_extensions_alpn_str")
    }   

def get_dns_hostname(ip):
    try:
        domain, ts = dns_cache.get(ip, (None, 0))
        if domain and (time.time() - ts) < DNS_TTL_SECONDS:
            return domain
    except:
        pass
    return "Unknown"

def capture_dns(interface='Wi-Fi'):
    print("[+] DNS monitor running...")
    capture = pyshark.LiveCapture(interface=interface, display_filter="dns and (dns.a or dns.aaaa)")
    for packet in capture.sniff_continuously():
        try:
            if hasattr(packet, 'dns'):
                dns = packet.dns
                if hasattr(dns, 'qry_name') and hasattr(dns, 'a'):
                    domain = dns.qry_name
                    ip = dns.a
                elif hasattr(dns, 'qry_name') and hasattr(dns, 'aaaa'):
                    domain = dns.qry_name
                    ip = dns.aaaa
                else:
                    continue
                dns_cache[ip] = (domain, time.time())
        except Exception as e:
            print("DNS Parse Error:", e)

def flush_inactive_sessions():
    while True:
        time.sleep(2)
        now = time.time()
        expired = []

        for stream_id, session in list(stream_sessions.items()):
            if now - session['last_seen'] > SESSION_TIMEOUT:
                expired.append(stream_id)

        for stream_id in expired:
            session = stream_sessions.pop(stream_id)

            # Enrich session with hostname
            ip = session["destination"]
            sni = session["sni"]
            resolved_host = sni if sni != "N/A" else get_dns_hostname(ip)
            if resolved_host == "Unknown":
                resolved_host = reverse_dns_lookup(ip)

            session_info = {
                "Stream ID": stream_id,
                "Start Time": session["start_time"],
                "End Time": session["last_seen"],
                "Duration (s)": round(session["last_seen"] - session["start_time"], 3),
                "Source": session["source"],
                "Destination": session["destination"],
                "Protocol": session["protocol"],
                "Packet Count": session["packet_count"],
                "Resolved Hostname": resolved_host,
                "GeoIP": session["geo"],
                "TLS Metadata": session["tls"]
            }

            encrypted_data = encrypt_packet_data(json.dumps(session_info))
            block = blockchain.add_block(encrypted_data)
            print_block(block)
            blockchain.save_chain("blockchain.txt")

def capture_tls(interface='Wi-Fi'):
    print("[+] TLS session capture running...")
    capture = pyshark.LiveCapture(interface=interface, display_filter="tls")
    for packet in capture.sniff_continuously():
        try:
            if not hasattr(packet, 'tcp'):
                continue
            stream_id = packet.tcp.stream

            ip_layer = packet.ip if hasattr(packet, 'ip') else packet.ipv6
            src = ip_layer.src
            dst = ip_layer.dst
            protocol = packet.highest_layer
            now = time.time()

            # Extract metadata
            tls_layer = packet.tls
            tls_info = extract_tls_metadata(tls_layer)
            sni = tls_info.get("TLS SNI (Server Name)", "N/A")
            cipher = tls_info.get("TLS Cipher Suite", "N/A")

            if stream_id not in stream_sessions:
                # New session
                geo = get_geo_info(dst)
                stream_sessions[stream_id] = {
                    "start_time": now,
                    "last_seen": now,
                    "source": src,
                    "destination": dst,
                    "protocol": protocol,
                    "geo": geo,
                    "tls": tls_info,
                    "sni": sni,
                    "cipher": cipher,
                    "packet_count": 1
                }
            else:
                session = stream_sessions[stream_id]
                session["last_seen"] = now
                session["packet_count"] += 1
                # Update TLS info if empty
                for k in tls_info:
                    if session["tls"].get(k, "N/A") == "N/A" and tls_info[k] != "N/A":
                        session["tls"][k] = tls_info[k]

        except Exception as e:
            print("TLS Parse Error:", e)

if __name__ == "__main__":
    dns_thread = threading.Thread(target=capture_dns, daemon=True)
    dns_thread.start()

    flush_thread = threading.Thread(target=flush_inactive_sessions, daemon=True)
    flush_thread.start()

    capture_tls()
