import pyshark
import subprocess
from encryption_utils import encrypt_metadata

def get_active_interface():
    """Auto-detect active network interface"""
    result = subprocess.run(['route', '-n', 'get', 'default'], 
                          capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'interface:' in line:
            return line.split(':')[-1].strip()
    return 'en0'  # Fallback

def capture_tls_sessions(public_key_pem, interface=None):
    interface = interface or get_active_interface()
    try:
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter='tls.handshake.type == 1',
            output_file='capture.pcap'  # Optional: save to file
        )
        
        for packet in capture.sniff_continuously():
            try:
                session_data = {
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "tls_version": getattr(packet.tls, 'handshake_version', 'Unknown'),
                    "timestamp": packet.sniff_time.isoformat()
                }
                yield encrypt_metadata(session_data, public_key_pem)
                
            except AttributeError as e:
                print(f"Skipping malformed packet: {e}")
                continue
                
    except Exception as e:
        print(f"Capture failed on interface {interface}: {e}")
        raise