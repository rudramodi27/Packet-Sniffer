import socket
import struct
import textwrap

# --- Configuration Constants for Output Formatting ---
# Use spaces for better alignment in terminal
T1, T2, T3 = '    - ', '        - ', '            - '
D1, D2, D3 = '      ', '          ', '              '

# --- Utility Functions ---

def get_mac_addr(bytes_addr):
    """Converts a 6-byte MAC address into a readable hex string."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_to_str(addr):
    """Converts a 4-byte IP address into a readable dotted-decimal string."""
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string, size=80):
    """Formats binary data or long text for clean, indented terminal output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        # Convert bytes to hex string for display
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# --- Protocol Parsers (The Dissectors) ---

def ethernet_frame(data):
    # Unpack 14 bytes: Dest MAC (6s), Src MAC (6s), EtherType (H)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # Convert network byte order protocol to host byte order (e.g., 0x0800 -> 2048)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    v_ihl = data[0]
    version = v_ihl >> 4
    header_len = (v_ihl & 15) * 4

    # Unpack TTL, Protocol, Source IP (4s), Target IP (4s) from the first 20 bytes
    # The '8x' skips 8 bytes (TOS, Total Length, ID, Flags, Frag Offset)
    # The '2x' skips the 2-byte Checksum
    ttl, proto, src, target = struct.unpack('! 8x B 2x 4s 4s', data[:20])

    return version, header_len, ttl, proto, ipv4_to_str(src), ipv4_to_str(target), data[header_len:]

def icmp_packet(data):
    # Unpack 4 bytes: Type (B), Code (B), Checksum (H)
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    # Unpack 14 bytes: Src Port (H), Dest Port (H), Sequence (L), Acknowledgment (L), Flags/Offset (H)
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    
    # Calculate offset (first 4 bits of H field, multiplied by 4)
    offset = (offset_reserved_flags >> 12) * 4
    
    # Extract the 6 flags using bitwise masking and shifting
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    # Unpack 8 bytes: Src Port (H), Dest Port (H), Skip Checksum (2x), Length (H)
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# --- Main Logic ---

def sniffer_main():
    # Attempt to create a raw socket (requires root/sudo privileges on Linux/Unix)
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("!! ERROR: Root/Sudo permissions are required to run a raw socket sniffer.")
        return
    except AttributeError:
        print("!! ERROR: AF_PACKET is typically only available on Linux/Unix systems.")
        return

    print("--- Starting Packet Sniffer (Ctrl+C to stop) ---")

    while True:
        raw_data, _ = conn.recvfrom(65536)
        
        # 1. Ethernet (Layer 2)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        print('\n' + '='*80)
        print(f'ETHERNET FRAME: [Source: {src_mac}] [Destination: {dest_mac}] [Proto: {eth_proto}]')
        
        # 2. IPv4 (Protocol 2048 or 0x0800)
        if eth_proto == 2048:
            version, header_len, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)
            
            print(T1 + f'IPv4 Packet:')
            print(T2 + f'Version: {version}, Header Length: {header_len} bytes, TTL: {ttl}')
            print(T2 + f'Source IP: {src_ip}, Target IP: {dest_ip}, Protocol: {proto}')

            # 3. Layer 4 Protocol Check
            
            # ICMP (Protocol 1)
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(T1 + 'ICMP:')
                print(T2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(T2 + 'Data:')
                print(format_multi_line(D3, data))

            # TCP (Protocol 6)
            elif proto == 6:
                s_port, d_port, seq, ack, urg, ack_f, psh, rst, syn, fin, data = tcp_segment(data)
                
                print(T1 + 'TCP Segment:')
                print(T2 + f'Ports: {s_port} -> {d_port}, Seq: {seq}, Ack: {ack}')
                print(T2 + f'Flags: URG:{urg} ACK:{ack_f} PSH:{psh} RST:{rst} SYN:{syn} FIN:{fin}')
                
                # Check for common protocols (HTTP/HTTPS/FTP) and try to decode data
                if s_port in (80, 443, 21) or d_port in (80, 443, 21):
                    try:
                        decoded_data = data.decode('utf-8').strip()
                        if decoded_data:
                            print(T2 + 'Application Data (Decoded):')
                            print(format_multi_line(D3, decoded_data))
                        else:
                            print(T2 + 'Payload Data (Hex):')
                            print(format_multi_line(D3, data))
                    except:
                        print(T2 + 'Payload Data (Hex):')
                        print(format_multi_line(D3, data))
                else:
                    print(T2 + 'Payload Data (Hex):')
                    print(format_multi_line(D3, data))

            # UDP (Protocol 17)
            elif proto == 17:
                s_port, d_port, length, data = udp_segment(data)
                print(T1 + 'UDP Segment:')
                print(T2 + f'Ports: {s_port} -> {d_port}, Length: {length}')
                print(T2 + 'Payload Data (Hex):')
                print(format_multi_line(D3, data))

            # Other IP Protocols
            else:
                print(T1 + f'Other IP Protocol ({proto}) Data (Hex):')
                print(format_multi_line(D2, data))
                
        # 4. Other Link-Layer Protocols (e.g., ARP - 1544)
        else:
            print(T1 + f'Other Link Protocol ({eth_proto}) Data (Hex):')
            print(format_multi_line(D1, data))

if __name__ == '__main__':
    sniffer_main()
