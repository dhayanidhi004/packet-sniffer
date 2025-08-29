#!/usr/bin/env python3
import socket
import struct
import argparse
import time
from collections import defaultdict

LOG_FILE = "sniffer.log"

# Track SYN packets and ports per IP for alerts
syn_tracker = defaultdict(list)
port_tracker = defaultdict(set)
SYN_THRESHOLD = 5       # SYN flood threshold
PORT_SCAN_THRESHOLD = 10  # Port scan threshold

def log(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(msg)

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return dest_mac, src_mac, socket.htons(proto), data[14:]

def parse_ip_header(data):
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    return src_ip, dest_ip, protocol, data[iph_length:]

def parse_tcp_header(data):
    tcph = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcph[0]
    dest_port = tcph[1]
    seq = tcph[2]
    ack_seq = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = (doff_reserved >> 4) * 4
    flags = tcph[5]
    return src_port, dest_port, flags, data[tcph_length:]

def parse_udp_header(data):
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return src_port, dest_port, data[8:]

def parse_icmp_header(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, data[4:]

def check_syn_flood(src_ip, flags):
    # SYN = 0x02, ACK = 0x10
    if flags & 0x02 and not flags & 0x10:
        syn_tracker[src_ip].append(time.time())
        # remove old timestamps
        syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if time.time() - t < 10]
        if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
            log(f"ALERT: Possible SYN flood from {src_ip}")

def check_port_scan(src_ip, dest_port):
    port_tracker[src_ip].add(dest_port)
    if len(port_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
        log(f"ALERT: Possible port scan from {src_ip}")

def main(proto_filter=None, port_filter=None, max_packets=None):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Run this script with sudo/root privileges.")
        return

    count = 0
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)

        if eth_proto == 8:  # IPv4
            src_ip, dest_ip, protocol, ip_data = parse_ip_header(data)

            if protocol == 6:  # TCP
                src_port, dest_port, flags, tcp_data = parse_tcp_header(ip_data)
                if proto_filter and proto_filter.lower() != "tcp":
                    continue
                if port_filter and port_filter != src_port and port_filter != dest_port:
                    continue
                log(f"[TCP] {src_ip}:{src_port} -> {dest_ip}:{dest_port} flags={flags}")
                check_syn_flood(src_ip, flags)
                check_port_scan(src_ip, dest_port)

            elif protocol == 17:  # UDP
                src_port, dest_port, udp_data = parse_udp_header(ip_data)
                if proto_filter and proto_filter.lower() != "udp":
                    continue
                if port_filter and port_filter != src_port and port_filter != dest_port:
                    continue
                log(f"[UDP] {src_ip}:{src_port} -> {dest_ip}:{dest_port} length={len(udp_data)}")

            elif protocol == 1:  # ICMP
                icmp_type, code, icmp_data = parse_icmp_header(ip_data)
                if proto_filter and proto_filter.lower() != "icmp":
                    continue
                log(f"[ICMP] {src_ip} -> {dest_ip} type={icmp_type} code={code}")

        count += 1
        if max_packets and count >= max_packets:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Packet Sniffer")
    parser.add_argument("--proto", help="Filter by protocol (tcp/udp/icmp)")
    parser.add_argument("--port", type=int, help="Filter by port number")
    parser.add_argument("--max", type=int, help="Max number of packets to capture")
    args = parser.parse_args()

    main(proto_filter=args.proto, port_filter=args.port, max_packets=args.max)
