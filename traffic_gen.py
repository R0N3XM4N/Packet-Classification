"""
SDN Traffic Classifier - Traffic Generator
Generates TCP, UDP, and ICMP traffic from inside Mininet for testing.
Run this from the Mininet CLI using: h1 python3 traffic_gen.py <mode>

Alternatively, use the helper commands listed in README.md.
"""

import argparse
import socket
import os
import sys
import time
import struct
import random


# ------------------------------------------------------------------ #
#  ICMP
# ------------------------------------------------------------------ #
def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def send_icmp(dst_ip, count=5):
    print(f"[ICMP] Sending {count} echo requests to {dst_ip}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for seq in range(count):
        header = struct.pack("bbHHh", 8, 0, 0, random.randint(1, 65535), seq)
        payload = b"SDN-CLASSIFIER-TEST"
        chk = checksum(header + payload)
        header = struct.pack("bbHHh", 8, 0, chk, random.randint(1, 65535), seq)
        sock.sendto(header + payload, (dst_ip, 0))
        print(f"  → ICMP echo #{seq} sent to {dst_ip}")
        time.sleep(0.5)
    sock.close()


# ------------------------------------------------------------------ #
#  TCP
# ------------------------------------------------------------------ #
def send_tcp(dst_ip, dst_port=5001, message="TCP-TEST", count=5):
    print(f"[TCP] Sending {count} messages to {dst_ip}:{dst_port}")
    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((dst_ip, dst_port))
            sock.sendall(f"{message}-{i}".encode())
            sock.close()
            print(f"  → TCP message #{i} sent to {dst_ip}:{dst_port}")
        except ConnectionRefusedError:
            print(f"  ✗ TCP #{i}: Connection refused (is a server running on {dst_ip}:{dst_port}?)")
        except Exception as e:
            print(f"  ✗ TCP #{i}: {e}")
        time.sleep(0.5)


# ------------------------------------------------------------------ #
#  UDP
# ------------------------------------------------------------------ #
def send_udp(dst_ip, dst_port=5002, message="UDP-TEST", count=5):
    print(f"[UDP] Sending {count} datagrams to {dst_ip}:{dst_port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        payload = f"{message}-{i}".encode()
        sock.sendto(payload, (dst_ip, dst_port))
        print(f"  → UDP datagram #{i} sent to {dst_ip}:{dst_port}")
        time.sleep(0.5)
    sock.close()


# ------------------------------------------------------------------ #
#  Simple TCP server (listener)
# ------------------------------------------------------------------ #
def tcp_server(port=5001):
    print(f"[SERVER] TCP server listening on port {port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.listen(10)
    while True:
        conn, addr = sock.accept()
        data = conn.recv(1024)
        print(f"  ← Received from {addr}: {data.decode()}")
        conn.close()


# ------------------------------------------------------------------ #
#  UDP server (listener)
# ------------------------------------------------------------------ #
def udp_server(port=5002):
    print(f"[SERVER] UDP server listening on port {port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"  ← Received from {addr}: {data.decode()}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traffic Generator for SDN Classifier")
    parser.add_argument("mode", choices=["tcp", "udp", "icmp", "tcp-server", "udp-server"],
                        help="Traffic mode to use")
    parser.add_argument("--dst",   default="10.0.0.2", help="Destination IP")
    parser.add_argument("--port",  default=5001, type=int, help="Destination/listen port")
    parser.add_argument("--count", default=5,    type=int, help="Number of packets to send")
    parser.add_argument("--msg",   default="SDN-TEST",   help="Payload message")
    args = parser.parse_args()

    if args.mode == "icmp":
        if os.geteuid() != 0:
            sys.exit("ICMP requires root privileges. Run with sudo.")
        send_icmp(args.dst, args.count)
    elif args.mode == "tcp":
        send_tcp(args.dst, args.port, args.msg, args.count)
    elif args.mode == "udp":
        send_udp(args.dst, args.port, args.msg, args.count)
    elif args.mode == "tcp-server":
        tcp_server(args.port)
    elif args.mode == "udp-server":
        udp_server(args.port)
