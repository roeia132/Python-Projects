#!/usr/bin/env python3

"""
A basic packet sniffer script in Python that allows the user to choose which layer and protocol
to sniff packets for, such as Ethernet (Linux only), IPv4, TCP, and UDP.
"""

import socket
import struct
import os
import sys
import argparse
import platform
import ctypes


def main():
    if not is_admin():
        print("NOTE: The program must be used with high privileges!")
        return

    layer = input("Choose the layer and protocol to sniff (ethernet, ipv4, tcp, udp): ").lower()
    local_ip = input("Enter the local IP address of the device running the sniffer: ")

    if layer not in ["ethernet", "ipv4", "tcp", "udp"]:
        print("Invalid layer input. Please choose from ethernet, ipv4, tcp, or udp.")
        return

    # Check if the script is running on Windows and set the socket protocol accordingly
    if os.name == "nt" and layer == "ethernet":
        print("Can't sniff Ethernet on Windows without downloading additional libraries")
        return
    elif os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.ntohs(0x0003)

    conn = create_socket(socket_protocol, local_ip)
    sniff(conn, socket_protocol, layer)


def is_admin():
    """
    Check if the script is running with high privileges (as an administrator or root user).
    """
    if platform.system() == "Windows":
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:  # For Linux and macOS
        is_admin = os.geteuid() == 0

    return is_admin



def create_socket(protocol, local_ip):
    """
    Create a raw socket connection.
    """
    try:
        if protocol == socket.IPPROTO_IP:
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            conn.bind((local_ip, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol)
        return conn
    except socket.error as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)


def sniff(conn, protocol, layer_choice):
    """
    Receive and analyze network packets.
    """
    while True:
        raw_data, addr = conn.recvfrom(65535)

        # Analyze the IPv4 packet
        if protocol == socket.IPPROTO_IP:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(raw_data)

            # Print the IPv4 packet information if the user selected this option
            if layer_choice == 'ipv4':
                print(f"\nIPv4 Packet:")
                print(f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
                print(f"Protocol: {proto}, Source: {src}, Target: {target}")

            # Analyze the TCP segment if the user selected this option and the packet is a TCP packet
            elif layer_choice == 'tcp' and proto == 6:
                tcp_src_port, tcp_dest_port, tcp_data = tcp_segment(data)
                print(f"\nTCP Segment:")
                print(f"Source Port: {tcp_src_port}, Destination Port: {tcp_dest_port}")
                print(f"Data: {tcp_data}")

            # Analyze the UDP datagram if the user selected this option and the packet is a UDP packet
            elif layer_choice == 'udp' and proto == 17:
                udp_src_port, udp_dest_port, udp_data = udp_datagram(data)
                print(f"\nUDP Datagram:")
                print(f"Source Port: {udp_src_port}, Destination Port: {udp_dest_port}")
                print(f"Data: {udp_data}")

        # Analyze the Ethernet frame if the user selected this option
        else:
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if layer_choice == 'ethernet':
                print("\nEthernet Frame:")
                print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

            # Analyze the IPv4 packet inside the Ethernet frame if the user selected this option and the frame
            # contains an IPv4 packet
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

                if layer_choice == 'ipv4':
                    print(f"\nIPv4 Packet:")
                    print(f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
                    print(f"Protocol: {proto}, Source: {src}, Target: {target}")

                # Analyze the TCP segment inside the IPv4 packet if the user selected this option and the packet is a
                # TCP packet
                elif layer_choice == 'tcp' and proto == 6:
                    tcp_src_port, tcp_dest_port, tcp_data = tcp_segment(data)
                    print(f"\nTCP Segment:")
                    print(f"Source Port: {tcp_src_port}, Destination Port: {tcp_dest_port}")
                    print(f"Data: {tcp_data}")

                # Analyze the UDP datagram inside the IPv4 packet if the user selected this option and the packet is
                # a UDP packet
                elif layer_choice == 'udp' and proto == 17:
                    udp_src_port, udp_dest_port, udp_data = udp_datagram(data)
                    print(f"\nUDP Datagram:")
                    print(f"Source Port: {udp_src_port}, Destination Port: {udp_dest_port}")
                    print(f"Data: {udp_data}")


def ethernet_frame(data):
    """
    Extract Ethernet frame header information.
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    """
    Format MAC address from bytes to string.
    """
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    """
    Extract IPv4 packet header information.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    """
    Format IPv4 address from bytes to string.
    """
    return '.'.join(map(str, addr))


def tcp_segment(data):
    """
    Extract TCP segment header information.
    """
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[20:]


def udp_datagram(data):
    """
    Extract UDP datagram header information.
    """
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[8:]


def parse_arguments():
    """
    Parse command-line arguments using argparse.
    """
    parser = argparse.ArgumentParser(description="A basic packet sniffer in Python.")
    parser.add_argument("layer", choices=["ethernet", "ipv4", "tcp", "udp"],
                        help="Select the layer and protocol to sniff: ethernet (Linux only), ipv4, tcp, or udp")
    parser.add_argument("local_ip", type=str,
                        help="Enter the local IP address of the device running the sniffer")

    return parser.parse_args()


if __name__ == '__main__':
    main()


