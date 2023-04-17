#!/usr/bin/env python3

import socket
import struct
import os


def main():
    print("Choose the layer and protocol to sniff:")
    print("1. Ethernet - Linux Only")
    print("2. IPv4")
    print("3. TCP")
    print("4. UDP")
    choice = input("Enter the number of your choice: \n")

    if choice not in ["1", "2", "3", "4"]:
        print("Invalid input")
        return

    if os.name == "nt" and choice == "1":
        print("Can't sniff Ethernet on Windows without downloading additional libraries")
        return
    elif os.name == "nt":  # Check if the script is running on Windows
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.ntohs(0x0003)

    conn = create_socket(socket_protocol)
    sniff(conn, socket_protocol, choice)


def create_socket(protocol):
    try:
        if protocol == socket.IPPROTO_IP:
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            conn.bind(("10.100.102.32", 0))  # Set your local ip address
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol)
        return conn
    except socket.error as e:
        print(f"Error creating socket: {e}")
        exit(1)


def sniff(conn, protocol, choice):
    while True:
        raw_data, addr = conn.recvfrom(65535)

        if protocol == socket.IPPROTO_IP:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(raw_data)
            if choice == '2':
                print(f"\nIPv4 Packet:")
                print(f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
                print(f"Protocol: {proto}, Source: {src}, Target: {target}")

            elif choice == '3' and proto == 6:  # TCP
                tcp_src_port, tcp_dest_port, tcp_data = tcp_segment(data)
                print(f"\nTCP Segment:")
                print(f"Source Port: {tcp_src_port}, Destination Port: {tcp_dest_port}")
                print(f"Data: {tcp_data}")

            elif choice == '4' and proto == 17:  # UDP
                udp_src_port, udp_dest_port, udp_data = udp_datagram(data)
                print(f"\nUDP Datagram:")
                print(f"Source Port: {udp_src_port}, Destination Port: {udp_dest_port}")
                print(f"Data: {udp_data}")

        else:
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if choice == '1':
                print("\nEthernet Frame:")
                print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

            if eth_proto == 8:  # IPv4
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

                if choice == '2':
                    print(f"\nIPv4 Packet:")
                    print(f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
                    print(f"Protocol: {proto}, Source: {src}, Target: {target}")

                elif choice == '3' and proto == 6:  # TCP
                    tcp_src_port, tcp_dest_port, tcp_data = tcp_segment(data)
                    print(f"\nTCP Segment:")
                    print(f"Source Port: {tcp_src_port}, Destination Port: {tcp_dest_port}")
                    print(f"Data: {tcp_data}")

                elif choice == '4' and proto == 17:  # UDP
                    udp_src_port, udp_dest_port, udp_data = udp_datagram(data)
                    print(f"\nUDP Datagram:")
                    print(f"Source Port: {udp_src_port}, Destination Port: {udp_dest_port}")
                    print(f"Data: {udp_data}")


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def tcp_segment(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[20:]


def udp_datagram(data):
    src_port, dest_port = struct.unpack('! H H', data[:4])
    return src_port, dest_port, data[8:]


if __name__ == '__main__':
    main()
