ARP
IP
ICMP

DHCP - Request

def dhcp_discover():
    # Disable IP address validation in Scapy
    conf.checkIPaddr = False
    # Get the MAC address of the network interface that will be used for sending the DHCP request
    fam, hw = get_if_raw_hwaddr(conf.iface)
    # Construct a DHCP discover packet using the necessary layers and options in Scapy
    dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67)/BOOTP(chaddr=hw)/DHCP(options=[('message-type', 'discover'), 'end'])
    # Send the DHCP discover packet using the srp() function in Scapy
    srp(dhcp_discover)
# Call the dhcp_request() function to execute the DHCP discovery process
dhcp_discover()

DHCP - Offer

# Define a function to send a DHCP Offer packet in response to a DHCP Discover packet
def dhcp_offer(pkt):
    # Check if the packet is a DHCP Discover packet
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        # Get the MAC address of the client that sent the DHCP Discover packet
        client_mac = pkt[Ether].src
        # Get the MAC address of the network interface that will be used to send the DHCP Offer packet
        server_mac = get_if_hwaddr(conf.iface)
        # Set the IP address of the DHCP server
        server_ip = "192.168.1.1"
        # Set the IP address to be offered to the client
        offer_ip = "192.168.1.100"
        # Construct a DHCP Offer packet using the necessary layers and options in Scapy
        dhcp_offer_pkt = Ether(src=server_mac, dst=client_mac)/IP(src=server_ip, dst='255.255.255.255')/UDP(sport=67, dport=68)/BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, chaddr=client_mac)/DHCP(options=[('message-type', 'offer'), ('server_id', server_ip), ('lease_time', 86400), ('subnet_mask', '255.255.255.0'), ('router', server_ip), 'end']) 
        # Send the DHCP Offer packet using the sendp() function in Scapy
        sendp(dhcp_offer_pkt, iface=conf.iface)
# Use Scapy's sniff() function to capture DHCP packets on the network and call the dhcp_offer() function in response to DHCP Discover packets
sniff(filter="udp and (port 67 or port 68)", prn=dhcp_offer)

DHCP - Request

def dhcp_request():
    # Disable IP address checking to allow sending packets with a source IP of 0.0.0.0
    conf.checkIPaddr = False
    # Get the MAC address of the network interface that will be used to send the DHCP request
    fam, hw = get_if_raw_hwaddr(conf.iface)
    # Construct a DHCP request packet using the necessary layers and options in Scapy
    dhcp_request_pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / BOOTP(chaddr=hw) / DHCP(options=[('message-type', 'request'), ('requested_addr', '192.168.1.100'), ('server_id', '192.168.1.1'), 'end'])
    # Send the DHCP request packet and receive the DHCP response
    dhcp_response_pkt = srp1(dhcp_request_pkt, timeout=2)
    # Print the DHCP response packet
    print(dhcp_response_pkt.show())
# Call the dhcp_request() function to send a DHCP request and receive the DHCP response
dhcp_request()

DHCP - Acknowledge

# Define a function to send a DHCP Acknowledge packet in response to a DHCP Request packet
def dhcp_ack(pkt):
    # Check if the packet is a DHCP Request packet
    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        # Get the MAC address of the client that sent the DHCP Request packet
        client_mac = pkt[Ether].src
        # Get the MAC address of the network interface that will be used to send the DHCP Acknowledge packet
        server_mac = get_if_hwaddr(conf.iface)
        # Set the IP address of the DHCP server
        server_ip = "192.168.1.1"
        # Get the IP address that was offered to the client in the DHCP Offer packet
        offered_ip = pkt[BOOTP].yiaddr
        # Construct a DHCP Acknowledge packet using the necessary layers and options in Scapy
        dhcp_ack_pkt = Ether(src=server_mac, dst=client_mac)/IP(src=server_ip, dst='255.255.255.255')/UDP(sport=67, dport=68)/BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip, chaddr=client_mac)/DHCP(options=[('message-type', 'ack'), ('server_id', server_ip), ('lease_time', 86400), ('subnet_mask', '255.255.255.0'), ('router', server_ip), 'end'])
        # Send the DHCP Acknowledge packet using the sendp() function in Scapy
        sendp(dhcp_ack_pkt, iface=conf.iface)
# Use Scapy's sniff() function to capture DHCP packets on the network and call the dhcp_ack() function in response to DHCP Request packets
sniff(filter="udp and (port 67 or port 68)", prn=dhcp_ack)

DNS
HTTP
