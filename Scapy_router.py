# Roei Atlas
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP


def dhcp_offer(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        client_mac = pkt[Ether].src
        client_mac_bytes = bytes(int(b, 16) for b in client_mac.split(':'))
        server_mac = "00:50:56:C0:00:0F"
        server_ip = "10.0.0.1"
        offer_ip = "10.0.0.10"
        trans_id = pkt[BOOTP].xid
        dhcp_offer_pkt = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=offer_ip) / UDP(
            sport=67, dport=68) / BOOTP(op=2, htype=pkt[BOOTP].htype, hlen=pkt[BOOTP].hlen, hops=pkt[BOOTP].hops,
                                        xid=trans_id, secs=pkt[BOOTP].secs, ciaddr=pkt[BOOTP].ciaddr, yiaddr=offer_ip,
                                        siaddr=server_ip, giaddr=pkt[BOOTP].giaddr,
                                        chaddr=client_mac_bytes + b'\x00' * 10) / \
                         DHCP(options=[('message-type', 'offer'), ('server_id', server_ip), ('lease_time', 86400),
                                       ('subnet_mask', '255.255.255.0'), ('broadcast_address', '10.0.0.255'),
                                       ('name_server', server_ip),
                                       ('domain', 'localdomain'), ('router', server_ip), 'end'])
        sendp(dhcp_offer_pkt, iface="VMware Network Adapter VMnet15")


sniff(filter="udp and (port 67 or port 68)", prn=dhcp_offer, iface="VMware Network Adapter VMnet15", count=1)


def dhcp_ack(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        client_mac = pkt[Ether].src
        client_mac_bytes = bytes(int(b, 16) for b in client_mac.split(':'))
        server_mac = "00:50:56:C0:00:0F"
        server_ip = "10.0.0.1"
        offer_ip = "10.0.0.10"
        trans_id = pkt[BOOTP].xid
        dhcp_ack_pkt = Ether(src=server_mac, dst=client_mac) / IP(tos=pkt[IP].tos, src=server_ip, dst=offer_ip) / UDP(
            sport=67, dport=68) / BOOTP(op=2, htype=pkt[BOOTP].htype, hlen=pkt[BOOTP].hlen, hops=pkt[BOOTP].hops,
                                        xid=trans_id, secs=pkt[BOOTP].secs, ciaddr=pkt[BOOTP].ciaddr, yiaddr=offer_ip,
                                        siaddr=server_ip, giaddr=pkt[BOOTP].giaddr,
                                        chaddr=client_mac_bytes + b'\x00' * 10) / \
                       DHCP(options=[('message-type', 'ack'), ('server_id', server_ip), ('lease_time', 86400),
                                     ('subnet_mask', '255.255.255.0'), ('broadcast_address', '10.0.0.255'),
                                     ('name_server', server_ip), ('domain', 'localdomain'),
                                     ('NetBIOS_server', server_ip), ('router', server_ip), 'end'])
        sendp(dhcp_ack_pkt, iface="VMware Network Adapter VMnet15")


sniff(filter="udp and (port 67 or port 68)", prn=dhcp_ack, iface="VMware Network Adapter VMnet15", count=1)


def arp_reply(pkt):
    if ARP in pkt and pkt[ARP].op == 1:
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].psrc
        my_server_mac = "00:50:56:C0:00:0F"
        my_server_ip = "10.0.0.1"
        arp_reply_pkt = Ether(src=my_server_mac, dst=src_mac) / ARP(op=2, hwsrc=my_server_mac, psrc=my_server_ip,
                                                                    hwdst=src_mac, pdst=src_ip)
        sendp(arp_reply_pkt, iface="VMware Network Adapter VMnet15")


sniff(filter="arp", prn=arp_reply, iface="VMware Network Adapter VMnet15", count=1)


def dns_query_handler(pkt):
    time.sleep(3)
    if DNS in pkt:
        fake_site = "100.0.0.100"
        print(pkt.show())
        b_site_add = pkt[DNS][DNSQR].qname
        site_add = b_site_add.decode('utf-8')
        response = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/
                       DNS(rd=1, qd=DNSQR(qname=site_add)), iface="Ethernet")
        if response[DNS].rcode == 3:
            dns_response_pkt = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=53) / \
                               DNS(id=pkt[DNS].id, qr=1, opcode=0, rd=1, ra=1, rcode=0, qdcount=1, ancount=1,
                                   qd=DNSQR(qname=b_site_add, qtype=1, qclass=1),
                                   an=DNSRR(rrname=b_site_add, type=1, rclass=1, rdlen=4, ttl=86400, rdata=fake_site))
        else:
            dns_response_pkt = IP(dst=pkt[IP].src, src='10.0.0.1') / UDP(dport=pkt[UDP].sport) / DNS()
            dns_response_pkt[DNS] = response[DNS]
        send(dns_response_pkt, iface="VMware Network Adapter VMnet15", verbose=0)


sniff(filter="host 10.0.0.10", prn=dns_query_handler, iface="VMware Network Adapter VMnet15", count=1)
