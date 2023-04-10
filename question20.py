from scapy.all import sniff, Raw
from scapy.layers.inet import IP
import requests
from bs4 import BeautifulSoup
import re
import ipaddress


# Function to sniff packets and return URLs
def sniff_packets():
    packets = sniff(count=15, filter="tcp dst port 80 and host 82.80.219.248")
    urls_list = []

    for index, packet in enumerate(packets):
        try:
            if Raw in packet:
                protocol = "http://"
                loads = packet[Raw].load
                ls_load = str(loads).split(":")
                path = ls_load[0].split(" ")[1]
                domain = str(ls_load[1]).split("\\")[0].split(" ")[1]
                url = protocol+domain+path
                if url not in urls_list:
                    urls_list.append(url)
            else:
                packets.pop(index)
        except:
            packets.pop(index)

    return urls_list, packets


# Function to get working links from the main site
def get_working_links(url):
    href_list = []
    src = requests.get(url).text
    soup = BeautifulSoup(src, 'lxml')

    try:
        links = soup.find_all('a')
        for link in links:
            if 'href' in link.attrs:
                try:
                    is_ip = re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', link['href'])
                    if is_ip:
                        print("An ip address exists in this href: ", link['href'])
                    status = requests.get(link['href']).status_code
                    if status == 200:
                        href_list.append(link['href'])
                except:
                    pass
    except:
        print("Error occurred while getting working links")

    return href_list


# Function to extract data from packets
def extract_data(packets):
    data_dict = {}
    src_IP = ""
    dst_IP = ""

    for index, packet in enumerate(packets):
        try:
            if Raw in packet:
                data = packets[index][Raw].load.decode('utf-8', 'ignore')
                data_list = data.splitlines()
                method_type = data_list[0].split(" ")[0]
                src_IP = packet[IP].src
                dst_IP = packet[IP].dst

                for line in data_list:
                    if ":" in line:
                        key = line.split(":")[0]
                        value = line.split(": ")[1]
                        data_dict.update({key: value})
        except:
            pass

        if data_dict:
            break
        else:
            continue

    return data_dict, method_type, src_IP, dst_IP


# Main function to run the script
def main():
    urls_list, packets = sniff_packets()

    print("In the site: ", urls_list[0])

    href_list = get_working_links(urls_list[0])
    print("\nWorking links: ")
    for i in href_list:
        print(i)
    print()

    data_dict, method_type, src_IP, dst_IP = extract_data(packets)
    print(data_dict)
    print()
    print("The method was:", method_type)
    print()
    print(f"The source ip is: {src_IP} | The destination ip is: {dst_IP}")

    dst_IP = ipaddress.IPv4Address(dst_IP)
    src_IP = ipaddress.IPv4Address(src_IP)

    if dst_IP.is_private:
        print("dst ip is a private ip")
    if src_IP.is_private:
        print("src ip is a private ip")


# Run the main function
main()
