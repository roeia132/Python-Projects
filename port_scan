import socket

with open('scan_result.txt', 'w') as output:
    domain = input("Insert the Target domain > ")
    target_ip = socket.gethostbyname(domain)
    port_range = input("Insert the port range in the following format 'x..X' > ")
    f_port = int(port_range.split("..")[0])
    l_port = int(port_range.split("..")[1])
    output.write(f"Target Address: {domain} | IP Address: {target_ip} | Port Range: {f_port} - {l_port}\n")
    output.write(f"The open ports on this target are:\n")
    for p in range(f_port, l_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((domain, p))
            output.write(f"Port number {p}\n")
        except:
            pass
        finally:
            sock.close()
