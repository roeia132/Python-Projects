import socket
import re
import os
import datetime
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.bind(("127.0.0.1", 666))
soc.listen()
client, (ip, port) = soc.accept()
try:
    client.send(f"connected to{ip}".encode())
except:
    pass
while True:
    try:
        rcv = client.recv(1024).decode()
        print(f"{datetime.datetime.now()}<<     {rcv}")
        if rcv == "logout":
            client.send("logout".encode())
            client.close()
            break
        elif re.match("range [0-9]+ [0-9]+", rcv):
            rcv = rcv.split(" ")
            for i in range(int(rcv[1]), int(rcv[2]) + 1):
                print(i)
        elif re.match("https://", rcv):
            os.system(f"start brave {rcv}")
        snd = input(">>").encode()
        client.send(snd)
    except Exception as e:
        print(e)
