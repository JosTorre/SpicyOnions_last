#!/usr/bin/env python3
# coding : utf-8

'''
server.py
Sends back the hash of the received message

Should act like a normal server
Should not know it is being accessed through onion routing
'''
import socket
import configparser
from hashlib import sha224

CONFIG_FILE: str = "sweet_onions.cfg"
IP: str = socket.gethostbyname(socket.gethostname())

# Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Set configuration variables
PORT: int = int(config["DEFAULT"]["Port"])
BUFFER_SIZE: int = int(config["SERVER"]["BufferSize"])

# Open socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, PORT))
s.listen(1) #maximum 1 connection

print("Connection opened on {}:{}".format(IP,PORT))

# Return sha224 of first data for each connections
try:
    while True:
        conn, addr = s.accept()
        print("Connection from {}".format(addr[0]))

        data = conn.recv(BUFFER_SIZE)
        print("Received : {}".format(data.decode().strip()))

        # Send SHA 224 of received message
        response: bytes = bytes(sha224(data).hexdigest() + '\n',"utf-8")
        conn.send(response)

        conn.close()
except KeyboardInterrupt:
    print("Server closed")
