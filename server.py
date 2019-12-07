#!/usr/bin/env python3
# coding : utf-8

'''
server.py
Should act like a normal server
Should not know it is being accessed through onion routing
Should send back the hash of the received message
'''
import socket
import configparser
from hashlib import sha224

# Read configuration
CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

IP: str = socket.gethostbyname(socket.gethostname())
PORT: int = int(config["DEFAULT"]["Port"])
BUFFER_SIZE: int = int(config["SERVER"]["BufferSize"])

# Open socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, PORT))
s.listen(1) #maximum 1 connection

print("Connection opened on {}:{}".format(IP,PORT))

# Return sha224 of first data for each connections
data = 'useless garbage'
while data:
	conn, addr = s.accept()
	print("Connection from {}".format(addr[0]))
	data = conn.recv(BUFFER_SIZE)
	hashed = sha224(data).hexdigest()
	#if not data: break
	print("Received : {}".format(data.decode().split()))
	conn.send(bytes(hashed + '\n',"utf-8"))

conn.close()
