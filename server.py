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

CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

IP = socket.gethostbyname(socket.gethostname())
PORT = int(config['DEFAULT']['Port'])
BUFFER_SIZE = int(config['SERVER']['BufferSize'])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, PORT))
s.listen(1) #maximum 1 connection
print("Connection opened on {}:{}".format(IP,PORT))

while 1:
	conn, addr = s.accept()
	addr = addr[0]
	print('Connection from {}'.format(addr))
	data = conn.recv(BUFFER_SIZE)
	hashed = sha224(data).hexdigest()
	if not data: break
	print("Received : {}".format(data))
	conn.send(bytes(hashed + '\n',"utf-8"))

conn.close()
