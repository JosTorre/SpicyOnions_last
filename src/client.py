#!/usr/bin/env python3
# coding: utf-8

'''
client.py

Client should do the following things in order:
1. Get list of node ip addresses and public keys from directory node
2. Pick a random ordering of 3 of these nodes
3. Get user input for info to send
4. Add encryption layers onto the packet being sent
5. Send onion packet to first node
6. Wait on return packet from the server
7. Compare returned hash to hash of sent packet
8. Repeat from step 3
'''

import socket
import configparser
from random import randint, shuffle
from hashlib import sha224
from aes_rsa import *

# Init
# ----------------------------------------------------------------
IP: str = socket.gethostbyname(socket.gethostname())
CONFIG_FILE = "sweet_onions.cfg"

# Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

DIR_PORT: int = int(config["DIRECTORY"]["Port"])
PORT: int = int(config["DEFAULT"]["Port"])
BUFFER_SIZE: int = int(config["DEFAULT"]["BufferSize"])
SEP: str = config["MESSAGES"]["Separator"]
CLIENT_REQ: str = config["MESSAGES"]["ClientRequest"]
NOT_READY_MSG: str = config["MESSAGES"]["NotReady"]

DIR_NODE: str = input("Directory server to connect to: ")

# front of nodes is server ip, back of nodes is entrance node
def wrap_layers(message: str, nodes, public_keys) -> str:
    assert isinstance(message, str), "The variable message must be a string"

    for x in nodes[1:]:
        message += SEP + x

    for x in range(len(nodes) - 1):
        message = nodes[x] + SEP + message
        if x == len(nodes) - 2:
            message = message + SEP + 'entrance'

        print(message)
        print(public_keys[x])
        encrypted_key, encrypted_msg = easy_encrypt(public_keys[x], message)
        message = encrypted_msg + bytes(SEP,"utf-8") + encrypted_key

    return message


# Connect to directory
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_NODE, DIR_PORT))

# Send and receive message from directory
s.send(bytes(CLIENT_REQ + SEP,"utf-8"))
dir_data = s.recv(BUFFER_SIZE).decode()
# Then close the connection
s.close()

if not dir_data or NOT_READY_MSG in dir_data: 
    print("Directory server not ready")
    exit()

# Get the destination server and message
dest_ip: str = input("Destination Address: ")
msg: str = str(input("Message: "))
msg_hash: str = sha224(bytes(msg,"utf-8")).hexdigest()

# Parse response from the directory
dir_arr = dir_data.split(SEP)
NUM_ROUTERS: int = int(dir_arr[0])
dir_arr = dir_arr[1:]

# parse the directory data string
in_keys = []
in_addr = []
print("RECEIVED")
for x in range(int(len(dir_arr)/2)):
    in_addr.append(dir_arr[2*x])
    in_keys.append(bytes(dir_arr[2*x + 1],"utf-8"))


# Generate a random route
NUM_NODES = randint(2, NUM_ROUTERS)
i = 0
y = list(range(NUM_ROUTERS))
shuffle(y)
pubkeys = []
node_addr = [dest_ip]
while i < NUM_NODES:
    pubkeys.append(in_keys[y[i]])
    node_addr.append(in_addr[y[i]])
    i+=1


print("UP TO WRAPPING LAYERS")
message = wrap_layers(msg, node_addr, pubkeys)
print(message)

# Send Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_addr[i], PORT))
s.send(message)
s.close()

# Receive Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, PORT))
s.listen(1)

while 1:
    conn, addr = s.accept()
    addr = addr[0]
    if addr == node_addr[len(node_addr) - 1]:
        data = conn.recv(BUFFER_SIZE).decode()
        if data == msg_hash:
            print("Received data matches hash: {}".format(data))
            break
        else:
            print("Received data does not match hash: {}".format(data))
            break

