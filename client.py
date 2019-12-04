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

CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)


#NUM_NODES = 3
DIR_PORT = config["DEFAULT"]["DirectoryPort"]
PORT = config["DEFAULT"]["Port"]
DIR_NODE = '172.17.224.57' #change this

TCP_IP = socket.gethostbyname(socket.gethostname())
DIR_NODE = input("Directory server to connect to: ")


# Connect to directory
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_NODE, DIR_PORT))
s.send('Client Request###')
dir_data = s.recv(BUFFER_SIZE)
print(dir_data)
if dir_data and "Not ready yet" in dir_data: 
    print("directory server not ready")
    exit()
s.close()

# Get the destination server and message
dest_ip = input("Destination Address: ")
mes = input("Message: ")

# Save the hash of the message for integrity
mes_hash = sha224(mes).hexdigest()


# Parse response from the directory
dir_arr = dir_data.split("###")
NUM_ROUTERS = int(dir_arr[0])
dir_arr = dir_arr[1:]

# parse the directory data string
in_keys = []
in_addr = []
print("RECEIVED")
print(dir_arr)
for x in range(len(dir_arr)/2):
    in_addr.append(dir_arr[2*x])
    in_keys.append(dir_arr[2*x + 1])


# Generate a random route
NUM_NODES = randint(2, NUM_ROUTERS)
i = 0
y = range(NUM_ROUTERS)
shuffle(y)
pubkeys = []
node_addr = [dest_ip]
while i < NUM_NODES:
    pubkeys.append(in_keys[y[i]])
    node_addr.append(in_addr[y[i]])
    i+=1


print("UP TO WRAPPING LAYERS")
# front of nodes is server ip, back of nodes is entrance node
def wrap_layers(message, nodes, public_keys):
    for x in nodes[1:]:
        message += "###" + x
    for x in range(len(nodes) - 1):
        message = nodes[x] + '###' + message
        if x == len(nodes) - 2:
            message = message + '###' + 'entrance'

        encryptedKey, encryptedMsg = easy_encrypt(public_keys[x], message)
        message = encryptedMsg + "###" + encryptedKey
    return message
message = wrap_layers(mes, node_addr, pubkeys)
print(message)

# Send Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_addr[i], PORT))
s.send(message)
s.close()

# Recieve Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, PORT))
s.listen(1)

while 1:
    conn, addr = s.accept()
    addr = addr[0]
    if addr == node_addr[len(node_addr) - 1]:
        data = conn.recv(BUFFER_SIZE)
        if data == mes_hash:
            print("Received data matches hash: ", data)
            break
        else:
            print("Received data does not match hash: ", data)
            break

