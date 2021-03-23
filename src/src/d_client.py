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

import socket, pickle
import configparser
from random import randint, shuffle
from hashlib import sha224
from aes_rsa import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# Init
# ----------------------------------------------------------------
#IP: str = socket.gethostbyname(socket.gethostname())
IP: str = '172.18.0.1'
CONFIG_FILE = "/home/spice/spiceonion/SweetOnions/src/sweet_onions.cfg"

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
    print(message)
    for x in nodes[1:]:
        message += SEP + x
        print(message)
    for x in range(len(nodes) - 1):
        message = bytes(nodes[x],'utf-8') + bytes(SEP,'utf-8') + message
        if x == len(nodes) - 2:
            message = message + bytes(SEP,'utf-8') + b"entrance"
        print(message)
        print(public_keys[x])
        encrypted_key, encrypted_msg = easy_encrypt(public_keys[x], message)
        message = encrypted_msg + bytes(SEP,'utf-8') + encrypted_key
    return message


# Connect to directory to get nodes's public keys
# ----------------------------------------------------------------
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
# ----------------------------------------------------------------
dest_ip: str = input("Destination Address: ")
#msg: str = str(input("Message: "))
#msg_hash: str = sha224(bytes(msg,"utf-8")).hexdigest()

# Parse response from the directory
dir_arr = dir_data.split(SEP)
NUM_ROUTERS: int = int(dir_arr[0])
dir_arr = dir_arr[1:]
print(dir_arr)
# parse the directory data string
in_keys = []
in_addr = []
shared_onion_keys_arr = []
print("RECEIVED")
for x in range(int(len(dir_arr)/2)):
    in_addr.append(dir_arr[2*x])
    in_keys.append(bytes(dir_arr[2*x + 1],"utf-8"))


# Generate a random route
# ----------------------------------------------------------------
NUM_NODES = randint(3, NUM_ROUTERS)
i = 0
y = list(range(NUM_ROUTERS))
shuffle(y)
pubkeys = []
node_addr = [dest_ip]

while i < NUM_NODES:
    pubkeys.append(in_keys[y[i]])
    node_addr.append(in_addr[y[i]])
    i+=1
print(node_addr)

# Create Key
# ----------------------------------------------------------------

private_onion_key = X25519PrivateKey.generate()

private_bytes = private_onion_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
)
print(private_bytes)
public_onion_key = private_onion_key.public_key()

public_bytes = public_onion_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
)
print(public_bytes)

# Create Circuit
# ----------------------------------------------------------------

counter = len(node_addr)
relays = ['CREATE','EXTEND','EXTEND2']
cs = socket.socket()
print('Connecting to Entry Node')
try:
    cs.connect((node_addr[i], PORT))
except socket.error as e:
    print(str(e))

backend = default_backend()

for x in range(0, 3) :
        if x == 0:
            node_arr = [x+1,3,node_addr[3-x],relays[x],public_bytes]
            array = pickle.dumps(node_arr)
            cs.send(array) #CREATE
            response = cs.recv(1024) #CREATED (entry node)
            arr = pickle.loads(response)
            peer_public = x25519.X25519PublicKey.from_public_bytes(arr[4])
            shared_onion_key = private_onion_key.exchange(peer_public)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=backend
            ).derive(shared_onion_key)
            print("Entry Node Shared Secret:")
            print(derived_key)
            print("Received: " + arr[3])
            shared_onion_keys_arr.append(derived_key)
        else:
            node_arr = [x+1,3,node_addr[3-x],relays[x],public_bytes]
            array = pickle.dumps(node_arr)
            cs.send(array) #EXTEND
            response = cs.recv(1024) #EXTENDED (entry node)
            arr = pickle.loads(response)
            peer_public = x25519.X25519PublicKey.from_public_bytes(arr[4])
            shared_onion_key = private_onion_key.exchange(peer_public)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_onion_key)
            shared_onion_keys_arr.append(derived_key)
            if x == 1 :
                print("Middle Node Shared Secret:")
                print(shared_onion_key)
            else :
                print("Exit Node Shared Secret:")
                print(shared_onion_key)
                print("Received: " + arr[3])
        



#node_arr = [1,3,node_addr[3],'CREATE2']
#array = pickle.dumps(node_arr)
#
#cs.send(array) #CREATE
#response = cs.recv(1024) #CREATED (entry node)
#print("Received: " + response.decode('utf-8'))
#
#node_arr = [2,3,node_addr[2],'EXTEND2']
#array = pickle.dumps(node_arr)
#
#cs.send(array) #EXTEND
#response = cs.recv(1024) #EXTENDED (entry node)
#print("Received: " + response.decode('utf-8'))
#
#node_arr = [3,3,node_addr[1],'EXTEND2']
#array = pickle.dumps(node_arr)
#
#cs.send(array) #EXTEND
#response = cs.recv(1024) #EXTENDED (entry node)
#print("Received: " + response.decode('utf-8'))
print("CIRCUIT CREATED!")


while True:
    message = input('Say Something: ')
    for x in range(len(node_addr)-1) :
        print(message)
        print(type(message))
        print(shared_onion_keys_arr[x])
        ciphertext = aes_encrypt(shared_onion_keys_arr[x],message)
        message = ciphertext
    node_arr = [3,3,node_addr[0],'RELAY',str.encode(message)]
    print(len(message))
    print("Sending cell: " + str(node_arr))
    array = pickle.dumps(node_arr)
    cs.send(array)
    response = cs.recv(1024).decode()
    print("Received from Server: {}".format(response))

cs.close()

#s.close()

#Wrapping Layers
print("UP TO WRAPPING LAYERS")
message = wrap_layers(msg, node_addr, pubkeys)
print(message)

# Send Message
# ----------------------------------------------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_addr[i], PORT))
s.send(message)
s.close()

# Receive Message
# ----------------------------------------------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

