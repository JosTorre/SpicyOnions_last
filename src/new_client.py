#!/usr/bin/env python3
# coding: utf-8

 

import socket, pickle
import configparser
from class_cell import RelayCell, ExtendCell, CreateCell, DestroyCell
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

 

# Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

 

DIR_PORT: int = int(config["DIRECTORY"]["Port"])
PORT: int = int(config["DEFAULT"]["Port"])
BUFFER_SIZE: int = int(config["DEFAULT"]["BufferSize"])
SEP: str = config["MESSAGES"]["Separator"]
CLIENT_REQ: str = config["MESSAGES"]["ClientRequest"]
NOT_READY_MSG: str = config["MESSAGES"]["NotReady"]

 

DIR_NODE: str = input("Directory server to connect to: ")

 

# Connect to directory to get nodes's public keys
# ----------------------------------------------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_NODE, DIR_PORT))

 

# Send and receive message from directory
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

CreateCircuit(node_addr, public_bytes)

Communicate(node_addr, pubkeys)


def CreateCircuit(ips, public_bytes):
    for x in range(0, len(ips)):
        if x == 0:
            create = CreateCell(public_bytes)
            forward(create)
            response = load(cs.recv(1024))
            shared_onion_keys_arr.append(HKDF(cell.hdata))
            if response.command == 11:
                print("CREATED")
            else:
                print("NOT CREATED!")
        else:
            extend = ExtendCell(arr[x])
            forward(extend)
            response = load(cs.recv(1024))
            shared_onion_keys_arr.append(HKDF(cell.hdata))
            if response.command == 14:
                print("EXTENDED")
            else:
                print("NOT EXTENDED!")

    print("CIRCUIT CREATED")

def Communicate(ip, keys):
    open_channel = True
    while open_channel:
        message = input('Say Something: ')
        if message == "DESTROY":
            reason = input('Give a reason: ')
            destroy = DestroyCell(reason)
            forward(destroy)
            open_channel = False
        else:
            relay = RelayCell(ip[0], message)
            relay.full_encrypt(keys)
            forward(relayCell)
            cell = load(cs.recv(1024))
            cell.full_decrypt(keys)
            print(cell.payload)
            #print("Received from Server: {}".format(response.message))

    print("Communication finished!")

def forward(cell):
    pickled_cell = pickle.dumps(cell)
    front.send(pickled_cell)
    
def load(data):
    cell = pickle.loads(data)
    return cell
    
def HKDF(secret):
    peer_public = x25519.X25519PublicKey.from_public_bytes(secret)
    derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=backend
    ).derive(shared_onion_key)
    return derived_key

