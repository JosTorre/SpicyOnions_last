#!/usr/bin/env python3
# coding: utf-8

 
import os
import socket, pickle, sys, secrets
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
CONFIG_FILE = "spicy_onions.cfg" 

# Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)
#os.chdir('/home/spice/spiceonion/SpicyOnionsGit/src/')

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
# ----------------------------------------------------------------i

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
#print(dir_arr)
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

 

while i < 3:
    pubkeys.append(in_keys[y[i]])
    node_addr.append(in_addr[y[i]])
    i+=1
#print(node_addr)
#print(node_addr)
 

# Create Key
# ----------------------------------------------------------------

 

private_onion_key = X25519PrivateKey.generate()

 

private_bytes = private_onion_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
)
public_onion_key = private_onion_key.public_key()

 

public_bytes = public_onion_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
)

 

# Create Circuit
# ----------------------------------------------------------------

 
circuits = []
streams = []
counter = len(node_addr)
relays = ['CREATE','EXTEND','EXTEND2']
front = socket.socket()
print('Connecting to Entry Node')
try:
   front.connect((node_addr[i], PORT))
except socket.error as e:
    print(str(e))

 

backend = default_backend()




def CreateCircuit(ips, public_bytes):
    """
    CreateCircuit(argument1,argument2)

        Name: CreateCircuit 
        
        Send and recive create and extend cells for the circuit ceation.

        Parameters:

        argument1 (String Array): Array of string containing Node IP-Adresses
        argument2 (String): Public Bytes for Key Exchange

    """
    for x in range(0, len(ips)-1):
        if x == 0:
            create = CreateCell(public_bytes)
            print(create) #prints cells contents
            #create.print_type() # prints cell attribut types
            circuits.append(create.circID)
            forward(create)
            response = load(front.recv(1024))
            shared_onion_keys_arr.append(HKDFKey(response.hdata))
            if response.command == b'\x00\x0b': #CREATED2
                print(response)
            else:
                print("NOT CREATED!")
        else:
            extend = ExtendCell(ips[x], public_bytes)
            print(extend) #prints cells contents
            forward(extend)
            response = load(front.recv(1024))
            shared_onion_keys_arr.append(HKDFKey(response.hdata))
            if response.command == b'\x00\x0f': # EXTENDED
                print(response)
            else:
                print("NOT EXTENDED!")
    print("Shared Keys")
    print(shared_onion_keys_arr)
    print("CIRCUIT CREATED")

def Communicate(ip, keys):
    """
    Communicate(argument1,argument2)
        Name: Communicate

        Send and recive messages over the circuit

        Parameter:
        argument1 (String Array): Array of strings containing Node IP-Adresses
        argument2 (String Array): Array of strings containing keys for encrytion
    """
    open_channel = True
    streams.append(secrets.token_hex(2))
    while open_channel:
        message = input('Say Something: ')
        if message == "DESTROY":
            print("Sending Destroy Cell")
            reason = 0
            destroy = DestroyCell(reason.to_bytes(2, 'big'))
            destroy.set_circuit_id(circuits[0])
            print(destroy)
            #destroy.print_type()
            forward(destroy)
            streams.clear()
            front.close()
            open_channel = False
            print('CIRCUIT DESTROYED!')
        else:
            relay = RelayCell(ip[0], message)
            #relay.print_type() # print cell Attribute types
            relay.full_encrypt(shared_onion_keys_arr)
            print(relay) #prints cell contentsi
            forward(relay)
            cell = load(front.recv(1024))
            cell.full_decrypt(shared_onion_keys_arr)
            #cell.payload = b64decode(cell.payload)
            msg = cell.payload
            stripped_msg = msg.rstrip('=') 
            print(cell.payload)
            #print("Received from Server: {}".format(response.message))

    print("Communication finished!")

def forward(cell):
    """
    forward(agument1)
        Name: Forward

        Take object in argument1, converts it with pickle and sends it to the next Node.

        Parameter:
        argument1(object): Object to send to the next node.
    """
    pickled_cell = pickle.dumps(cell)
    front.send(pickled_cell)
    
def load(data):
    """
    load(argument1)
        Name: Load

        Loads object in argument1 with pickle an returns the object

        argument1(bytes): converts bytes via pickle to object

        return: converted object
    """
    cell = pickle.loads(data)
    return cell
    
def HKDFKey(secret):
    """
    HKDFKey(argument1)
        Name: HKDFKey

        Key derivation function. Takes secret in argument1 and derives key.

        argument1: Value for key derivation

        return: Key
    """
    peer_public = x25519.X25519PublicKey.from_public_bytes(secret)
    shared_onion_key = private_onion_key.exchange(peer_public)
    derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=backend
    ).derive(shared_onion_key)
    return derived_key

CreateCircuit(node_addr, public_bytes)
Communicate(node_addr, pubkeys)
