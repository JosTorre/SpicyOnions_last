#!/usr/bin/env python3
# coding : utf-8

import socket, pickle
import argparse
import configparser
from class_cell import RelayCell, ExtendCell, CreateCell, DestroyCell 
from os import chmod, path
from typing import List, Dict
from aes_rsa import *
from _thread import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Init
# ----------------------------------------------------------------

CONFIG_FILE: str = "sweet_onions.cfg"
IP: str = socket.gethostbyname(socket.gethostname())

# Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Set configuration variables
DIR_PORT: int = int(config['DIRECTORY']['Port'])
ONION_ROUTER: str = config["MESSAGES"]["OnionRouter"]
SEP: str = config["MESSAGES"]["Separator"]
ENTRANCE: str = config["MESSAGES"]["Entrance"]
# The keypair filenames to search for/to write to
priv_key_file: str = config['NODE']['PrivateKeyFilename']
pub_key_file: str = config['NODE']['PublicKeyFilename']
# The port on which we will listen
PORT: int = int(config['DEFAULT']['Port'])
BUFFER_SIZE: int = int(config['DEFAULT']['BufferSize'])

# Known nodes
node_list = {}

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="The program will detect and use already existing key if no option is specified")
parser.add_argument("-g", "--generate-keys", action="store_true", help="Generate RSA keypair of node")
args = parser.parse_args()

# Get node's keypair
# ----------------------------------------------------------------

# Check if key generation is needed
if args.generate_keys:
    print("Generating RSA key pair.")
    pub_key, priv_key = gen_rsa_key()

    with open(priv_key_file, 'wb') as f:
        chmod(priv_key_file, 0o600)
        f.write(priv_key)

    with open(pub_key_file, 'wb') as f:
        chmod(pub_key_file, 0o600)
        f.write(pub_key)

elif path.exists(pub_key_file) and path.exists(priv_key_file):
    print("Importing RSA key pair.")

    try:
        with open(pub_key_file, 'rb') as f:
            pub_key = f.read()
        with open(priv_key_file, 'rb') as f:
            priv_key = f.read()
    except:
        print("Importing keys failed")
        exit()
else:
    parser.print_help()
    exit()

# Send public key to directory
# ----------------------------------------------------------------
DIR_IP: str = input("Directory server to connect to: ")
print("Sending request to directory server.")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_IP, DIR_PORT))
s.send(bytes(ONION_ROUTER + SEP, "utf-8") + pub_key)
s.close()

# Listen in order to get data from directory
# ----------------------------------------------------------------
print("Listen for public keys on {}:{}".format(IP, DIR_PORT))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, DIR_PORT))
s.listen(1)

conn, addr = s.accept()
sep_as_bytes: bytes = SEP.encode("UTF-8")
data: List[bytes] = conn.recv(BUFFER_SIZE).split(sep_as_bytes)
number_of_nodes: int = int(data[0])
data: List[bytes] = data[1:]

print("Data received from directory :")
for x in range(number_of_nodes):
    node_list[data[2 * x]] = data[2 * x + 1]
    print("Public key of " + data[2 * x].decode())

conn.close()
s.close()

#Start Relay Servers
# ----------------------------------------------------------------

rs = socket.socket()
ThreadCount = 0

try:
    rs.bind((IP, PORT))
except socket.error as e:
    print(str(e))

# Key Creation
# ----------------------------------------------------------------

private_onion_key = X25519PrivateKey.generate()
public_onion_key = private_onion_key.public_key()
public_bytes = public_onion_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
)

print('Ready for Circuit...')
rs.listen(2)

backend = default_backend()
circuits = []

while True:
    Client, address = rs.accept()
    print('Connected to: ' +address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client,(Client, ))

rs.close()

#Circuit Creation
# ----------------------------------------------------------------

def threaded_client(back):
    proceed = True

    while proceed:
        data = back.recv(2048) # We get data from predecesor
        cell = pickle.loads(data)

        #Check keys
        if cell.hlen == 32 :
            peer_public = x25519.X25519PublicKey.from_public_bytes(cell.hdata)
            shared_onion_key = private_onion_key.exchange(peer_public)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=backend
            ).derive(shared_onion_key)

        print('Shared Secret:')
        print(derived_key)

        proceed = process(cell)

#Functions
# ----------------------------------------------------------------

def process(cell):
    print("proecess")
    extends = 0
    proceed = True

    if cell.command == 10: #CREATE2
        print(cell.type)
        circuits[0] = cell.get_circ_id()
        cell.to_created(public_bytes)
        print(cell.type)
        respond(cell)
    elif cell.type == 13: #EXTEND2 - 2 Scenarios
        extends += 1
        if extends == 1: #Needs to extend
            print(cell.type)
            connect_front(cell.lspec)
            cell = CreateCell(cell.hdata)
            print(cell.type)
            circuits[1] = cell.get_circ_id()
            forward(cell)
        else: #Just forward extend
            print(cell.type)
            forward(cell)
    elif cell.command == 11: #CREATED2
        print(cell.type)
        cell = Extend2Cell.to_extended(cell.hdata)
        print(cell.type)
        respond(cell)
    elif cell.command == 14: #EXTENDED2
        print(cell.type)
        respond(cell)
    elif cell.command == 3: #RELAY // Two options
        cell.decrypt(derived_key)
        if extends == 0: #If its the Exit Node...
            connect_front(cell.data)
            if cell.recognized() : #Check if Cell is still encrypted
                print("Forwarding to Destination Server")
                forward(cell.payload)
                cell = operate_endnode()
            else: 
                print("Cell not recognized")
                print(cell.show_payload())
        else:
            cell.update_stream(circuits[1])
            forward(cell)
            cell = operate_node()

    elif cell.command == 4: #DESTROY
        print("DESTROY")
        proceed = False
        forward(cell)
        respond(cell)
        back.close()
        front.close()
    else:
        print("Non Recognized - Dropping Cell.")

    return proceed


def operate_endnode():
    while operate:
        print("Waiting for Response")
        response = front.recv(1024)
        print("Processing Response")
        relay = RelayCell(0, response)
        relay.encrypt(derived_key)
        relay.update_stream(circuit[0])
        print("Sending Relay")
        respond(relay)

        client_response = back.recv(1024)
        relay = load(client_response)
        if relay.command == 4:
            operate = False
        else:
            relay.decrypt(derived_key)
            if relay.recognized() :
                forward(relay)
            else:
                print("Relay not recognized")
                print(relay.show_payload())
    return relay

def operate_node():
    while operate:
        print("Waiting for Response")
        relay = load_front()
        print("Processing Response")
        relay.encrypt(derived_key)
        relay.update_stream(stream[0])
        print("Sending Relay")
        respond(relay)
        print("Waiting for Response")
        relay = load_back()
        if relay.command == 4:
            operate = False
        else:
            print("Processing Response")
            relay.decrypt(derived_key)
            if relay.recognized() :
                forward(relay)
            else:
                print("Relay not recognized")
                print(relay.show_payload())
    return relay


def connect_front(ip):
    front = socket.socket() #Initialize Socket for next Node
    try:
      front.connect((ip, PORT)) #Connect with next Node
    except error as e:
      print(str(e))

def load_back():
    data = back.recv(1024)
    cell = pickle.loads(data)
    return cell

def load_front():
    data = back.recv(1024)
    cell = pickle.loads(data)
    return cell

def respond(cell):
    pickled_cell = pickle.dumps(cell)
    back.send(pickled_cell)

def forward(cell):
    pickled_cell = pickle.dumps(cell)
    front.send(pickled_cell)

