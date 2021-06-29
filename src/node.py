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

CONFIG_FILE: str = "spicy_onions.cfg"
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
extends = 0
rs.listen(2)

backend = default_backend()
circuits = []
streams = []
#Circuit Creation
# ----------------------------------------------------------------

def threaded_client(back):
    """
    threaded_client(argument1)
        Name: Threaded_Client

        ???

        argmuent1(???):???
    """
    proceed = True
    while proceed:
        data = back.recv(2048) # We get data from predecesor
        cell = pickle.loads(data)

        proceed = process(cell)
#Functions
# ----------------------------------------------------------------
def calculate_keys(cell):
    """
        calculate_keys(argument1)
            Name: Calculate_Keys

            Key derivation function. Takes object in argument1 and derives key.

            argument1(object): Takes object from circuit creation and uses the value in object.hdata for key derivation
    """
    #Check keys
    #if cell.hlen == 32 :
    peer_public = x25519.X25519PublicKey.from_public_bytes(cell.hdata)
    shared_onion_key = private_onion_key.exchange(peer_public)
    global derived_key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=backend
        ).derive(shared_onion_key)
    print('Shared Key:')
    print(derived_key)

def process(cell):
    
    """
    process(argument1)
        Name: Process

        Takes cells from communication and process them depending on the celltyp

        argument1(object): Cell object ???

    """

    proceed = True
    global extends
    print(cell)
    if cell.command == b'\x00\n': #CREATE2
        calculate_keys(cell)
        circuits.append(cell.circID)
        print("Circuit IDs: {}".format(circuits))
        cell.to_created(public_bytes)
        respond(cell)
    elif cell.command == b'\x00\x0e': #EXTEND2 - 2 Scenarios
        extends += 1
        if extends == 1: #Needs to extend
            connect_front(cell.lspec)
            cell = CreateCell(cell.hdata)
            circuits.append(cell.circID)
            print("Circuit IDs: {}".format(circuits))
            forward(cell)
        else: #Just forward extend
            forward(cell)
        cell = load_front()
        proceed = process(cell)
    elif cell.command == b'\x00\x0b': #CREATED2
        cell.to_extended()
        respond(cell)
    elif cell.command == b'\x00\x0f': #EXTENDED2
        respond(cell)
    elif cell.command == b'\x00\x03': #RELAY // Two options
        cell.decrypt(derived_key)
        streams.append(cell.streamID)
        print('Running Streams: {}'.format(streams))
        if extends == 0: #If its the Exit Node...
            print(cell.data)
            connect_front(cell.data)
            if cell.recognized == b'0' : #Check if Cell is still encrypted
                print("Forwarding to Destination Server")
                forward(cell.payload)
                cell = operate_endnode()
            else: 
                print("Cell not recognized")
                print(cell.show_payload())
        else:
            print('forwarding relay')
            forward(cell)
            cell = operate_node()

    elif cell.command == b'\x00\x04': #DESTROY
        if extends != 0:
            cell.set_circuit_id(circuits[1])
            forward(cell)
            front.close()
        circuits.clear()
        streams.clear()
        print('Circuit IDs: {} & Stream IDs: {}'.format(circuits, streams))
        proceed = False
        back.close()
        print('Circuit Closed!')
    else:
        print(cell.command)
        print("Non Recognized - Dropping Cell.")

    return proceed


def operate_endnode():
    """
    operate_endnode()
        Name: Operate_Endnode

        Function contains actions for messages on the Endnode in the Circuit

        return: Relay Cell

    """
    operate = True
    while operate:
        print("Waiting for Server")
        response = front.recv(1024)
        print("Processing Response")
        resp = pickle.loads(response)
        relay = RelayCell(0, resp)
        relay.encrypt(derived_key)
        #relay.update_stream(circuit[0])
        print("Sending Relay")
        respond(relay)
        print('Waiting for Client')
        relay = load_back()
        if relay.command == b'\x00\x04': # if Destroy
            operate = False
        else:
            relay.update_stream(streams[0])
            relay.decrypt(derived_key)
            print(relay.recognized)
            if relay.is_recognized():
                print(relay)
                forward(relay.payload)
            else:
                print("Relay not recognized")
                print(relay.show_payload())
    return relay

def operate_node():
    """
        operate_node()
            Name: Operate_Node

            Function contains actions for messages on the nodes in the Circuit

            return: Relay Cell

    """
    operate = True
    while operate:
        print("Waiting for Server")
        relay = load_front()
        print("Processing Response")
        relay.encrypt(derived_key)
        #relay.update_stream(stream[0])
        print("Sending Relay")
        respond(relay)
        print("Waiting for Client")
        relay = load_back()
        if relay.command == b'\x00\x04': #Destroy
            operate = False
        else:
            print(relay)
            print("Processing Response")
            relay.update_stream(streams[0])
            relay.decrypt(derived_key)
            forward(relay)
    return relay


def connect_front(ip):
    """
    connect_front(argument1)
        Name: Connect_Front

        Uses the IP-adreese from argument1 to connect to the next node

        argument1: IP-adresse of the next node or destination
    """
    global front
    front = socket.socket() #Initialize Socket for next Node
    try:
      front.connect((ip, PORT)) #Connect with next Node
    except error as e:
      print(str(e))

def load_back():
    """
    load_back()
        Name: Load_Back

        Takes Data and converts it with pickle.

        return: object variable
    """
    data = back.recv(1024)
    cell = pickle.loads(data)
    return cell

def load_front():
    """
    load_front()
        Name: Load_Front

        Takes Data and converts it with pickle.

        return: object variable
    """
    data = front.recv(1024)
    cell = pickle.loads(data)
    print(data)
    return cell

def respond(cell):
    """
    respond(argument1)
        Name: Respond

        Converts Object with pickle and sends it

        argument1(object): cell object to send
    """
    pickled_cell = pickle.dumps(cell)
    back.send(pickled_cell)

def forward(cell):
    """
    Forward(argument1)
        Name: Forward

        Converts Object with pickle and sends it

        argument1(object): cell object to send    
    """
    pickled_cell = pickle.dumps(cell)
    front.send(pickled_cell)
#Run Node
#-----------------------------------------------------------
while True:
    back, address = rs.accept()
    print('Connected to: ' +address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client,(back, ))

rs.close()
