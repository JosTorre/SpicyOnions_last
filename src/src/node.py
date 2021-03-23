#!/usr/bin/env python3
# coding : utf-8

"""
node.py

Tasks:
Send info to directory node
Decrypt layer of encryption
Relay data onward
On data coming back, decrypt and send to previous node
"""

import socket, pickle
import argparse
import configparser
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

#Circuit Creation
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

def threaded_client(client):
    endnode = False
    flag =0
    #conn.send(str.encode('CREATED'))

    while True:

        data = client.recv(2048) # We get data from Client
        arr = pickle.loads(data)
        content = arr[4]
        print(arr)
        print(len(content))
        if (len(content) == 32) :
            peer_public = x25519.X25519PublicKey.from_public_bytes(content)
            shared_onion_key = private_onion_key.exchange(peer_public)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=backend
            ).derive(shared_onion_key)
        if arr[3] == 'CREATE' or arr[3] == 'CREATE2' : 
            if arr[0] == 1 :
                print("Entry Node")
                print(arr[3])
                print("Entry Node Shared Secret:")
                print(derived_key)
            elif arr[0] != 1 and arr[0] != arr[1]  :
                print("Middle Node")
                print(arr[3])
                print("Middle Node Shared Secret:")
                print(derived_key)
            elif arr[0] == arr[1] :
                endnode = True
                print("Exit Node")
                print(arr[3])
                print("Exit Node Shared Secret:")
                print(derived_key)

            if arr[3] == 'CREATE' :
              arr[3] = "CREATED"
            elif arr[3] == 'CREATE2' :
              arr[3] = "CREATED2"

            peer_public = x25519.X25519PublicKey.from_public_bytes(arr[4])
            arr[4] = public_bytes
            array = pickle.dumps(arr)
            client.send(array)


        elif arr[3] == 'EXTEND' or arr[3] == 'EXTEND2' :
           print(arr[3])
           flag = flag + 1

           if flag == 1 : #Needs to change from extend to create

              ms = socket.socket() #Initialize Socket for next Node
              try:
                ms.connect((arr[2], PORT)) #Connect with next Node
              except error as e:
                print(str(e))

              if arr[3] == 'EXTEND' :
                arr[3] = 'CREATE' 
                print('EXTEND -> CREATE')
              elif arr[3] == 'EXTEND2' :
                arr[3] = 'CREATE2'
                print('EXTEND2 -> CREATE2')

              nodes = pickle.dumps(arr)
              ms.send(nodes)
              resp = ms.recv(1024)
              arr_resp = pickle.loads(resp)

              if arr_resp[3] == 'CREATED':
                arr_resp[3] = 'EXTENDED'
              elif arr_resp[3] == 'CREATED2' :
                arr_resp[3] = 'EXTENDED2'

              resp = pickle.dumps(arr_resp)
              client.send(resp)

           elif flag > 1 :
              nodes = pickle.dumps(arr)
              ms.send(nodes)
              resp = ms.recv(1024)
              client.send(resp)

        elif arr[3] == 'RELAY' :
            print("RELAY received")
            if endnode :
             ms = socket.socket() #Initialize Socket for Destination Server
             try:
               	ms.connect((arr[2], PORT)) #Connect with Destination Server
             except error as e:
               	print(str(e))
             
             print("Forwarding RELAY")   
             message = arr[4]
             decrypted = aes_decrypt(derived_key, message)
             print(type(decrypted))
             print(decrypted)
             ms.send(decrypted)
             resp = ms.recv(1024)
             client.send(resp)
             while True:
                print("Forwarding to Server")
                response = client.recv(1024)
                arr = pickle.loads(response)
                message = arr[4]
                decrypted = aes_decrypt(derived_key, message)
                print(type(decrypted))
                print(decrypted)
                ms.send(str.encode(decrypted))
                ms_response = ms.recv(1024)
                #arr = str.encode(ms_reponse) 
                #print("Forwarding " + arr[4])
                client.send(ms_response)
             ms.close()
             client.close()
            else :
             message = arr[4]
             decrypted = aes_decrypt(derived_key, message)
             print("Message: " + decrypted)
             arr[4] = decrypted
             nodes = pickle.dumps(arr)
             ms.send(nodes)

             while True:

                print("Passing Relay")
                response = ms.recv(1024)
                client.send(response)
                client_response = client.recv(1024)
                arr = pickle.loads(client_response)
                message = arr[4]
                decrypted = aes_decrypt(derived_key,message)
                print("Message: " + decrypted)
                ms.send(decrypted)
        
             ms.close()
             client.close()



#reply = 'Server Says: ' + data.decode('utf-8')
#if not data:
#   break
#   connection.sendall(str.encode(reply))
#      connection.close()

while True:
    Client, address = rs.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client, (Client, ))
    #ThreadCount += 1
    #print('Thread Number: ' + str(ThreadCount))

rs.close()

# Run Node
# ----------------------------------------------------------------
entrance_flag = ""
entrance_addr = ""

# Start Listening
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, PORT))
s.listen(1)

while 1:
    conn, addr = s.accept()
    addr = addr[0]
    data = conn.recv(BUFFER_SIZE)

    print("[Node Running] Connection address: {}".format(addr))

    if not data: break
    print("[Node Running] Received data: {}".format(data))
    encrypted_data: List[bytes] = data.split(sep_as_bytes)
    decrypted_message: List[bytes] = aes_rsa_decrypt(encrypted_data[1], priv_key, encrypted_data[0]).split(sep_as_bytes)
    next_node = decrypted_message[0]

    # Entrance Node Case
    print(len(decrypted_message))
    print(decrypted_message)
    if len(decrypted_message) == 4:
        entrance_flag = decrypted_message[3]
        entrance_addr = addr
        if decrypted_message[3] == b'entrance':
            print("This is the entrance node receiving initial packet.")
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Send to Next Node
    if next_node in node_list:
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((next_node, PORT))
        s.send(decrypted_message[1] + sep_as_bytes + decrypted_message[2])
        s.close()
        print("This is not an exit node. Nothing special here.")
    # Entrance Node
    elif entrance_flag == ENTRANCE and not next_node:
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((entrance_addr, PORT))
        # original's server response (at least it's supposed to be)
        s.send(decrypted_message[1])
        s.close()
        print("This is the entrance node returning to the client")
        entrance_flag = ""
        entrance_addr = ""
    # Exit Node - Send Data Back
    elif next_node not in node_list:
        # Close the current connection
        conn.close()
        s.close()
        print("This is the exit node.")

        # Return the message
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(next_node)
        print(PORT)
        s.connect((next_node, PORT))
        s.send(decrypted_message[1])
        server_response = s.recv(BUFFER_SIZE)
        s.close()

        return_route = decrypted_message[2:]
        return_route.reverse()
        return_message = server_response
        print("Return Route: {}".format(return_route))
        print("Decrypted Message: {}".format(decrypted_message))

        for x in range(len(return_route)):
            return_message = sep_as_bytes + return_message
            if x != 0:
                return_message = return_route[x - 1] + return_message
            encrypted_key, encrypted_msg = easy_encrypt(node_list[return_route[x]], return_message)
            return_message = encrypted_msg + sep_as_bytes + encrypted_key

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((decrypted_message[3], PORT))
        s.send(return_message)
        s.close()

    # Continue Listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, PORT))
    s.listen(1)
