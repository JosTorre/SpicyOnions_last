#!/usr/bin/env python3
# coding : utf-8

'''
node.py
Tasks:
Send info to directory node
Decrypt layer of encryption
Relay data onward
On data coming back, decrypt and send to previous node
'''

import socket
import argparse
import configparser
from os import chmod, path
from aes_rsa import *

CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

IP = socket.gethostbyname(socket.gethostname())
DIR_PORT =  config['DIRECTORY']['Port']
PORT = config['DEFAULT']['Port']

BUFFER_SIZE = config['DEFAULT']['BufferSize']
node_list = {}
number_of_nodes = 3

priv_key_file = config['DEFAULT']['PrivateKeyFilename']
pub_key_file = config['DEFAULT']['PublicKeyFilename']


# To put in config file
#------------------------------------------------------
# Code

parser = argparse.ArgumentParser(description="The program will detect and use already existing key if no option is specified")
parser.add_argument("-g","--generate-keys", action="store_true", help="Generate RSA keypair of node")
args = parser.parse_args()

if args.generate_keys:
    print("Generating RSA key pair.")
    pub_key, priv_key = gen_rsa_key()

    with open(priv_key_file, 'w') as f:
        chmod(priv_key_file, 0o600)
        f.write(priv_key)

    with open(pub_key_file, 'w') as f:
        chmod(pub_key_file, 0o600)
        f.write(pub_key)
elif path.exists(pub_key_file) and path.exists(priv_key_file):
    print("Importing keys")

    try:
        with open(pub_key_file,'rb') as f:
            pub_key = f.read()
        with open(priv_key_file,'rb') as f:
            priv_key = f.read()
    except:
        print("Importing keys failed")
        exit()
else:
    parser.print_help()
    exit()

DIR_IP = input("Directory server to connect to: ")
print("Sending request to directory server.")
# Update Directory
# -----------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_IP, DIR_PORT))
s.send('Onion Router###' + pub_key)
s.close()

# Get Directory Data
# -----------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, DIR_PORT))
s.listen(1)

conn, addr = s.accept()
addr = addr[0]
data = conn.recv(BUFFER_SIZE).split("###")

number_of_nodes = int(data[0])
data = data[1:]

print('Connection address:', addr)
print("Return data from directory server: ")
for x in range(number_of_nodes):
    node_list[data[2 * x]] = data[2 * x + 1]
    print(data[2 * x] + ":" + data[2 * x + 1])

conn.close()
s.close()

# Run Node
# -----------------------------
entranceFlag = ""
entranceAddr = ""
exitAddr = ""

# Start Listening
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

while 1:
    conn, addr = s.accept()
    addr = addr[0]
    data = conn.recv(BUFFER_SIZE)

    print("[Node Running] Connection address: ", addr)

    if not data: break
    print("[Node Running] Received data: ", data)

    myEncryptedData = data.split("###")
    decryptedMessage = decryptAESRSA(myEncryptedData[1], privateRSA, myEncryptedData[0]).split("###")
    next_node = decryptedMessage[0]

    # Entrance Node Case
    if len(decryptedMessage) == 4:
        entranceFlag = decryptedMessage[3]
        entranceAddr = addr
        if decryptedMessage[3] == "entrance":
            print("This is the entrance node receiving initial packet.")
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Send to Next Node
    if next_node in NODES:
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((next_node, TCP_PORT))
        s.send(decryptedMessage[1] + "###" + decryptedMessage[2])
        s.close()
        print("This is not an exit node. Nothing special here.")
        
    # Entrance Node
    elif entranceFlag == "entrance" and not next_node:

        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((entranceAddr, TCP_PORT))
        # original's server response (at least it's supposed to be)
        s.send(decryptedMessage[1])
        s.close()
        print("This is the entrance node returning to the client")
        entranceFlag = ""
        entranceAddr = ""
        
    # Exit Node - Send Data Back
    elif next_node not in node_list:
        conn.close()
        s.close()
        print("This is the exit node.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((next_node, TCP_PORT))
        s.send(decryptedMessage[1])

        server_response = s.recv(BUFFER_SIZE)
        s.close()
        
        return_route = decryptedMessage[3:]
        return_route.reverse()
        returnMessage = server_response
        print("Return Route: ")
        print(return_route)
        print("Decrypted Message:")
        print(decryptedMessage)

        for x in range(len(return_route)):
            returnMessage = "###" + returnMessage
            if x != 0:
                returnMessage = return_route[x-1] + returnMessage
            encryptedKey, encryptedMsg = easy_encrypt(node_list[return_route[x]], returnMessage)
            returnMessage = encryptedMsg + "###" + encryptedKey
            
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((decryptedMessage[3], TCP_PORT))
        s.send(returnMessage)
        s.close()
        
    # Continue Listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)
