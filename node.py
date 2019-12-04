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
from os import chmod, path
import argparse
from aes_rsa import *

#DIR_IP = '172.17.224.57'
DIR_PORT = 1600

TCP_IP = socket.gethostbyname(socket.gethostname())
TCP_PORT = 1601

BUFFER_SIZE = 4096 
NODES = {}
NUM_NODES = 3

# Generate RSA Keys
# -----------------------------
priv_key_file = "privateRSA.key"
pub_key_file = "publicRSA.key"


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
s.send('Onion Router###' + publicRSA)
s.close()

# Get Directory Data
# -----------------------------
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, DIR_PORT))
s.listen(1)

conn, addr = s.accept()
addr = addr[0]
myData = conn.recv(BUFFER_SIZE).split("###")

NUM_NODES = int(myData[0])
myData = myData[1:]

print('Connection address:', addr)
print("Return data from directory server: ")
for x in range(NUM_NODES):
    NODES[myData[2 * x]] = myData[2 * x + 1]
    print(myData[2 * x] + ":" + myData[2 * x + 1])

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
    nextNode = decryptedMessage[0]

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
    if nextNode in NODES:
        conn.close()
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((nextNode, TCP_PORT))
        s.send(decryptedMessage[1] + "###" + decryptedMessage[2])
        s.close()
        print("This is not an exit node. Nothing special here.")
        
    # Entrance Node
    elif entranceFlag == "entrance" and not nextNode:

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
    elif nextNode not in NODES:
        conn.close()
        s.close()
        print("This is the exit node.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((nextNode, TCP_PORT))
        s.send(decryptedMessage[1])

        serverResponse = s.recv(BUFFER_SIZE)
        s.close()
        
        returnRoute = decryptedMessage[3:]
        returnRoute.reverse()
        returnMessage = serverResponse
        print("Return Route: ")
        print(returnRoute)
        print("Decrypted Message:")
        print(decryptedMessage)

        for x in range(len(returnRoute)):
            returnMessage = "###" + returnMessage
            if x != 0:
                returnMessage = returnRoute[x-1] + returnMessage
            encryptedKey, encryptedMsg = easy_encrypt(NODES[returnRoute[x]], returnMessage)
            returnMessage = encryptedMsg + "###" + encryptedKey
            
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((decryptedMessage[3], TCP_PORT))
        s.send(returnMessage)
        s.close()
        
    # Continue Listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)
