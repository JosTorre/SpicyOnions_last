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

# Read configuration
CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

DIR_PORT = int(config['DIRECTORY']['Port'])
ONION_ROUTER: str = config["MESSAGES"]["OnionRouter"]
SEP: str = config["MESSAGES"]["Separator"]
priv_key_file: str = config['NODE']['PrivateKeyFilename']
pub_key_file: str = config['NODE']['PublicKeyFilename']
PORT: int = int(config['DEFAULT']['Port'])
BUFFER_SIZE: str = int(config['DEFAULT']['BufferSize'])

IP = socket.gethostbyname(socket.gethostname())
node_list = {}

# Parse command line arguments
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
    print("Importing RSA key pair.")

    try:
        with open(pub_key_file,'r') as f:
            pub_key = f.read()
        with open(priv_key_file,'r') as f:
            priv_key = f.read()
    except:
        print("Importing keys failed")
        exit()
else:
    parser.print_help()
    exit()

# Send public key to directory
DIR_IP: str = input("Directory server to connect to: ")
print("Sending request to directory server.")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_IP, DIR_PORT))
s.send(bytes(ONION_ROUTER + SEP + pub_key,"utf-8"))
s.close()

# Listen in order to get data from directory
print("Listen for public keys on {}:{}".format(IP,DIR_PORT))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, DIR_PORT))
s.listen(1)

conn, addr = s.accept()
addr = addr[0]
data = conn.recv(BUFFER_SIZE).decode().split(SEP)
print(data)

number_of_nodes: int = int(data[0])
data = data[1:]

print('Connection address: {}'.format(addr))
print("Return data from directory server: ")
for x in range(number_of_nodes):
    node_list[data[2 * x]] = data[2 * x + 1]
    print(data[2 * x] + ":" + data[2 * x + 1])

conn.close()
s.close()

# Run Node
# -----------------------------
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

    encrypted_data = data.split(SEP)
    decrypted_message = aes_rsa_decrypt(encrypted_data[1], priv_key, encrypted_data[0]).split(SEP)
    next_node = decrypted_message[0]

    # Entrance Node Case
    if len(decrypted_message) == 4:
        entrance_flag = decrypted_message[3]
        entrance_addr = addr
        if decrypted_message[3] == ENTRANCE:
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
        s.send(decrypted_message[1] + SEP + decrypted_message[2])
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
        conn.close()
        s.close()
        print("This is the exit node.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((next_node, PORT))
        s.send(decrypted_message[1])

        server_response = s.recv(BUFFER_SIZE)
        s.close()
        
        return_route = decrypted_message[3:]
        return_route.reverse()
        return_message = server_response
        print("Return Route: {}".format(return_route))
        print("Decrypted Message: {}".format(decrypted_message))

        for x in range(len(return_route)):
            return_message = SEP + return_message
            if x != 0:
                return_message = return_route[x-1] + return_message
            encrypted_key, encrypted_msg = easy_encrypt(node_list[return_route[x]], return_message)
            return_message = encrypted_msg + SEP + encrypted_key
            
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((decrypted_message[3], PORT))
        s.send(return_message)
        s.close()
        
    # Continue Listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, PORT))
    s.listen(1)
