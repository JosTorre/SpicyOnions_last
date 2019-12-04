#!/usr/bin/env python3
# coding : utf-8
"""
Maintain a list of available nodes (Node Name, IP Address, Public Key) for clients
to access. Upon request, provide three nodes (entry, onion router, exit) for the client. 
This should also be able to communicate with the other available nodes and obtain 
their information (i.e. changing public keys, etc.).
"""

import socket
import configparser
from time import sleep
from aes_rsa import *

CONFIG_FILE = "sweet_onions.cfg"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

NUM_ROUTERS = int(input("Number of routers before running: "))
NUM_NODES = config["DIRECTORY"]["NumberNode"]

router_count = 0
pub_keys = {}

DIR_IP = socket.gethostbyname(socket.gethostname()) #'127.0.0.1' for testing
DIR_PORT = config["DIRECTORY"]["Port"]
NB_CONN = config["DIRECTORY"]["SimultaneousConnections"]
BUFFER_SIZE = config["DIRECTORY"]["BufferSize"]

directory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
directory_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
directory_server.bind((DIR_IP, DIR_PORT))
directory_server.listen(NB_CONN)

print()
# Begin listening for onion routers
while router_count < NUM_ROUTERS:
    client_socket, client_address = directory_server.accept()
    client_address = client_address[0]
    data_received = client_socket.recv(BUFFER_SIZE)
    print("Connection from: " + str(client_address))
    
    # Initialization: Communicate with all onion routers until all keys are stored.    
    data = data_received.split("###")
    if data[0].strip() == "Onion Router":
        pub_keys[client_address] = data[1].strip() #add to the dictionary
        router_count += 1
        print("Onion router information received :\n{}\n".format(data[1]))
    
    # If a client connects too early, tell it...
    elif data[0].strip() == "Client Request":
        client_socket.send("Not ready yet")
    client_socket.close()

print("Dictionary of nodes:")
for key in pub_keys:
    print(x + " : " + pub_keys[x])

directory_server.close()
sleep(1)

#Sending serialized dictionary to all nodes
message = ""                                                 
for key in pub_keys.keys():
    message += "###" + str(key) + "###" + str(pub_keys[key])
message = str(NUM_ROUTERS) + "###" + message[3:]
for key in pub_keys.keys():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((str(key), DIR_PORT))
    conn.send(message)
    conn.close()

sleep(1)

# Make sure socket is closed
directory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
directory_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
while (1):
    try:
        directory_server.bind((DIR_IP, DIR_PORT))
        break
    except:
        pass
    
directory_server.listen(NB_CONN)

# Wait for clients to connect
while 1:
    client_socket, client_address = directory_server.accept()
    client_address = client_address[0]
        data_received = client_socket.recv(BUFFER_SIZE)
    
    data = data_received.split("###")
    # Initialization complete. 
    if "Client Request" == data[0]:

        # Send client the dictionary of nodes as well
        client_socket.send(message)
    
    client_socket.close()

directory_server.close()
