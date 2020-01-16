#!/usr/bin/env python3
# coding : utf-8
"""
Maintain a list of available nodes (Node Name, IP Address, Public Key) for clients
to access. Upon request, provide three nodes (entry, onion router, exit) for the client. 
This should also be able to communicate with the other available nodes and obtain 
their information (i.e. changing public keys, etc.).
"""

import socket
import argparse
import configparser
from time import sleep

# Init
# ----------------------------------------------------------------
CONFIG_FILE = "sweet_onions.cfg"

#  Read configuration
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

NUM_NODES: int = int(config["DIRECTORY"]["NumberNode"])
# Define all standard messages/communications transmitted with the nodes
NOT_READY_MSG: bytes = bytes(config["MESSAGES"]["NotReady"], "utf-8")
CLIENT_MSG: str = config["MESSAGES"]["ClientRequest"]
ONION_ROUTER: str = config["MESSAGES"]["OnionRouter"]
SEP: str = config["MESSAGES"]["Separator"]
DIR_PORT: int = int(config["DIRECTORY"]["Port"])
NB_CONN: int = int(config["DIRECTORY"]["SimultaneousConnections"])
BUFFER_SIZE: int = int(config["DIRECTORY"]["BufferSize"])

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-n", "--number-of-nodes", action="store_true", help="Specify the number of active nodes")
args = parser.parse_args()

DIR_IP: str = socket.gethostbyname(socket.gethostname())
print("Directory IP : {}".format(DIR_IP))
router_count: int = 0
pub_keys = {}

# Open socket
# ----------------------------------------------------------------
directory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
directory_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
directory_server.bind((DIR_IP, DIR_PORT))
directory_server.listen(NB_CONN)

# Listen for node's public key
# ----------------------------------------------------------------
while router_count < NUM_NODES:
    client_socket, client_address = directory_server.accept()
    client_address = client_address[0]
    data_received = client_socket.recv(BUFFER_SIZE).decode()
    print("Connection from: {}".format(client_address), end="")

    # Initialization: Communicate with all onion routers until all keys are stored.    
    data = data_received.split(SEP)
    if data[0].strip() == ONION_ROUTER:
        pub_keys[client_address] = data[1].strip()  # add to the dictionary
        router_count += 1
        print("\t| Public key received")
    # If a client connects too early, tell it...
    elif data[0].strip() == CLIENT_MSG:
        client_socket.send(NOT_READY_MSG)
        print("\t| Not ready signal sent")

    client_socket.close()

# Close directory server
directory_server.close()
sleep(1)

# Send all node's public keys to all nodes
# ----------------------------------------------------------------
directory_content = bytes(str(NUM_NODES), "utf-8")
for key in pub_keys:
    directory_content += bytes(SEP + str(key) + SEP + str(pub_keys[key]), "utf-8")

for addr in pub_keys:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, DIR_PORT))
    conn.send(directory_content)
    conn.close()

sleep(1)

# Make sure socket is closed
# ----------------------------------------------------------------
directory_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
directory_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
while (1):
    try:
        directory_server.bind((DIR_IP, DIR_PORT))
        break
    except:
        pass

# Wait for clients to connect
# ----------------------------------------------------------------
directory_server.listen(NB_CONN)

while 1:
    client_socket, client_address = directory_server.accept()
    data_received = client_socket.recv(BUFFER_SIZE).decode()

    data = data_received.split(SEP)
    # Initialization complete. 
    if CLIENT_MSG == data[0]:
        # Send client the dictionary of nodes as well
        client_socket.send(directory_content)

    client_socket.close()

