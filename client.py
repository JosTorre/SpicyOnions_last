'''
client.py
Client should do the following things in order:
1. Get list of node ip addresses and public keys from directory node
2. Pick a random ordering of 3 of these nodes
3. Get user input for info to send
4. Add encryption layers onto the packet being sent
5. Send onion packet to first node
6. Wait on return packet from the server
7. Compare returned hash to hash of sent packet
8. Repeat from step 3
'''
import sys
from os import chmod
import socket
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import random
import hashlib

DIR_PORT = 1600
TCP_PORT = 1601
BUFFER_SIZE = 4096
DIR_NODE = '127.0.0.1' #change this


private_key_file = "private.key"
public_key_file = "public.key"

# when the command line argument for generating a key pair is passed
if len(sys.argv) == 2 and sys.argv[1] == "-genKey":
    new_key = RSA.generate(2048, e=65537) 
    public_key = new_key.publickey().exportKey('PEM') 
    private_key = new_key.exportKey('PEM') 
    with open(private_key_file, 'w') as content_file:
        chmod(private_key_file, 0600)
        content_file.write(private_key)
    with open(public_key_file, 'w') as content_file:
        content_file.write(public_key)
elif len(sys.argv) == 1:
    print "importing keys"
    
else:
    print "Incorrect arguments"
    sys.exit()

try:
    key_file = open(private_key_file, "r").read()
    rsakey = RSA.importKey(key_file)
    ownpubkey = rsakey.publickey().exportKey('PEM')
except:
    print "failed to import keys"
    exit()

dest_ip = raw_input("Destination Address: ")
mes =  raw_input("Message: ")
mes_hash = hashlib.sha224(mes).hexdigest()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DIR_NODE, DIR_PORT))
while 1:
	s.send('Client Request,' + ownpubkey)
	dir_data = s.recv(BUFFER_SIZE)
        print(dir_data)
	if dir_data and "Not ready yet" in dir_data: 
            print("directory server not ready")
            exit()
	#sleep(1)
s.close()

decrypted = rsakey.decrypt(dir_data)
print decrypted
#parse the directory data string
#code goes here
in_keys = []
in_addr = []
dir_arr = decrypted.split(',')
for x in dir_arr:
	if '.' in x:
		in_addr.append(x)
	else:
		in_keys.append(x)
i = 0
for x in random.shuffle(range(0,2)):
	pubkeys[i] = RSA.importKey(in_keys[x])
	node_addr[i+1] = in_addr[x]
	i+=1
node_addr[0] = dest_ip

def wrap_layers(message, nodes, public_keys):
	message = message + ',' + nodes[2] + ',' + nodes[1] + ',' + nodes[0]
	for x in range(0,2):
		message = nodes[x] + ',' + message
		if x == 2:
			message = message + ',' + 'entrance'
		message = public_keys[x].encrypt(message, 32)

wrap_layers(mes, node_addr, pubkeys)

# Send Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((node_addr[i], TCP_PORT))
s.send(mes)
s.close()

# Recieve Message
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

while 1:
	conn, addr = s.accept()
        addr = addr[0]
	if addr == node_addr[len(node_addr) - 1]:
		data = conn.recv(BUFFER_SIZE)
		if data == mes_hash:
			print "Received data matches hash: ", data
			break
		else:
			print "Received data does not match hash: ", data
			break

