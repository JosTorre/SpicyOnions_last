# SweetOnions - Making Onion Routing Great Again

The purpose of SweetOnions is to emulate a smaller-scale version of onion routing using Python 3. 

There will be a client, server, directory, and three onion routing nodes through which the client can send and receive encrypted messages.
Each message uses asymmetric encryption - the message itself is encrypted with 192-bit AES and the AES key is subsequently encrypted with 2048-RSA to ensure the sender is anonymized. 

## Installation

You need Python**3** or higher.

## Usage

This tool requires a minimum of five machines (2 onion routing nodes) and six machines (3 onion routing nodes) to operate in order to simulate a TOR/onion routing network. The machines should be running as follows:

__Machine 1__: ./client.py (This will request the user to enter the directory node's IP address as well as the message the user would like to send)

__Machine 2__: ./directory.py

__Machine 3__: ./node.py --generate-keys

__Machine 4__: ./node.py --generate-keys

__Machine 5__: ./node.py --generate-keys (Each node will request the directory node's IP address) [Optional Machine]

__Machine 6__: ./server.py

## Demo

The following is a video demo of SweetOnions running across six machines: https://www.youtube.com/playlist?list=PLPNnD5CzODl0AT8zfREUCfGqaUXMoN9Dm

## How it Works

The following is a breakdown of what each aspect of the project accomplishes. 

Firstly in a general manner :

* The directory server waits for the operational nodes addresses and public keys
* The nodes send their public keys at launch time
* When the directory has every key it sends the dictionnary to all nodes
* Then it sends the dictionnary for each client request

We will tend to use mainly bytes and cast to string when necessary

### 1. client.py

This is the front-end tool that allows users to send and receive messages from the server. Upon receiving the message from the server, the client will compare the hashes of the sent and received messages to ensure integrity. 

The client must first contact the directory node in order to receive a list of potential onion routing nodes and their RSA public keys. The client will randomly select the path through which the message will be sent, and it will encrypt the message in the following manner, where Node 3 is the exit node and Node 1 is the entrance node:

a) AES Encrypt via Node 3's AES Key the following: [message + Node3_IP]

b) RSA Encrypt Node 3's AES Key with Node 3's public RSA key: [Node3_AESKey]

c) Concatenate the two encrypted messages - this is the inner most layer and the process will repeat two more times.

By the end of the encryption scheme, the following is the result:

_Layer 1_: AES[message + DestinationIP] + RSA[Node3_AESKey]

_Layer 2_: AES[AES[message + DesinationIP] + RSA[Node3_AESKey] + Node3_IP] + RSA[Node2_AESKey]

_Layer 3_: AES[AES[AES[message + DestinationIP] + RSA[Node3_AESKey] + Node2_IP] + RSA[Node2_AESKey] + Node1_IP] + RSA[Node1_AESKey]

It is the each node's responsibility to unwrap each layer via its RSA private key and continue to send the message along.

### 2. directory.py

The directory node is designed to send the client (upon request) the list of node IP's and their corresponding public RSA keys. Before the client can make a valid request to the directory node, each onion routing node must first send its IP and its RSA public key to the directory - this is an initialization phase.

### 3. node.py

This represents each onion routing node (and has cases for both entrance and exit nodes) and must unwrap one layer of encryption and send the message along. The decryption occurs as follows:

__Message Sent to Node__: AES[AES[message + DestinationIP] + RSA[Node3_AESKey] + Node3_IP] + RSA[Node2_AESKey]

Node 2 uses its private RSA key to obtain the AES Key, and then uses that AES Key to encrypt the remaining contents. The result is:

__Message Node 2 Sends to Node 3__: AES[message + DestinationIP] + RSA[Node3_AESKey]

### 4. server.py

The purpose of server is to simply receive messages and send the hashed version of the message back to the original exit node. 
