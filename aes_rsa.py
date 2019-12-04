#!/usr/bin/env python3
# coding: utf-8

# This file contains functions used for multi-layered encryption
import os
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

BLOCK_SIZE = 16
PADDING = '{'

def pad(msg: str) -> str:
    return msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * PADDING

#Generates an AES key
#Returns base64 encoded AES key
def genAESKey():
	secret = os.urandom(BLOCK_SIZE)
	return b64encode(secret)

#Generates an RSA key
#returns a tuple with public key as the first value and private key as the second
def genRSAKey():
	new_key = RSA.generate(2048, e=65537)
	public_key = new_key.publickey().exportKey('PEM') 
	private_key = new_key.exportKey('PEM') 
	return (public_key, private_key)

#Encrypts using AES
#Arguments are the key, then the message
#returns the encrypted message
def encryptAES(key: str, msg: str) -> str:
    """Encrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to encrypt
    :type key: str
    :type msg: str
    :return: The encrypted message in base 64
    :rtype: str
    """
    padded_msg = pad(msg)

    cipher = AES.new(b64decode(key))
    encrypted = cipher.encrypt(padded_msg)

    return b64encode(encrypted)

#Decrypts using AES
#Arguments are the key, then the encrypted message
#returns the decrypted message
def decryptAES(key: str, msg: str) -> str:
    """Decrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to decrypt encoded in base 64
    :type key: str
    :type msg: str
    :return: The cleartext
    :rtype: str
    """

    uncipher = AES.new(b64decode(key))
    # Get the string representation
    decrypted = uncipher.decrypt(b64decode(msg)).decode()
    # Remove the padding put before
    decrypted = decrypted.rstrip(PADDING)

    return decrypted

#Encrypts using RSA public key
#Arguments are public key and message
#returns encrypted message
def encryptRSA(pubKey, msg):
	pubKeyObj =  RSA.importKey(pubKey)
	encryptedMsg = pubKeyObj.encrypt(msg, 32)[0]
	return encryptedMsg

#Decrypts using RSA private key
#Arguments are private key and encrypted message
#returns decrypted message
def decryptRSA(privKey, msg):
	privKeyObj = RSA.importKey(privKey)
	decryptedMsg = privKeyObj.decrypt(msg)
	return decryptedMsg

#Encrypts using both AES and RSA
#Arguments are AES key, then RSA public key, then message
#returns tuple containing encrypted AES key, then encrypted message
def encryptAESRSA(aesKey, rsaKey, msg):
	encryptedMsg = encryptAES(aesKey, msg)
	encryptedKey = encryptRSA(rsaKey, aesKey)
	return (encryptedKey, encryptedMsg)

#Decrypts using both AES and RSA
#Arguments are encrypted AES key, then RSA private key, then encrypted message
#returns the decrypted message
def decryptAESRSA(aesKey, rsaKey, msg):
	decryptedKey = decryptRSA(rsaKey, aesKey)
	decryptedMsg = decryptAES(decryptedKey, msg)
	return decryptedMsg

#Encrypts using both AES and RSA after generating the AES key itself
#Arguments are RSA public key, then message
#returns tuple containing encrypted AES key, then encrypted message
def easyEncrypt(rsaKey, msg):
	return encryptAESRSA(genAESKey(), rsaKey, msg)

