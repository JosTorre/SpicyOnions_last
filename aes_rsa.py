#!/usr/bin/env python3
# coding: utf-8

# This file contains functions used for multi-layered encryption
from os import urandom
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

BLOCK_SIZE = 16
PADDING = '{'

def pad(msg: str) -> str:
    return msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * PADDING

def gen_aes_key() -> str:
    """Create new key usable by AES

    Generate a random secret key using urandom

    :return: The key encoded in base 64
    :rtype: str
    """
    secret = urandom(BLOCK_SIZE)
    return b64encode(secret)

def gen_rsa_key():
    """Create new keypair usable by RSA

    Returns a tuple with public key as the first value and private key as the second

    :return: The private and public keys in PEM
    :rtype: str, str
    """

    new_key = RSA.generate(2048, e=65537)
    public_key = new_key.publickey().exportKey('PEM').decode()
    private_key = new_key.exportKey('PEM').decode()

    return public_key, private_key

def aes_encrypt(key: str, msg: str) -> bytes:
    """Encrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to encrypt
    :type key: str
    :type msg: str
    :return: The encrypted message in base 64
    :rtype: bytes
    """
    padded_msg = pad(msg)

    cipher = AES.new(b64decode(key))
    encrypted = cipher.encrypt(padded_msg)

    return b64encode(encrypted)

#Decrypts using AES
#Arguments are the key, then the encrypted message
#returns the decrypted message
def aes_decrypt(key: str, msg: bytes) -> str:
    """Decrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to decrypt encoded in base 64
    :type key: str
    :type msg: bytes
    :return: The cleartext
    :rtype: str
    """

    uncipher = AES.new(b64decode(key))
    # Get the string representation
    decrypted = uncipher.decrypt(b64decode(msg)).decode()
    # Remove the padding put before
    decrypted = decrypted.rstrip(PADDING)

    return decrypted

def rsa_encrypt(pub_key: str, msg: str) -> str:
    """Encrypts using RSA public key
    :param priv_key: The RSA private key
    :param msg: The encrypted message
    :return: The encrypted message
    :rtype: str
    """

    pub_key_obj =  RSA.importKey(pub_key)
    encrypted = pub_key_obj.encrypt(bytes(msg,"utf-8"), "")[0]
    return encrypted

def rsa_decrypt(priv_key: str, msg: str) -> str:
    """Decrypts using RSA private key

    :param priv_key: The RSA private key
    :param msg: The encrypted message
    :return: The cleartext
    :rtype: str
    """

    priv_key_obj = RSA.importKey(priv_key)
    decrypted = priv_key_obj.decrypt(msg).decode()

    return decrypted

def aes_rsa_encrypt(aes_key: str, rsa_key: str, msg: str):
    """Encrypts using both AES and RSA
    :param aes_key: The AES key
    :param rsa_key: The RSA public key
    :param msg: The message
    :return: The encrypted AES key, the encrypted message
    :rtype: str, str
    """
    encrypted = aes_encrypt(aes_key, msg)
    encrypted = rsa_encrypt(rsa_key, aes_key)
    return encryptedKey, encryptedMsg

def aes_rsa_decrypt(aes_key: str, rsaKey: str, msg: str) -> str:
    """Decrypts using both AES and RSA

    :param aes_key: The encrypted AES key
    :param rsa_key: The RSA private key
    :param msg: The encrypted message
    :return: The decrypted message
    :rtype: str
    """

    decrypted_key = rsa_decrypt(rsa_key, aes_key)
    decrypted_msg = aes_decrypt(decrypted_key, msg)
    return decrypted_msg

def easy_encrypt(rsa_key: str, msg: str):
    """Encrypts using both AES and RSA after generating the AES key itself

    :param rsa_key: The RSA public key
    :param msg: The message to encrypt
    :return: The encrypted AES key, the encrypted message
    :rtype: str, str
    """
    return aes_rsa_encrypt(gen_aes_key(), rsa_key, msg)
