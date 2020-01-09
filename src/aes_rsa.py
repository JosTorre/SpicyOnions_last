#!/usr/bin/env python3
# coding: utf-8

# This file contains functions used for multi-layered encryption
from os import urandom
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

BLOCK_SIZE: int = 16
PADDING: str = '{'

def pad(msg: str) -> str:
    """Pad message in order to have 16 bytes blocks

    :return: The padded message
    :rtype: bytes
    """
    if isinstance(msg,str):
        return msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * PADDING
    else:
        raise TypeError("The variable msg must be a string")

def gen_aes_key() -> bytes:
    """Create new key usable by AES

    Generate a random secret key using urandom

    :return: The key encoded in base 64
    :rtype: bytes
    """
    secret: bytes = urandom(BLOCK_SIZE)
    return b64encode(secret)

def gen_rsa_key():
    """Create new keypair usable by RSA

    Returns a tuple with public key as the first value and private key as the second

    :return: The private and public keys in PEM
    :rtype: bytes, bytes
    """

    new_key = RSA.generate(2048, e=65537)
    public_key: bytes = new_key.publickey().exportKey('PEM')
    private_key: bytes = new_key.exportKey('PEM')

    return public_key, private_key

def aes_encrypt(key: bytes, msg: str) -> bytes:
    """Encrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to encrypt
    :type key: bytes
    :type msg: str
    :return: The encrypted message in base 64
    :rtype: bytes
    """

    if not isinstance(msg,str):
        raise TypeError("The variable msg must be a string")
    if not isinstance(key,bytes):
        raise TypeError("The variable key must be bytes")

    padded_msg: str = pad(msg)

    cipher = AES.new(b64decode(key))
    encrypted: bytes = cipher.encrypt(padded_msg)

    return b64encode(encrypted)

def aes_decrypt(key: bytes, msg: bytes) -> bytes:
    """Decrypt msg using AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to decrypt encoded in base 64
    :type key: bytes
    :type msg: bytes
    :return: The cleartext
    :rtype: bytes
    """

    if not isinstance(msg,bytes):
        raise TypeError("The variable msg must be bytes")
    if not isinstance(key,bytes):
        raise TypeError("The variable key must be bytes")

    uncipher = AES.new(b64decode(key))
    # Get the string representation
    decrypted: str = uncipher.decrypt(b64decode(msg)).decode()
    # Remove the padding put before
    decrypted = decrypted.rstrip(PADDING)

    return decrypted

def rsa_encrypt(pub_key: bytes, msg: str) -> str:
    """Encrypts using RSA public key

    :param priv_key: The RSA private key
    :param msg: The encrypted message
    :type pub_key: bytes
    :type msg: str
    :return: The encrypted message
    :rtype: bytes
    """

    if not isinstance(msg,str):
        raise TypeError("The variable msg must be a string")
    if not isinstance(pub_key,bytes):
        raise TypeError("The public key must be bytes")

    pub_key_obj =  RSA.importKey(pub_key)
    encrypted: bytes = pub_key_obj.encrypt(bytes(msg,"utf-8"), "")[0]
    return encrypted

def rsa_decrypt(priv_key: bytes, msg: bytes) -> bytes:
    """Decrypts using RSA private key

    :param priv_key: The RSA private key
    :param msg: The encrypted message
    :type priv_key: bytes
    :type msg: bytes
    :return: The cleartext
    :rtype: bytes
    """

    if not isinstance(msg,bytes):
        raise TypeError("The variable msg must be bytes")
    if not isinstance(key,bytes):
        raise TypeError("The variable key must be bytes")

    priv_key_obj = RSA.importKey(priv_key)
    decrypted: bytes = priv_key_obj.decrypt(msg)

    return decrypted

def aes_rsa_encrypt(aes_key: bytes, rsa_key: bytes, msg: str):
    """Encrypts msg using both AES and RSA

    :param aes_key: The AES key
    :param rsa_key: The RSA public key
    :param msg: The message
    :type aes_key: bytes
    :type rsa_key: bytes
    :type msg: str
    :return: The encrypted AES key, the encrypted message
    :rtype: bytes, bytes
    """

    if not isinstance(msg,str):
        raise TypeError("The variable msg must be a string")
    if not isinstance(rsa_key,bytes):
        raise TypeError("The variable rsa_key must be bytes")
    if not isinstance(aes_key,bytes):
        raise TypeError("The variable aes_key must be bytes")

    encrypted_msg: bytes = aes_encrypt(aes_key, msg)
    encrypted_key: bytes = rsa_encrypt(rsa_key, aes_key.decode())
    return encrypted_key, encrypted_msg

def aes_rsa_decrypt(aes_key: bytes, rsa_key: bytes, msg: bytes) -> bytes:
    """Decrypts using both AES and RSA

    :param aes_key: The encrypted AES key
    :param rsa_key: The RSA private key
    :param msg: The encrypted message
    :type aes_key: bytes
    :type rsa_key: bytes
    :type msg: bytes
    :return: The decrypted message
    :rtype: str
    """

    if not isinstance(msg,bytes):
        raise TypeError("The variable msg must be bytes")
    if not isinstance(rsa_key,bytes):
        raise TypeError("The variable rsa_key must be bytes")
    if not isinstance(aes_key,bytes):
        raise TypeError("The variable aes_key must be bytes")

    decrypted_key: bytes = rsa_decrypt(rsa_key, aes_key)
    decrypted_msg = aes_decrypt(decrypted_key, msg)
    return decrypted_msg

def easy_encrypt(rsa_key: bytes, msg: str):
    """Encrypts using both AES and RSA after generating the AES key itself

    :param rsa_key: The RSA public key
    :param msg: The message to encrypt
    :return: The encrypted AES key, the encrypted message
    :rtype: bytes, bytes
    """

    if not isinstance(msg,str):
        raise TypeError("The variable msg must be a string")
    if not isinstance(rsa_key,bytes):
        raise TypeError("The variable key must be bytes")

    return aes_rsa_encrypt(gen_aes_key(), rsa_key, msg)
