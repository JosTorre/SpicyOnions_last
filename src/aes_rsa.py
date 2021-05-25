#!/usr/bin/env python3
# coding: utf-8

# This file contains functions used for multi-layered encryption
from os import urandom
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
BLOCK_SIZE: int = 16
PADDING: str = '=' # war } vorher

def pad(msg: str) -> str:
    """Pad message in order to have 16 bytes blocks

    :return: The padded message
    :rtype: bytes
    """
    assert isinstance(msg,str), "The variable msg must be a string"
    # (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * PADDING
    msg = msg + (BLOCK_SIZE - len(msg) % BLOCK_SIZE) * PADDING  
    print(len(msg))
    print(msg)
    print(type(msg))
    return msg
        

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

def aes_encrypt(key: bytes, msg: str) -> str:
    """Encrypt msg in AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to encrypt
    :type key: bytes
    :type msg: str
    :return: The encrypted message in base 64
    :rtype: bytes
    """

    assert isinstance(msg,str), "The variable msg must be a string"
    assert isinstance(key,bytes), "The variable key must be bytes"

    padded_msg: str = pad(msg)
    keydigest = hashes.Hash(hashes.SHA256(),backend=backend)
    keydigest.update(key)
    cipher = AES.new(keydigest.finalize())
    encrypted: str = cipher.encrypt(padded_msg)
    encoded = b64encode(encrypted)
    print(encoded)
    return str(encoded, 'utf-8')

def aes_decrypt(key: bytes, msg: bytes) -> bytes:
    """Decrypt msg using AES with key

    :param key: The AES key encoded in base 64
    :param msg: The message to decrypt encoded in base 64
    :type key: bytes
    :type msg: bytes
    :return: The cleartext
    :rtype: bytes
    """

    assert isinstance(msg,str), "The variable msg must be bytes"
    assert isinstance(key,bytes), "The variable key must be bytes"
    keydigest = hashes.Hash(hashes.SHA256(),backend=backend)
    print(msg)
    keydigest.update(key)
    uncipher = AES.new(keydigest.finalize())
    # Get the string representation
    #paddedmsg = pad(msg.decode('utf8','ignore'))
    #b64_msg = b64decode(paddedmsg)
    #print(b64_msg)
    decoded = b64decode(msg)
    decrypted: str = uncipher.decrypt(decoded)
    print(decrypted)
    # Remove the padding put before
    #decrypted = decrypted.decode()
    padding = PADDING.encode()
    #decrypted = decrypted.rstrip(padding)
    return str(decrypted, 'utf-8')

def rsa_encrypt(pub_key: bytes, msg: str) -> str:
    """Encrypts using RSA public key

    :param priv_key: The RSA private key
    :param msg: The encrypted message
    :type pub_key: bytes
    :type msg: str
    :return: The encrypted message
    :rtype: bytes
    """

    #assert isinstance(msg,str), "The variable msg must be a string"
    assert isinstance(pub_key,bytes), "The public key must be bytes"
    #(msg.decode())
    pub_key_obj =  RSA.importKey(pub_key)
    encrypted: str = pub_key_obj.encrypt(msg, "")[0]
    #print(encrypted)
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

    assert isinstance(msg,bytes), "The variable msg must be bytes"
    assert isinstance(priv_key,bytes), "The variable key must be bytes"

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

    assert isinstance(msg,str), "The variable msg must be a string"
    assert isinstance(rsa_key,bytes), "The variable rsa_key must be bytes"
    assert isinstance(aes_key,bytes), "The variable aes_key must be bytes"

    encrypted_msg: bytes = aes_encrypt(aes_key, msg)
    encrypted_key: bytes = rsa_encrypt(rsa_key, aes_key)
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

    assert isinstance(msg,bytes), "The variable msg must be bytes"
    assert isinstance(rsa_key,bytes), "The variable rsa_key must be bytes"
    assert isinstance(aes_key,bytes), "The variable aes_key must be bytes"

    decrypted_key: bytes = rsa_decrypt(rsa_key, aes_key)
    decrypted_msg = aes_decrypt(decrypted_key, msg)
    return decrypted_msg

def easy_encrypt(rsa_key: bytes, msg: bytes):
    """Encrypts using both AES and RSA after generating the AES key itself

    :param rsa_key: The RSA public key
    :param msg: The message to encrypt
    :return: The encrypted AES key, the encrypted message
    :rtype: bytes, bytes
    """

    assert isinstance(msg,bytes), "The variable msg must be a string"
    assert isinstance(rsa_key,bytes), "The variable key must be bytes"

    return aes_rsa_encrypt(gen_aes_key(), rsa_key, msg)
