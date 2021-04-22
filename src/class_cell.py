#New version of Nodes using Cell Objects
import sys
import secrets
import hashlib

class CreateCell:

        def __init__(self, handshake):
                self.type = 'CREATE2'
                self.command = 10
                self.circID = secrets.token_hex(2) # 00 - FF
                self.htype = 2 
                self.hlen = len(handshake)
                self.hdata = handshake

        def to_created(self, handshake_resp):
                self.type = 'CREATED2'
                self.command = 11
                self.hlen = len(handshake_resp)
                self.hdata = handshake_resp
        
        def to_extended(self): 
                self.type = 'EXTENDED2'
                self.command = 14
                self.lspec = 0
                self.htype = 'ntor'

class ExtendCell:

        def __init__(self, nodeip, handshake):
                
                self.type = 'EXTEND2'
                self.command = 13 #in der Doku nicht spezifiziert
                self.lstype = 0
                self.lslen = 2
                self.lspec = nodeip
                self.htype = 'ntor'
                self.hdata = handshake
                self.hlen = len(handshake)

        #def to_extended(self, handshake_resp):
                
                #self.type = 'EXTENDED2'
                #self.command = 14 #in der Doku nicht spezifiziert
                #self.hlen = len(handshake_resp)
                #self.hdata = handshake_resp

class RelayCell:

        def __init__(self, destip, message):

                self.type = 'RELAY'
                self.command = 3
                self.recognized = 0 #0 encrypted (3 times)
                self.streamID = 0 # change from node to node
                self.digest: str = sha224(bytes(msg,"utf-8")).hexdigest() #Hash von Nachricht (klartext)
                self.len = sys.getsizeof(message)
                self.data = destip
                self.payload = message
                #self.padding = ?

        def update_stream(self, sid):
                self.streamID = sid

        def decrypt(self, key):
                self.payload = aes_decrypt(key, self.payload)
                self.recognized = aes_decrypt(key, self.recognized)
                

        def encrypt(self, key):
                self.payload = aes_encrypt(key, self.payload)
                self.recognized = aes_encrypt(key, self.recognized)
                
        def full_encrypt(self, keys):
                for x in range(len(keys)-1) :
                    self.payload = aes_encrypt(keys[x], self.payload)
                    self.recognized = aes_encrypt(keys[x], self.recognized)

        def full_decrypt(self, keys):
                for x in range(len(keys)-1) :
                    self.payload = aes_decrypt(keys[x], self.payload)
                    self.recognized = aes_decrypt(keys[x], self.recognized)

        def recognized():
                if self.recognized == 0:
                        return True
                else:
                        return False

        def show_payload():
                return self.payload

class DestroyCell:

        def __init__(self, reason):
                self.type = 'DESTROY'
                self.command = 4
                self.payload = reason
