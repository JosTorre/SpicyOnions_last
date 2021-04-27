#New version of Nodes using Cell Objects
import sys
import secrets
#import hashlib
from aes_rsa import *

class CreateCell:

        def __init__(self, handshake):
                self.type = 'CREATE2'
                self.command = b'10'
                self.circID = secrets.token_hex(2) # 00 - FF
                self.htype = '0x0002' 
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
                self.lspec = None 
                self.htype = '0x0002'

        def print_it(self):
            print('{}: [{}|{}|{}|{}|{}]'.format(self.type, self.command, self.circID, self.htype, self.hlen, self.hdata))
        
        def print_type(self):
                print('Typ: {}  Länge: {} '.format(type(self.type), sys.getsizeof(self.type)))
                print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
                print('Typ: {}  Länge: {} '.format(type(self.circID), sys.getsizeof(self.circID)))
                print('Typ: {}  Länge: {} '.format(type(self.htype), sys.getsizeof(self.htype)))
                print('Typ: {}  Länge: {} '.format(type(self.hlen), sys.getsizeof(self.hlen)))
                print('Typ: {}  Länge: {} '.format(type(self.hdata), sys.getsizeof(self.hdata)))

class ExtendCell:

        def __init__(self, nodeip, handshake):
                
                self.type = 'EXTEND2'
                self.command = 13 #in der Doku nicht spezifiziert
                self.nspec = 1
                self.lstype = '00' 
                self.lslen = len(nodeip) 
                self.lspec = nodeip
                self.htype = '0x0002'
                self.hdata = handshake
                self.hlen = len(handshake)

        def print_it(self):
            print('{}: [{}|{}|{}|{}|{}|{}|{}]'.format(self.type, self.command, self.lstype, self.lslen, self.lspec, self.htype, self.hlen, self.hdata))

        def print_type(self):
                print('Typ: {}  Länge: {} '.format(type(self.type), sys.getsizeof(self.type)))
                print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
                print('Typ: {}  Länge: {} '.format(type(self.nspec), sys.getsizeof(self.nspec)))
                print('Typ: {}  Länge: {} '.format(type(self.nspec), sys.getsizeof(self.lstype)))
                print('Typ: {}  Länge: {} '.format(type(self.lslen), sys.getsizeof(self.lslen)))
                print('Typ: {}  Länge: {} '.format(type(self.lspec), sys.getsizeof(self.lspec)))
                print('Typ: {}  Länge: {} '.format(type(self.htype), sys.getsizeof(self.htype)))
                print('Typ: {}  Länge: {} '.format(type(self.hlen), sys.getsizeof(self.hlen)))
                print('Typ: {}  Länge: {} '.format(type(self.hdata), sys.getsizeof(self.hdata)))


        #def to_extended(self, handshake_resp):
                
                #self.type = 'EXTENDED2'
                #self.command = 14 #in der Doku nicht spezifiziert
                #self.hlen = len(handshake_resp)
                #self.hdata = handshake_resp

class RelayCell:

        def __init__(self, destip, message):

                self.type = 'RELAY'
                self.command = 3
                self.recognized = '0' #0 encrypted (3 times)
                self.streamID = 0 # change from node to node
                self.digest = hash(message) #Hash von Nachricht (klartext)
                self.len = sys.getsizeof(message)
                self.data = destip
                self.payload = message
                #self.padding = ?

        def print_type(self):
                print('Typ: {}  Länge: {} '.format(type(self.type), sys.getsizeof(self.type)))
                print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
                print('Typ: {}  Länge: {} '.format(type(self.recognized), sys.getsizeof(self.recognized)))
                print('Typ: {}  Länge: {} '.format(type(self.streamID), sys.getsizeof(self.streamID)))
                print('Typ: {}  Länge: {} '.format(type(self.digest), sys.getsizeof(self.digest)))
                print('Typ: {}  Länge: {} '.format(type(self.len), sys.getsizeof(self.len)))
                print('Typ: {}  Länge: {} '.format(type(self.data), sys.getsizeof(self.data)))
                print('Typ: {}  Länge: {} '.format(type(self.payload), sys.getsizeof(self.payload)))

        def print_it(self):
            print('{}: [{}|{}|{}|{}|{}|{}|{}]'.format(self.type, self.command, self.recognized, self.streamID, self.digest, self.len, self.data, self.payload))

        def update_stream(self, sid):
                self.streamID = sid

        def decrypt(self, key):
                print(self.payload)
                self.payload = aes_decrypt(key, self.payload)
                self.recognized = aes_decrypt(key, self.recognized)
                print(self.recognized) 

        def encrypt(self, key):
                self.payload = aes_encrypt(key, self.payload)
                self.recognized = aes_encrypt(key, self.recognized)
                
        def full_encrypt(self, keys):
                for x in range(len(keys)-1) :
                    self.payload = aes_encrypt(keys[x], str(self.payload))
                    print(self.payload)
                    print(str(self.payload))
                    print(bytes(str(self.payload)))
                    self.recognized = aes_encrypt(keys[x], str(self.recognized))
        def full_decrypt(self, keys):
                for x in range(len(keys)-1) :
                    self.payload = aes_decrypt(keys[x], self.payload)
                    print(self.payload)
                    self.recognized = aes_decrypt(keys[x], self.recognized)

        def recognized():
                print(self.recognized)
                print(type(self.recognized))
                if self.recognized == b'0':
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
