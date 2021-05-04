#New version of Nodes using Cell Objects
import sys
import secrets
#import hashlib
from aes_rsa import *

class CreateCell:

        def __init__(self, handshake):
                self.type = b'CREATE2'
                self.command = b'10'
                self.circID = str.encode(secrets.token_hex(2)) # 00 - FF
                self.htype = b'0x0002'
                self.hlen = sys.getsizeof(handshake)
                self.hdata = handshake

        def to_created(self, handshake_resp):
                self.type = b'CREATED2'
                self.command = b'11'
                self.hlen = sys.getsizeof(handshake_resp)
                self.hdata = handshake_resp
        
        def to_extended(self): 
                self.type = b'EXTENDED2'
                self.command = b'14'

        def __str__(self):
            if self.command == b'10':
                return '{}: [{}|{}|{}|{}|{}]'.format(self.type.decode('utf-8'), self.command.decode('utf-8'), self.circID, self.htype.decode('utf-8'), self.hlen, self.hdata.hex())
            else:
                return '{}: [{}|{}|{}]'.format(self.type.decode('utf-8'), self.command.decode('utf-8'), self.hlen, self.hdata.hex())
        
        def print_type(self):
                print('Typ: {}  Länge: {} '.format(type(self.type), sys.getsizeof(self.type)))
                print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
                print('Typ: {}  Länge: {} '.format(type(self.circID), sys.getsizeof(self.circID)))
                print('Typ: {}  Länge: {} '.format(type(self.htype), sys.getsizeof(self.htype)))
                print('Typ: {}  Länge: {} '.format(type(self.hlen), sys.getsizeof(self.hlen)))
                print('Typ: {}  Länge: {} '.format(type(self.hdata), sys.getsizeof(self.hdata)))

class ExtendCell:

        def __init__(self, nodeip, handshake):
                
                self.type = b'EXTEND2'
                self.command = b'13' #in der Doku nicht spezifiziert
                self.nspec = b'1'
                self.lstype = b'00' 
                self.lslen = len(nodeip) 
                self.lspec = nodeip
                self.htype = b'0x0002'
                self.hdata = handshake
                self.hlen = sys.getsizeof(handshake)

        def __str__(self):
            return '{}: [{}|{}|{}|{}|{}|{}|{}]'.format(self.type.decode('utf-8'), self.command.decode('utf-8'), self.lstype.decode('utf-8'), self.lslen, self.lspec, self.htype.decode('utf-8'), self.hlen, self.hdata.hex())

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



class RelayCell:

        def __init__(self, destip, message):

                self.type = b'RELAY'
                self.command = b'3'
                self.recognized = b'0' #0 encrypted (3 times)
                self.streamID = b'0' # change from node to node
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

        def __str__(self):
            return '{}: [{}|{}|{}|{}|{}|{}|{}]'.format(self.type.decode('utf-8'), self.command.decode('utf-8'), self.recognized, self.streamID, self.digest, self.len, self.data, self.payload)

        def update_stream(self, sid):
                self.streamID = sid

        def decrypt(self, key):
                print(self.payload)
                self.payload = aes_decrypt(key, self.payload)
                #selrecognized = aes_decrypt(key, self.recognized)
                #print(self.recognized) 

        def encrypt(self, key):
                self.payload = aes_encrypt(key, self.payload)
                self.recognized = aes_encrypt(key, self.recognized)
                
        def full_encrypt(self, keys):
                for x in range(len(keys)) :
                    print(x)
                    print(keys[x])
                    #print(self.payload)
                    self.payload = aes_encrypt(keys[2-x], self.payload)
                    #print(self.payload)
                    #print(str(self.payload))
                    #print(bytes(str(self.payload)))
                    #self.recognized = aes_encrypt(keys[2-x], str(self.recognized))
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
                return self.payload.decode('utf-8')

class DestroyCell:

        def __init__(self, reason):
                self.type = b'DESTROY'
                self.command = b'4'
                self.circID = b'0'
                self.reason = reason

        def __str__(self):
            return "{}: [{}|{}|{}]".format(self.type.decode('utf-8'), self.command.decode('utf-8'), self.circID.decode('utf-8'), self.reason)

        def set_circuit_id(self, new_id):
            self.circID = new_id

        def print_type(self):
            print('{} : [{},{}|{},{}|{},{}]'.format(self.type.decode('utf-8'), type(self.command),sys.getsizeof(self.command), type(self.circID), sys.getsizeof(self.circID), type(self.reason), sys.getsizeof(self.reason))) 
