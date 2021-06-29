#New version of Nodes using Cell Objects
import sys
import secrets
#import hashlib
from aes_rsa import *

def beits(number, size):
    number = number.to_bytes(size, 'big')
    return number

class CreateCell:
        """
                CreateCell
    
                Name: CreateCell

                CreateCell-Object. Used to send create cells through the circuit

                Attributes:

                attribute1 (bytes): command - contains the command code
                attribute2 (string): circID - contains the Circuit ID of the current Object
                attribute3 (bytes): htype - contains the command code
                attribute4 (int): hlen - contains the length of the following hdata field.
                attribute5 (bytes): hdata - contains the handshake data für the key exchange
        """
        def __init__(self, handshake):
            """
            __init__

            Name: Init

            CreateCell-Class Constructor
            
            Attributes:

            argument1: Contains handshake Data
            """
            self.command = beits(10,2) 
            self.circID = str.encode(secrets.token_hex(2)) # 00 - FF
            self.htype = b'0x0002'
            self.hlen = sys.getsizeof(handshake)
            self.hdata = handshake

        def to_created(self, handshake_resp):
            """
                To_Created

                Name: To Created

                Changes Attrubtes to Created-Cell

                Attributes:

                argument1: Contains handshake Data
            """
            self.command = beits(11,2) 
            self.hlen = sys.getsizeof(handshake_resp)
            self.hdata = handshake_resp
        
        def to_extended(self): 
            """
                To_Extended

                Name: To Extended

                Changes attributes to Extended_Cell
            """
            self.command = beits(15,2) 

        def __str__(self):
            """
                __str__

                Name: Str

                Returns string with attributes based on command
            """
            if self.command == b'\x00\n':
                return 'CREATE2: [{}|{}|{}|{}|{}]'.format(self.command, self.circID, self.htype.decode('utf-8'), self.hlen, self.hdata.hex())
            elif self.command == b'\x00\x0b':
                return 'CREATED2: [{}|{}|{}]'.format(self.command, self.hlen, self.hdata.hex())
            elif self.command == b'\x00\x0f':
                return 'EXTENDED2: [{}|{}|{}]'.format(self.command, self.hlen, self.hdata.hex())
        
        def print_type(self):
            """
                Print_Type

                Name: Print Type

                Prints type of all attributes
            """
            print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
            print('Typ: {}  Länge: {} '.format(type(self.circID), sys.getsizeof(self.circID)))
            print('Typ: {}  Länge: {} '.format(type(self.htype), sys.getsizeof(self.htype)))
            print('Typ: {}  Länge: {} '.format(type(self.hlen), sys.getsizeof(self.hlen)))
            print('Typ: {}  Länge: {} '.format(type(self.hdata), sys.getsizeof(self.hdata)))

class ExtendCell:
        """
            ExtendCell
            
            Name: ExtendCell

            Creates Extend-Cell objects for communication in the circuit

            Attributes:

            attribute1 (bytes): command - contains the command code
            attribute2 (bytes): lstype - link specifier type
            attribute3 (int): lslen - link specifier length
            attribute4 (string): lspec - link specifier, contains adresss
            attribute5 (bytes): htype - contains the command code
            attribute6 (int): hlen - contains the length of the following hdata field.
            attribute7 (bytes): hdata - contains the handshake data für the key exchange
        """
        def __init__(self, nodeip, handshake):
            """
                __init__

                Name: Init

                ExtentCell-Class Constructor

                Attributes:

                argument1: Contains handshake Data
            """
            self.command = beits(14,2) #in der Doku nicht spezifiziert
            self.nspec = beits(1,1) #b'1'
            self.lstype = beits(00,2)
            self.lslen = len(nodeip) 
            self.lspec = nodeip
            self.htype = b'0x0002' # 0x0002 => 0x02 0x00 Little Endian
            self.hdata = handshake
            self.hlen = sys.getsizeof(handshake)

        def __str__(self):
            """
                __str__

                Name: Str

                Returns string with attributes based on command
            """
            return 'EXTEND2: [{}|{}|{}|{}|{}|{}|{}]'.format(self.command, self.lstype, self.lslen, self.lspec, self.htype.decode('utf-8'), self.hlen, self.hdata.hex())

        def print_type(self):
                """
                    Print_Type

                    Name: Print Type

                    Prints type of all attributes
                """
                print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
                print('Typ: {}  Länge: {} '.format(type(self.nspec), sys.getsizeof(self.nspec)))
                print('Typ: {}  Länge: {} '.format(type(self.nspec), sys.getsizeof(self.lstype)))
                print('Typ: {}  Länge: {} '.format(type(self.lslen), sys.getsizeof(self.lslen)))
                print('Typ: {}  Länge: {} '.format(type(self.lspec), sys.getsizeof(self.lspec)))
                print('Typ: {}  Länge: {} '.format(type(self.htype), sys.getsizeof(self.htype)))
                print('Typ: {}  Länge: {} '.format(type(self.hlen), sys.getsizeof(self.hlen)))
                print('Typ: {}  Länge: {} '.format(type(self.hdata), sys.getsizeof(self.hdata)))



class RelayCell:
        """
            Relay Cell

            Name: ExtendCell

            Creates Extend-Cell objects for communication in the circuit

            Attributes:

            attribute1 (bytes): command - contains the command code
            attribute2 (bytes): recogniced
            attribute3 (bytes): streamID - contains ID of Steam
            attribute4 (int): digest - hash value of message
            attribute5 (int): len - contains Lenght
            attribute6 (string): data - contains destination adress
            attribute7 (string): payload - contains message
        """
        def __init__(self, destip, message):
            """
                __init__

                Name: Init

                ExtentCell-Class Constructor

                Attributes:

                argument1: Contains destination adress
                argument2: contains message
            """
            self.command = beits(3,2) 
            self.recognized = b'0' #0 encrypted (3 times)
            self.streamID = b'0' # change from node to node
            self.digest = hash(message) #Hash von Nachricht (klartext)
            self.len = sys.getsizeof(message)
            self.data = destip
            self.payload = message
            #self.padding = ?

        def print_type(self):
            """
                Print_Type

                Name: Print Type

                Prints type of all attributes
            """
            print('Typ: {}  Länge: {} '.format(type(self.command), sys.getsizeof(self.command)))
            print('Typ: {}  Länge: {} '.format(type(self.recognized), sys.getsizeof(self.recognized)))
            print('Typ: {}  Länge: {} '.format(type(self.streamID), sys.getsizeof(self.streamID)))
            print('Typ: {}  Länge: {} '.format(type(self.digest), sys.getsizeof(self.digest)))
            print('Typ: {}  Länge: {} '.format(type(self.len), sys.getsizeof(self.len)))
            print('Typ: {}  Länge: {} '.format(type(self.data), sys.getsizeof(self.data)))
            print('Typ: {}  Länge: {} '.format(type(self.payload), sys.getsizeof(self.payload)))

        def __str__(self):
            """
                __str__

                Name: Str

                Returns string with attributes based on command
            """
            return 'RELAY: [{}|{}|{}|{}|{}|{}|{}]'.format(self.command, self.recognized, self.streamID, self.digest, self.len, self.data, self.payload)

        def update_stream(self, sid):
            """
                update_stream

                Name: Update Stream

                Methode to update stream ID

                Argmuents:

                argument1(bytes): Contains StreamID
            """
            self.streamID = sid

        def decrypt(self, key):
            """
                decrypt

                Name: Decrypt

                Method to decrypt Message

                Attributes:

                argument1(bytes): contains key to decrypt
            """
            #print(self.payload)
            self.payload = aes_decrypt(key, self.payload)
            #selrecognized = aes_decrypt(key, self.recognized)
            #print(self.recognized) 

        def encrypt(self, key):
            """
                encrypt

                Name: Encrypt

                Method to encrypt Message

                Attributes:

                argument1(bytes): contains key to encrypt
            """
            #print(key)
            self.payload = aes_encrypt(key, self.payload)
            #self.recognized = aes_encrypt(key, self.recognized)
                
        def full_encrypt(self, keys):
            """
                full_encrypt

                Name: Full_Encrypt

                Method to encrypt message with all keys in argument1

                Attributes:

                argument1(bytes): contains keys to encrypt
            """
            for x in range(len(keys)) :
                self.payload = aes_encrypt(keys[2-x], self.payload)
                #self.recognized = aes_encrypt(keys[2-x], str(self.recognized))
        def full_decrypt(self, keys):
            """
                full_decrypt

                Name: Full_Decrypt

                Method to decrypt message with all keys in argument1

                Attributes:

                argument1(bytes): contains keys to decrypt
            """
            for x in range(len(keys)) :
                self.payload = aes_decrypt(keys[x], self.payload)
                #print(self.payload)
                #self.recognized = aes_decrypt(keys[x], self.recognized)

        def is_recognized(self):
                #print(self.recognized)
                #print(type(self.recognized))
                if self.recognized == b'0':
                        return True
                else:
                        return False

        def show_payload(self):
                return self.payload.decode('utf-8')

class DestroyCell:

        def __init__(self, reason):
                self.command = beits(4,2) 
                self.circID = beits(0,2)
                self.reason = reason

        def __str__(self):
            return "DESTROY: [{}|{}|{}]".format(self.command, self.circID.decode('utf-8'), self.reason)

        def set_circuit_id(self, new_id):
            self.circID = new_id

        def print_type(self):
            print('DESTROY: [{},{}|{},{}|{},{}]'.format(type(self.command),sys.getsizeof(self.command), type(self.circID), sys.getsizeof(self.circID), type(self.reason), sys.getsizeof(self.reason))) 
