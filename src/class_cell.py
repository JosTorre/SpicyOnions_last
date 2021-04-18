#EXTEND2 CELL FORMAT: [Command ID, LSTYPE, LSLEN, LSPEC, HTYPE, HLEN, HDATA]
extend_cell = ["EXTEND2",0, 2, node_addr[len(nodes)-x], "ntor", len(handshake), handshake]
relay_cell = [3, 1, streamID, digest, len(destination), destination, str.encode(message)]
#create_cell = [10, circID, 2, len(public_bytes), public_bytes]
destroy_cell = [4, reason]

import sys

class CreateCell:

	def __init__(self, handshake):

		self.type = 'CREATE2'
		self.command = 10
		self.circID = secrets.token_hex(2) # 00 - FF
		self.htype = 2 
		self.hlen = len(self.handshake)
		self.hdata = handshake

	def to_created(handshake_resp):
		self.type = 'CREATED2'
		self.command = 11
		self.hlen = len(self.handshake_resp)
		self.hdata = handshake_resp

	def get_circ_id():
		return self.circID

class ExtendCell:

	def __init__(self, nodeip):

		self.type = 'EXTEND2'
		self.command = 13 #in der Doku nicht spezifiziert
		self.lstype = 0
		self.lslen = 2
		self.lspec = nodeip
		self.htype = 'ntor'
		self.hlen = len(handshake)
		self.hdata = handshake

	def to_extended(handshake_resp):
		self.type = 'EXTENDED2'
		self.command = 14 #in der Doku nicht spezifiziert
		self.hlen = len(self.handshake_resp)
		self.hdata = handshake_resp
		

class RelayCell:

	def __init__(self, destip, message):

		self.type = 'RELAY'
		self.command = 3
		self.recognized = 0 #0 encrypted (3 times)
		self.streamID = ? # change from node to node
		self.digest: str = sha224(bytes(msg,"utf-8")).hexdigest() #Hash von Nachricht (klartext)
		self.len = sys.getsizeof(message)
		self.data = destip
		self.payload = message
		#self.padding = ?

	def update_stream(sid):
		self.streamID = sid

	def decrypt(key):
		self.payload = aes_decrypt(key, self.payload)
		self.recognized = aes_decrypt(key, self.recognized)
		

	def encrypt(key):
		self.payload = aes_encrypt(key, self.payload)
		self.recognized = aes_encrypt(key, self.recognized)

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