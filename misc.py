import base64

def xor_two_bytes(bytes_one, bytes_two):
	xor_set = []
	for i in range(len(bytes_one)):
		xor_value = chr(ord(bytes_one[i]) ^ bytes_two[i%1])
		xor_set.append(xor_value)
	string = "".join(xor_set)
	return string


def problem_one():
    msg = "Karma police, arrest this man, he talks in maths"
    hexMsg = ""
    for char in range(len(msg)):
        hexMsg += hex(ord(msg[char]))[2:4]
    print(hexMsg)
    binMsg =  bytes.fromhex(hexMsg).decode("utf-8")
    key = bytes.fromhex("01")
    a = xor_two_bytes(binMsg, key)
    b = base64.b64decode(a)
    print(a)
    print(b)

def problem_two():
      ciphertext = "210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
      

problem_one()