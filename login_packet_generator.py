import json
import struct
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from config import KEY, OPCODE_LOGIN_REQ
import time
from server import login_db
import sys

def generate_login_packet(usr, pwd):
    data = json.dumps((usr,pwd,time.time())).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    payload = json.dumps({'iv':iv, 'ciphertext':ct}).encode('utf-8')
    payload_len = len(payload)
    header = struct.pack('!HH', OPCODE_LOGIN_REQ, payload_len)

    return header + payload

def generate_all():
    for a in login_db:
        print(generate_login_packet(a,login_db[a]))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(generate_login_packet(sys.argv[1],sys.argv[2]))
    else:
        generate_all()