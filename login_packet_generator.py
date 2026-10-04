import json
import struct
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from config import KEY, OPCODE_LOGIN_REQ
import time

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

if __name__ == "__main__":
    username = input("enter username: ")
    password = input("enter password: ")
    print(generate_login_packet(username,password))