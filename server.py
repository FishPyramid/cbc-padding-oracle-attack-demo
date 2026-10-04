import json
import socket
import struct
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *
import time

# mock database
login_db = {
    "user": "password",
    "fella": "cbods123",
    "folk99": "ough_1ough$"
}

def recv_all(sock, length):
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

def handle_client(client_socket):
  client_socket.settimeout(2.0)

  try:
    header = recv_all(client_socket, 4)
    if not header:
        return

    cmd_id, payload_len = struct.unpack('!HH', header)

    # Optional safety check: guard against absurdly large payloads
    if payload_len > 4096:
        return

    payload = recv_all(client_socket, payload_len)
    if not payload:
        return

    if cmd_id == OPCODE_LOGIN_REQ:
        response = login(payload)
        client_socket.sendall(response)
    else:
        client_socket.sendall(RESP_UNKNOWN_CMD)

  except socket.timeout:
        print("timeout")
  except Exception as e:
        print(f'error: {e}')
  finally:
        client_socket.close()

def login(data):
    try:
        b64 = json.loads(data)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size) # throws ValueError if ct has incorrect padding
        json_str = pt.decode('utf-8')
        login_data = json.loads(json_str)
        user, password, login_time = login_data
        if time.time - login_time > 10:
            return RESP_AUTH_FAIL
        if user in login_db and login_db[user] == password:
            return RESP_SUCCESS
        else:
            return RESP_AUTH_FAIL
    except ValueError:
        return RESP_PADDING_ERROR

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    server.settimeout(.1) 
    print(f"login server started on {HOST}:{PORT}")
    
    try:
        while True:
            try:
                client, addr = server.accept()
                handle_client(client)
            except socket.timeout:
                continue 
    except KeyboardInterrupt:
        print("\nclosing login server...")
    finally:
        server.close()
        print("server closed")