import socket
from config import HOST, PORT

def query_server(packet):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(packet)

        response = sock.recv(1024)
        return response

if __name__ == "__main__":
    packet = input("enter packet: ")
    packet_bytes = eval(packet)
    print(query_server(packet_bytes))