from config import RESP_PADDING_ERROR, OPCODE_LOGIN_REQ # key not given
from Crypto.Cipher import AES
from query_server import query_server
from base64 import b64decode, b64encode
import struct
import json

def oracle(iv, ct):
    iv_b64 = b64encode(iv).decode('utf-8')
    ct_b64 = b64encode(ct).decode('utf-8')

    payload = json.dumps({'iv':iv_b64, 'ciphertext':ct_b64}).encode('utf-8')
    payload_len = len(payload)
    header = struct.pack('!HH', OPCODE_LOGIN_REQ, payload_len)
    return query_server(header + payload) != RESP_PADDING_ERROR
    
def attack_block(prev, cur):
    result = bytearray(AES.block_size)
    intermediate = bytearray(AES.block_size)

    for pad_val in range(1, AES.block_size + 1):
        idx = AES.block_size - pad_val
        modify = bytearray(prev)

        for j in range(idx + 1, AES.block_size):
            modify[j] = intermediate[j] ^ pad_val

        found = False
        for b in range(256):
            modify[idx] = b
            
            if oracle(bytes(modify), cur):
                if pad_val == 1: # test false positive
                    modify[14] ^= 0x01
                    still_valid = oracle(bytes(modify), cur)
                    modify[14] ^= 0x01
                    if not still_valid:
                        continue
                intermediate[idx] = b ^ pad_val
                result[idx] = intermediate[idx] ^ prev[idx]
                print(f"found bytes: {bytes(result[idx:])}")
                found = True
                break
        if not found:
            raise RuntimeError(f"no valid padding candidate at byte {idx}")
    return bytes(result)

def attack(iv, ct):
    blocks = [iv] + [ct[i:i+AES.block_size] for i in range(0, len(ct), AES.block_size)]
    result = bytearray()
    for i in range(len(blocks) - 1, 0, -1):
        target_block = blocks[i]
        prev_block = blocks[i-1]
        
        print(f"-----decrypting block {i} of {len(blocks) - 1}-----")
        recovered_block = attack_block(prev_block, target_block)
        result = recovered_block + result
    print(result)
    return result

def extract_packet(packet):
    start = packet.index(b"{")
    end = packet.rindex(b"}") + 1
    json_str = packet[start:end]
    b64 = json.loads(json_str)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    return (iv,ct)

if __name__ == "__main__":
    packet = input("enter packet: ")
    packet_bytes = eval(packet)
    iv, ct = extract_packet(packet_bytes)
    attack(iv, ct)