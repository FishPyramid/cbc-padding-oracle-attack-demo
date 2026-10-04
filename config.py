# encryption
KEY = b"super secret 123" # 16, 24, or 32 bytes

# server config
HOST = '127.0.0.1'
PORT = 9999

OPCODE_LOGIN_REQ = 0x0001

RESP_SUCCESS = b"\x00\x00" 
RESP_AUTH_FAIL = b"\x00\x01"
RESP_PADDING_ERROR = b"\x00\x02"
RESP_UNKNOWN_CMD = b"\x00\xFF"