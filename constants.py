# connection and commons
HOST_ADDR = "150.140.188.188"
OPC_UA_PORT = 4840
ENDPOINT_STRING = 'opc.tcp://localhost:4840/'.encode('utf-8')
CHUNK_TYPE = b'F'

# hello msg related
HELLO_MSG_TYPE = b'HEL'
HELLO_MSG_NAME = 'Hello'
HELLO_MSG_HEADER_NAME = 'h-header'
HELLO_MSG_BODY_NAME = 'h-body'

# open secure channel req related
OPEN_MSG_TYPE = b'OPN'
OPEN_MSG_NAME = 'Open'
OPEN_MSG_HEADER_NAME = 'o-header'
OPEN_MSG_BODY_NAME = 'o-body'

# close msg related
CLOSE_MSG_TYPE = b'CLO'
CLOSE_MSG_NAME = 'Close'
CLOSE_MSG_HEADER_NAME = 'c-header'
CLOSE_MSG_BODY_NAME = 'c-body'

# ack msg related