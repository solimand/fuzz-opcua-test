# connection
HOST_ADDR = "150.140.188.188"
OPC_UA_PORT = 4840
ENDPOINT_STRING = 'opc.tcp://localhost:4840/'.encode('utf-8')

# msg types
HELLO_MSG_TYPE = b'HEL'
ACK_MSG_TYPE = b'ACK'
OPEN_MSG_TYPE = b'OPN' 
CLOSE_MSG_TYPE = b'CLO'
MSG_TYPE = b'MSG'