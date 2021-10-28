# connection and commons
HOST_ADDR = "150.140.188.188"
OPC_UA_PORT = 4840
ENDPOINT_STRING = 'opc.tcp://localhost:4840/'.encode('utf-8')
CHUNK_TYPE = b'F'
UNIX_TIME = 116444736000000000  # January 1, 1970
COMMON_MSG_TYPE = b'MSG'
PNG_GRAPH_OUT_FILE = './myopcuaTest.png'
ACK_MSG_TYPE = b'ACK'
ERR_MSG_TYPE = b'ERR'

# hello msg client initiated req related
HELLO_MSG_TYPE = b'HEL'
HELLO_MSG_NAME = 'Hello'
HELLO_MSG_HEADER_NAME = 'h-header'
HELLO_MSG_BODY_NAME = 'h-body'

# open secure channel req related
OPEN_MSG_TYPE = b'OPN'
OPEN_MSG_NAME = 'Open'
OPEN_MSG_HEADER_NAME = 'o-header'
OPEN_MSG_BODY_NAME = 'o-body'
OPEN_MSG_SEC_POLICY_NONE = 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')

# get endpoints req related 
GET_ENDPOINTS_MSG_NAME = 'GetEndpoints'
GET_ENDPOINTS_MSG_HEADER_NAME = 'g-header'
GET_ENDPOINTS_MSG_BODY_NAME = 'g-body'
GET_ENDPOINTS_MSG_TYPE_ID = 428


# close msg related
CLOSE_MSG_TYPE = b'CLO'
CLOSE_MSG_NAME = 'Close'
CLOSE_MSG_HEADER_NAME = 'c-header'
CLOSE_MSG_BODY_NAME = 'c-body'
CLOSE_MSG_TYPE_ID = 452

# ack msg related