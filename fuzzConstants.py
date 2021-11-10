# connection and commons
OPC_UA_PORT = 4840
ENDPOINT_STRING = 'opc.tcp://localhost:4840/'.encode('utf-8')
CHUNK_TYPE = b'F'
UNIX_TIME = 116444736000000000  # January 1, 1970
COMMON_MSG_TYPE = b'MSG'
PNG_GRAPH_OUT_FILE = './myopcuaTest.png'
ACK_MSG_TYPE = b'ACK'
ERR_MSG_TYPE = b'ERR'

#callbacks related
SEC_CH_ID_PRIM_NAME = 'secure channel id'
SEC_TOKEN_ID_PRIM_NAME = 'secure token id'
SEC_SEQ_NUM_PRIM_NAME = 'secure sequence number'
SEC_REQ_ID_PRIM_NAME = 'secure request id'

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
    # values to be overwritten whit callbacks
GET_ENDPOINTS_MSG_SEC_CH_ID_NODE_FIELD = GET_ENDPOINTS_MSG_NAME + "." + GET_ENDPOINTS_MSG_BODY_NAME + "." + SEC_CH_ID_PRIM_NAME
GET_ENDPOINTS_MSG_TOKEN_ID_NODE_FIELD = GET_ENDPOINTS_MSG_NAME + "." + GET_ENDPOINTS_MSG_BODY_NAME + "." + SEC_TOKEN_ID_PRIM_NAME
GET_ENDPOINTS_MSG_SEQ_NUM_NODE_FIELD = GET_ENDPOINTS_MSG_NAME + "." + GET_ENDPOINTS_MSG_BODY_NAME + "." + SEC_SEQ_NUM_PRIM_NAME
GET_ENDPOINTS_MSG_SEQ_REQ_ID_NODE_FIELD = GET_ENDPOINTS_MSG_NAME + "." + GET_ENDPOINTS_MSG_BODY_NAME + "." + SEC_REQ_ID_PRIM_NAME

# close msg related
CLOSE_MSG_TYPE = b'CLO'
CLOSE_MSG_NAME = 'Close'
CLOSE_MSG_HEADER_NAME = 'c-header'
CLOSE_MSG_BODY_NAME = 'c-body'
CLOSE_MSG_TYPE_ID = 452
    # values to be overwritten with callbacks
CLOSE_MSG_SEC_CH_ID_NODE_FIELD = CLOSE_MSG_NAME + "." + CLOSE_MSG_BODY_NAME + "." + SEC_CH_ID_PRIM_NAME
CLOSE_MSG_TOKEN_ID_NODE_FIELD = CLOSE_MSG_NAME + "." + CLOSE_MSG_BODY_NAME + "." + SEC_TOKEN_ID_PRIM_NAME
CLOSE_MSG_SEQ_NUM_NODE_FIELD = CLOSE_MSG_NAME + "." + CLOSE_MSG_BODY_NAME + "." + SEC_SEQ_NUM_PRIM_NAME
CLOSE_MSG_SEQ_REQ_ID_NODE_FIELD = CLOSE_MSG_NAME + "." + CLOSE_MSG_BODY_NAME + "." + SEC_REQ_ID_PRIM_NAME


# create session req related
CREATE_SESSION_MSG_NAME = 'Create Session'
CREATE_SESSION_MSG_HEADER_NAME = 'cs-header'
CREATE_SESSION_MSG_BODY_NAME = 'cs-body'
CREATE_SESSION_MSG_TYPE_ID = 461
CREATE_SESSION_MSG_APP_URI_STRING = 'urn:pcname:application'.encode('utf-8')

# TODO activate session req related

