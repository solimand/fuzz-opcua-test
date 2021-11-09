from fuzzConstants import CLOSE_MSG_TYPE_ID, HELLO_MSG_BODY_NAME, ENDPOINT_STRING, CHUNK_TYPE, COMMON_MSG_TYPE
from fuzzConstants import HELLO_MSG_NAME, HELLO_MSG_TYPE, HELLO_MSG_HEADER_NAME, HELLO_MSG_BODY_NAME
from fuzzConstants import OPEN_MSG_NAME, OPEN_MSG_TYPE, OPEN_MSG_HEADER_NAME, OPEN_MSG_BODY_NAME, OPEN_MSG_SEC_POLICY_NONE
from fuzzConstants import CLOSE_MSG_NAME, CLOSE_MSG_TYPE, CLOSE_MSG_HEADER_NAME, CLOSE_MSG_BODY_NAME, CLOSE_MSG_TYPE_ID, SEC_CH_ID_PRIM_NAME, SEC_TOKEN_ID_PRIM_NAME, SEC_SEQ_NUM_PRIM_NAME, SEC_REQ_ID_PRIM_NAME
from fuzzConstants import GET_ENDPOINTS_MSG_NAME, GET_ENDPOINTS_MSG_HEADER_NAME, GET_ENDPOINTS_MSG_BODY_NAME, GET_ENDPOINTS_MSG_TYPE_ID
from fuzzConstants import CREATE_SESSION_MSG_NAME, CREATE_SESSION_MSG_HEADER_NAME, CREATE_SESSION_MSG_BODY_NAME, CREATE_SESSION_MSG_TYPE_ID, CREATE_SESSION_MSG_APP_URI_STRING

from fuzzConstants import UNIX_TIME

from boofuzz import s_initialize, s_bytes, s_dword, s_block, s_size, s_qword

# Dates
from datetime import datetime
from calendar import timegm
import time 

import struct

# -----------------------UTILS---------------------
def print_dbg(msg):
    print("\tDBG: "+str(msg))
print_dbg.__doc__ = "Modified print func for debug and testing prints"

def opcua_time():
    now = datetime.now()
    res_time = UNIX_TIME + (timegm(now.timetuple()) * 10000000)
    return res_time + (now.microsecond * 10) - 72000000000 #time correction
opcua_time.__doc__ = "Get the time stamp in microseconds in OPC UA format"

# -----------------------HELLO MSG---------------------
def hello_msg_nf():
    s_initialize(HELLO_MSG_NAME)

    with s_block(HELLO_MSG_HEADER_NAME):
        s_bytes(HELLO_MSG_TYPE, name='Hello msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(HELLO_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(HELLO_MSG_BODY_NAME):
        s_dword(0, name='Protocol version', fuzzable=False)
        s_dword(65536, name='Receive buffer size', fuzzable=False)
        s_dword(65536, name='Send buffer size', fuzzable=False)
        s_dword(0, name='Max message size', fuzzable=False)
        s_dword(0, name='Max chunk count', fuzzable=False)
        s_dword(len(ENDPOINT_STRING), name='Url length', fuzzable=False)
        s_bytes(ENDPOINT_STRING, name='Endpoint url', fuzzable=False)

def hello_msg():
    s_initialize(HELLO_MSG_NAME)

    with s_block(HELLO_MSG_HEADER_NAME):
        s_bytes(HELLO_MSG_TYPE, name='Hello msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(HELLO_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    #default value is used when other are fuzzed
    with s_block(HELLO_MSG_BODY_NAME):
        protVerList=[b"\x00\x00\xff\xff",b"\xff\x00\xff\x00"] #add these values to protVersion fuzz
        s_dword(1, name='Protocol version')#, fuzz_values=protVerList) #(140)
        s_dword(65536, name='Receive buffer size') #(280)
        s_dword(65536, name='Send buffer size') #(420)
        s_dword(0, name='Max message size') #(560)
        s_dword(0, name='Max chunk count') #(700)
        s_dword(len(ENDPOINT_STRING), name='Url length') #(840)
        s_bytes(ENDPOINT_STRING, name='Endpoint url') #(2270)

# -----------------------OPEN MSG---------------------
def open_msg():
    s_initialize(OPEN_MSG_NAME)

    with s_block(OPEN_MSG_HEADER_NAME):
        s_bytes(OPEN_MSG_TYPE, name='Open msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(OPEN_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(OPEN_MSG_BODY_NAME):
        s_dword(0, name='channel id')
        s_dword(len(OPEN_MSG_SEC_POLICY_NONE), name='uri length')
        s_bytes(OPEN_MSG_SEC_POLICY_NONE, name='security policy uri')
        #for following values refer to docs/MsgFormats/OpenSecureChannel
        s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint')
        s_dword(1, name='sequence number')
        s_dword(1, name='request id')
        #Encodable Obj > Expanded NodeID
        s_bytes(b'\x01\x00\xbe\x01', name='Type id')
        # Req header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(opcua_time(), name='timestamp')
        #s_qword(opcua_time_v2(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
        # Req params     
        s_dword(0, name='client protocol version')
        s_dword(0, name='request type')
        s_dword(1, name='security mode')
        s_bytes(b'\x00\x00\x00\x00', name='client nonce')
        s_dword(3600000, name='requested lifetime')

def open_msg_nf():
    s_initialize(OPEN_MSG_NAME)

    with s_block(OPEN_MSG_HEADER_NAME):
        s_bytes(OPEN_MSG_TYPE, name='Open msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(OPEN_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(OPEN_MSG_BODY_NAME):
        s_dword(0, name='channel id', fuzzable=False)
        s_dword(len(OPEN_MSG_SEC_POLICY_NONE), name='uri length', fuzzable=False)
        s_bytes(OPEN_MSG_SEC_POLICY_NONE, name='security policy uri', fuzzable=False)
        #for following values refer to docs/MsgFormats/OpenSecureChannel
        s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint', fuzzable=False)
        s_dword(1, name='sequence number', fuzzable=False)
        s_dword(1, name='request id', fuzzable=False)
        #Encodable Obj > Expanded NodeID
        s_bytes(b'\x01\x00\xbe\x01', name='Type id', fuzzable=False)
        # Req header
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)
        # Req params     
        s_dword(0, name='client protocol version', fuzzable=False)
        s_dword(0, name='request type', fuzzable=False)
        s_dword(1, name='security mode', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='client nonce', fuzzable=False)
        s_dword(3600000, name='requested lifetime', fuzzable=False)


# -----------------------CLOSE MSG---------------------
def close_msg():
    s_initialize(CLOSE_MSG_NAME)

    with s_block(CLOSE_MSG_HEADER_NAME):
        s_bytes(CLOSE_MSG_TYPE, name='Close msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(CLOSE_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(CLOSE_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False) #from open callback
        # type id  b'\x01\x00\xc4\x01 > c401 > 01c4 > 452'
        s_bytes(b'\x01\x00' + struct.pack('<H', CLOSE_MSG_TYPE_ID), name='Type id', fuzzable=False)
        # request header
            # NOTE if you fuzz Auth Token you will get Malformed Packet
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(10000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

def close_msg_nf():
    s_initialize(CLOSE_MSG_NAME)

    with s_block(CLOSE_MSG_HEADER_NAME):
        s_bytes(CLOSE_MSG_TYPE, name='Close msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(CLOSE_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(CLOSE_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False) #from open callback
        # type id  b'\x01\x00\xc4\x01 > c401 > 01c4 > 452'
        s_bytes(b'\x01\x00' + struct.pack('<H', CLOSE_MSG_TYPE_ID), name='Type id', fuzzable=False)
        # request header
            # NOTE if you fuzz Auth Token you will get Malformed Packet
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(10000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)

        
# -----------------------GET ENDPOINTS MSG---------------------
def get_endpoints_msg():
    s_initialize(GET_ENDPOINTS_MSG_NAME)

    with s_block(GET_ENDPOINTS_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Get endpoints', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(GET_ENDPOINTS_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(GET_ENDPOINTS_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False)  #from open callback
        # type id  b'\x01\x00\xac\x01 > ac01 > 01ac > 428
        s_bytes(b'\x01\x00' + struct.pack('<H', GET_ENDPOINTS_MSG_TYPE_ID), name='Type id', fuzzable=False)
        # request header
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False)
        s_qword(opcua_time(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
        # request parameter
        s_dword(len(ENDPOINT_STRING), name='Url length')
        s_bytes(ENDPOINT_STRING, name='Endpoint url')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='locale ids')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='profile ids')


# -----------------------CREATE SESSION MSG---------------------
def create_session_msg():
    s_initialize(CREATE_SESSION_MSG_NAME)

    with s_block(CREATE_SESSION_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Create session', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(CREATE_SESSION_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(CREATE_SESSION_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False)  #from open callback
        # type id  b'\x01\x00\xcd\x01 > cd01 > 01cd > 461
        s_bytes(b'\x01\x00' + struct.pack('<H', CREATE_SESSION_MSG_TYPE_ID), name='Type id', fuzzable=False)
        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(opcua_time(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
        # application description
        s_dword(len(CREATE_SESSION_MSG_APP_URI_STRING), name='Application Uri Length')        
        s_bytes(CREATE_SESSION_MSG_APP_URI_STRING, name='Application Uri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Product Uri') #TODO change in STRING
        s_bytes(0, name='Application Name') #TODO this is the app name
        s_dword(1, name='Application Type')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri') # opcua null string
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri') # opcua null string
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryUrls') # array of string (dim 0)
        # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri') # opcua null string
        s_dword(len(ENDPOINT_STRING), name='Url length')
        s_bytes(ENDPOINT_STRING, name='Endpoint url')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SessionName') # TODO string same as app uri
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientNonce') # TODO 
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate') # null
        s_bytes(struct.pack('d', 1200000.0), name='Requested Session Timeout')
        s_dword(2147483647, name='MaxResponseMessageSize') # TODO def value