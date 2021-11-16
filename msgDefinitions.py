from fuzzConstants import ENDPOINT_STRING, CHUNK_TYPE, COMMON_MSG_TYPE, UNIX_TIME

from fuzzConstants import HELLO_MSG_NAME, HELLO_MSG_TYPE, HELLO_MSG_HEADER_NAME, HELLO_MSG_BODY_NAME

from fuzzConstants import OPEN_MSG_NAME, OPEN_MSG_TYPE, OPEN_MSG_HEADER_NAME, OPEN_MSG_BODY_NAME, OPEN_MSG_SEC_POLICY_NONE

from fuzzConstants import CLOSE_MSG_NAME, CLOSE_MSG_TYPE, CLOSE_MSG_HEADER_NAME, CLOSE_MSG_BODY_NAME, CLOSE_MSG_TYPE_ID, SEC_CH_ID_PRIM_NAME, SEC_TOKEN_ID_PRIM_NAME, SEC_SEQ_NUM_PRIM_NAME, SEC_REQ_ID_PRIM_NAME

from fuzzConstants import GET_ENDPOINTS_MSG_NAME, GET_ENDPOINTS_MSG_HEADER_NAME, GET_ENDPOINTS_MSG_BODY_NAME, GET_ENDPOINTS_MSG_TYPE_ID

from fuzzConstants import CREATE_SESSION_MSG_NAME, CREATE_SESSION_MSG_HEADER_NAME, CREATE_SESSION_MSG_BODY_NAME, CREATE_SESSION_MSG_TYPE_ID, CREATE_SESSION_MSG_APP_URI_STRING, CREATE_SESSION_MSG_APP_NAME_STRING, CREATE_SESSION_MSG_SESSION_NAME, CREATE_SESSION_MSG_PRODUCER_URI_STRING

from fuzzConstants import ACTIVATE_SESSION_MSG_NAME, ACTIVATE_SESSION_MSG_BODY_NAME, ACTIVATE_SESSION_MSG_HEADER_NAME, ACTIVATE_SESSION_MSG_TYPE_ID, ACTIVATE_SESSION_MSG_LOCALE_ID_STRING, ACTIVATE_SESSION_MSG_NUM_ID, ACTIVATE_SESSION_MSG_POLICY_ID

from fuzzConstants import READ_MSG_NAME, READ_MSG_HEADER_NAME, READ_MSG_BODY_NAME, READ_MSG_TYPE_ID

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

def get_endpoints_msg_nf():
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
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)
        # request parameter
        s_dword(len(ENDPOINT_STRING), name='Url length', fuzzable=False)
        s_bytes(ENDPOINT_STRING, name='Endpoint url', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='locale ids', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='profile ids', fuzzable=False)


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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False) #fuzzing auth toke > BadInternalError
        s_qword(opcua_time(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
            # application description
        s_dword(len(CREATE_SESSION_MSG_APP_URI_STRING), name='Application Uri Length')        
        s_bytes(CREATE_SESSION_MSG_APP_URI_STRING, name='Application Uri')
        s_dword(len(CREATE_SESSION_MSG_PRODUCER_URI_STRING), name='Production Uri Length')        
        s_bytes(CREATE_SESSION_MSG_PRODUCER_URI_STRING, name='Production Uri')
        s_bytes(b'\x02', name='App Name Has text')
        s_dword(len(CREATE_SESSION_MSG_APP_NAME_STRING), name='Application Name Length')        
        s_bytes(CREATE_SESSION_MSG_APP_NAME_STRING, name='Application Name')
        s_dword(1, name='Application Type')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri')
        s_bytes(b'\x00\x00\x00\x00', name='DiscoveryUrls') 
            # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri')
        s_dword(len(ENDPOINT_STRING), name='Url length')
        s_bytes(ENDPOINT_STRING, name='Endpoint url')
        s_dword(len(CREATE_SESSION_MSG_SESSION_NAME), name='Session Name Length')        
        s_bytes(CREATE_SESSION_MSG_APP_NAME_STRING, name='Session Name')
        s_qword(0, name='ClientNonce part 1')
        s_qword(0, name='ClientNonce part 2')
        s_qword(0, name='ClientNonce part 3')
        s_qword(0, name='ClientNonce part 4')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate')
        s_bytes(struct.pack('d', 1200000.0), name='Requested Session Timeout')
        s_dword(16777216, name='MaxResponseMessageSize')

def create_session_msg_nf():
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
        s_bytes(b'\x00\x00', name='authentication token', fuzzable=False) #fuzzing auth toke > BadInternalError
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='request handle', fuzzable=False)
        s_dword(0, name='return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id', fuzzable=False)
        s_dword(1000, name='timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='additional header', fuzzable=False)
            # application description
        s_dword(len(CREATE_SESSION_MSG_APP_URI_STRING), name='Application Uri Length', fuzzable=False)        
        s_bytes(CREATE_SESSION_MSG_APP_URI_STRING, name='Application Uri', fuzzable=False)
        s_dword(len(CREATE_SESSION_MSG_PRODUCER_URI_STRING), name='Production Uri Length', fuzzable=False)        
        s_bytes(CREATE_SESSION_MSG_PRODUCER_URI_STRING, name='Production Uri', fuzzable=False)
        s_bytes(b'\x02', name='App Name Has text', fuzzable=False)
        s_dword(len(CREATE_SESSION_MSG_APP_NAME_STRING), name='Application Name Length', fuzzable=False)        
        s_bytes(CREATE_SESSION_MSG_APP_NAME_STRING, name='Application Name', fuzzable=False)
        s_dword(1, name='Application Type', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri', fuzzable=False)
        s_bytes(b'\x00\x00\x00\x00', name='DiscoveryUrls', fuzzable=False) 
            # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri', fuzzable=False)
        s_dword(len(ENDPOINT_STRING), name='Url length', fuzzable=False)
        s_bytes(ENDPOINT_STRING, name='Endpoint url', fuzzable=False)
        s_dword(len(CREATE_SESSION_MSG_SESSION_NAME), name='Session Name Length', fuzzable=False)        
        s_bytes(CREATE_SESSION_MSG_APP_NAME_STRING, name='Session Name', fuzzable=False)
        s_qword(0, name='ClientNonce part 1', fuzzable=False)
        s_qword(0, name='ClientNonce part 2', fuzzable=False)
        s_qword(0, name='ClientNonce part 3', fuzzable=False)
        s_qword(0, name='ClientNonce part 4', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate', fuzzable=False)
        s_bytes(struct.pack('d', 1200000.0), name='Requested Session Timeout', fuzzable=False)
        s_dword(16777216, name='MaxResponseMessageSize', fuzzable=False)


# -----------------------ACTIVATE SESSION MSG---------------------
#TODO see what I can fuzz here (for now only timestamp)
def activate_session_msg():
    s_initialize(ACTIVATE_SESSION_MSG_NAME)

    with s_block(ACTIVATE_SESSION_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Activate session', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(ACTIVATE_SESSION_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(ACTIVATE_SESSION_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False)  #from open callback
        # type id  b'\x01\x00\xd3\x01 > d301 > 01d3 > 467
        s_bytes(b'\x01\x00' + struct.pack('<H', ACTIVATE_SESSION_MSG_TYPE_ID), name='Type id', fuzzable=False)
        # request header
        s_bytes(b'\x04', name='Encoding mask guid', fuzzable=False) # bad decoding error if fuzzed
        s_bytes(b'\x01\x00', name='Namespace idx', fuzzable=False)
        # 16B -> a6 b5 e0 ea 33 7f be 45 6a 36 e3 5e 91 59 b5 9b 
        s_bytes(b'\xa6\xb5\xe0\xea\x33\x7f\xbe\x45\x6a\x36\xe3\x5e\x91\x59\xb5\x9b', name='Identifier guid', fuzzable=False) # TODO maybe this is the session not found
        s_qword(opcua_time(), name='timestamp')#, fuzzable=False)
        s_dword(1, name='Request handle', fuzzable=False)
        s_dword(0, name='Return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Audit entry id', fuzzable=False) # malformed if negative value
        s_dword(10000, name='Timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='Additional header')
            # ClientSignature: SignatureData
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Client algorithm', fuzzable=False) # malformed if negative value
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Client signature', fuzzable=False)
        # ClientSoftwareCertificates: Array of SignedSoftwareCertificate
        s_dword(0, name='Array size client cert', fuzzable=False)
            # LocaleIds: Array of String = array size & LocaleIds: en-US -> \x65\x6e\x2d\x55\x53
        s_dword(1, name='Array size locale ids', fuzzable=False)
        s_dword(len(ACTIVATE_SESSION_MSG_LOCALE_ID_STRING), name='Locale id length', fuzzable=False)
        s_bytes(ACTIVATE_SESSION_MSG_LOCALE_ID_STRING, name='Locale id', fuzzable=False)
        '''# UserIdentityToken: ExtensionObject = 
            # EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric & Namespace Index: 0 & Identifier Numeric: 321
            # &
            # EncodingMask: 0x01, has binary body
            # &
            # AnonymousIdentityToken: AnonymousIdentityToken (size+string)'''
        s_bytes(b'\x01\x00' + struct.pack('<H', ACTIVATE_SESSION_MSG_NUM_ID), name='user type id', fuzzable=False)
        s_bytes(b'\x01', name='Encoding mask user id', fuzzable=False)
        #TODO fix add int here
        s_dword(30, name='an int', fuzzable=False) # TODO I don't know the meaning of this int
        s_dword(len(ACTIVATE_SESSION_MSG_POLICY_ID), name='Policy id length', fuzzable=False)
        s_bytes(ACTIVATE_SESSION_MSG_POLICY_ID, name='Policy id', fuzzable=False)
        ''' OLD VERSION
            policy_id = 'open62541-username-policy'.encode('utf-8')
            username = 'user1'.encode('utf-8')
            password = 'password'.encode('utf-8')
            s_dword(len(policy_id) + len(username) + len(password) + 4 + 4 + 4 + 4,
                    name='length user id token')  # 3 length fields + algorithm
            s_dword(len(policy_id), name='id length')
            s_bytes(policy_id, name='policy id', fuzzable=False)
            s_dword(len(username), name='username length')
            s_bytes(username, name='username')
            s_dword(len(password), name='password length')
            s_bytes(password, name='password')
            s_bytes(b'\xFF\xFF\xFF\xFF', name='encryption algorithm')
        '''
        # UserTokenSignature: SignatureData
        s_bytes(b'\xFF\xFF\xFF\xFF', name='User token sign algorithm', fuzzable=False) # malformed if negative value
        s_bytes(b'\xFF\xFF\xFF\xFF', name='User token signature', fuzzable=False)

def activate_session_msg_nf():
    s_initialize(ACTIVATE_SESSION_MSG_NAME)

    with s_block(ACTIVATE_SESSION_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Activate session', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(ACTIVATE_SESSION_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(ACTIVATE_SESSION_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False)  #from open callback
        # type id  b'\x01\x00\xd3\x01 > d301 > 01d3 > 467
        s_bytes(b'\x01\x00' + struct.pack('<H', ACTIVATE_SESSION_MSG_TYPE_ID), name='Type id', fuzzable=False)
            # request header
        s_dword(4, name='Encoding mask guid', fuzzable=False) # bad decoding error if fuzzed
        s_bytes(b'\x01\x00', name='Namespace idx', fuzzable=False)
        # 16B -> 34 37 bd c7 3a 2a 4a 37 75 a7 0a 00 a8 da 6d 26
        s_bytes(b'\x34\x37\xbd\xc7\x3a\x2a\x4a\x37\x75\xa7\x0a\x00\xa8\xda\x6d\x26', name='Identifier guid', fuzzable=False)
        s_qword(opcua_time(), name='timestamp', fuzzable=False)
        s_dword(1, name='Request handle', fuzzable=False)
        s_dword(0, name='Return diagnostics', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Audit entry id', fuzzable=False)
        s_dword(10000, name='Timeout hint', fuzzable=False)
        s_bytes(b'\x00\x00\x00', name='Additional header', fuzzable=False)
            # ClientSignature: SignatureData
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Client algorithm', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='Client signature', fuzzable=False)
        # ClientSoftwareCertificates: Array of SignedSoftwareCertificate
        s_dword(0, name='Array size client cert', fuzzable=False)
            # LocaleIds: Array of String = array size & LocaleIds: en-US -> \x65\x6e\x2d\x55\x53
        s_dword(0, name='Array size locale ids', fuzzable=False)
        s_dword(len(ACTIVATE_SESSION_MSG_LOCALE_ID_STRING), name='Locale id length', fuzzable=False)
        s_bytes(ACTIVATE_SESSION_MSG_LOCALE_ID_STRING, name='Locale id', fuzzable=False)
        s_bytes(b'\x01\x00' + struct.pack('<H', ACTIVATE_SESSION_MSG_NUM_ID), name='user type id', fuzzable=False)
        s_bytes(b'\x01', name='Encoding mask user id', fuzzable=False)
        s_dword(len(ACTIVATE_SESSION_MSG_POLICY_ID), name='Policy id length', fuzzable=False)
        s_bytes(ACTIVATE_SESSION_MSG_POLICY_ID, name='Policy id', fuzzable=False)
        # UserTokenSignature: SignatureData
        s_bytes(b'\xFF\xFF\xFF\xFF', name='User token sign algorithm', fuzzable=False)
        s_bytes(b'\xFF\xFF\xFF\xFF', name='User token signature', fuzzable=False)


# -----------------------BROWSE/READ MSG---------------------
def read_msg():
    s_initialize(READ_MSG_NAME)

    with s_block(READ_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Activate session', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(READ_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(READ_MSG_BODY_NAME):
        s_dword(1, name=SEC_CH_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(2, name=SEC_TOKEN_ID_PRIM_NAME, fuzzable=False)  #from open callback
        s_dword(3, name=SEC_SEQ_NUM_PRIM_NAME, fuzzable=False) #from open callback
        s_dword(4, name=SEC_REQ_ID_PRIM_NAME, fuzzable=False)  #from open callback
        # type id  b'\x01\x00\x77\x02 > 7702 > 0277 > 631
        s_bytes(b'\x01\x00' + struct.pack('<H', READ_MSG_TYPE_ID), name='Type id', fuzzable=False)


# 37 Services:
#   Discovery: FindServers - FindServersOnNetwork - GetEndpoints - RegisterServer(called from server, not interesting) - 
#   SecureChannle: OpenSecureChannel - CloseSecureChannel - 
#   Session: CreateSession - ActivateSession - 
#   Node Management (modify Addr Space): AddNodes - DeleteNodes - AddReferences - DeleteReferences - 
#   View (navigate Addr Space): Browse - BrowseNext - TranslateBrowsePathsToNodeIds - RegisterNodes - UnregisterNodes - 
#   Query: QueryFirst - QueryNext - 
#   Attribute: Read (read one or more Attributes of one or mode Nodes) - Write - HistoryRead - HistoryUpdate - 
#   Method: Call - 
#   MonitoredItem: CreateMonitoredItems - ModifyMonitoredItems - SetMonitoringMode - SetTriggering - DeleteMonitoredItems - 
# Subscription: CreateSubscription - ModifySubscription - SetPublishingMode - Publish - Republish - TransferSubscrition (among sessions) - SeleteSubscriptions 
#        