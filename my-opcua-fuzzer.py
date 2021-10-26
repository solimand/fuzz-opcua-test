#!/usr/bin/env python3

from constants import HELLO_MSG_BODY_NAME, HOST_ADDR, OPC_UA_PORT, ENDPOINT_STRING, CHUNK_TYPE
from constants import HELLO_MSG_NAME, HELLO_MSG_TYPE, HELLO_MSG_HEADER_NAME, HELLO_MSG_BODY_NAME
from constants import OPEN_MSG_NAME, OPEN_MSG_TYPE, OPEN_MSG_HEADER_NAME, OPEN_MSG_BODY_NAME, OPEN_MSG_SEC_POLICY_NONE
from constants import UNIX_TIME, COMMON_MSG_TYPE, PNG_GRAPH_OUT_FILE
from constants import GET_ENDPOINTS_MSG_NAME, GET_ENDPOINTS_MSG_HEADER_NAME, GET_ENDPOINTS_MSG_BODY_NAME
from constants import CLOSE_MSG_NAME, CLOSE_MSG_TYPE, CLOSE_MSG_HEADER_NAME, CLOSE_MSG_BODY_NAME

from boofuzz import s_initialize, s_bytes, s_dword, s_get, s_block, s_size, s_qword
from boofuzz import Session, Target, TCPSocketConnection

# struct — Interpret bytes as packed binary data
import struct

# Dates
from datetime import datetime
from calendar import timegm

#DBG
from pprint import pprint #print obj attributes

def main():
    print_dbg("starting fuzzer")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(HOST_ADDR, OPC_UA_PORT)),
        index_start=0,
        index_end=5)
        #post_test_case_callbacks=[hello_callback])

    hello_msg_nf()
    #hello_msg()
    open_msg()
    close_msg()

    session.connect(s_get(HELLO_MSG_NAME))
    #session.connect(s_get(HELLO_MSG_NAME), callback=hello_callback)
    
    session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME), callback=hello_callback)
    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)
    
    # session graph PNG creation
    #with open(PNG_GRAPH_OUT_FILE, 'wb') as file:
    #    file.write(session.render_graph_graphviz().create_png())

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass

# -----------------------MSGs DEF - nf=not fuzzed---------------------
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

    with s_block(HELLO_MSG_BODY_NAME):
        s_dword(0, name='Protocol version')
        s_dword(65536, name='Receive buffer size')
        s_dword(65536, name='Send buffer size')
        s_dword(0, name='Max message size')
        s_dword(0, name='Max chunk count')
        s_dword(len(ENDPOINT_STRING), name='Url length')
        s_bytes(ENDPOINT_STRING, name='Endpoint url')

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

def close_msg():
    s_initialize(CLOSE_MSG_NAME)

    with s_block(CLOSE_MSG_HEADER_NAME):
        s_bytes(CLOSE_MSG_TYPE, name='Close msg', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(CLOSE_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(CLOSE_MSG_BODY_NAME):
        s_dword(0, name='secure channel id', fuzzable=False)
        s_dword(4, name='secure token id', fuzzable=False)
        s_dword(2, name='secure sequence number', fuzzable=False)
        s_dword(2, name='secure request id', fuzzable=False)
        # type id
        s_bytes(b'\x01\x00' + struct.pack('<H', 452), name='Type id', fuzzable=False)
        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(opcua_time(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(10000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')


'''def get_endpoints():
    s_initialize(GET_ENDPOINTS_MSG_NAME)

    with s_block(GET_ENDPOINTS_MSG_HEADER_NAME):
        s_bytes(COMMON_MSG_TYPE, name='Get Endpoints', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(GET_ENDPOINTS_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(GET_ENDPOINTS_MSG_BODY_NAME):
        s_dword(0, name='secure channel id', fuzzable=False)
        s_dword(4, name='secure token id', fuzzable=False)
        s_dword(2, name='secure sequence number', fuzzable=False)
        s_dword(2, name='secure request id', fuzzable=False)
        # Type ID
        s_bytes(b'\x01\x00' + struct.pack('<H', 428), name='Type id', fuzzable=False)
        # Req header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(opcua_time(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')
        #Req params
        #TODO other fields'''


# -----------------------CallBacks------------------
#TODO understand bytes
def open_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    print_dbg(str(pprint(vars(session))))
    try:
        channel_id, policy_len = struct.unpack('ii', res[8:16])
        sequence_offset = 24 + policy_len
        seq_num, req_id = struct.unpack('ii', res[sequence_offset:sequence_offset + 8])

        request_header_length = 8 + 4 + 4 + 1 + 4 + 3
        token_offset = sequence_offset + 8 + 4 + request_header_length + 4
        sec_channel_id, token_id = struct.unpack('ii', res[token_offset:token_offset + 8])

    except struct.error:
        fuzz_data_logger.log_error('ERR - could not unpack response')
    else:
        test_case_context.stack[1].stack[0]._value = sec_channel_id
        test_case_context.stack[1].stack[1]._value = token_id
        test_case_context.stack[1].stack[2]._value = seq_num + 1
        test_case_context.stack[1].stack[3]._value = req_id + 1

# TODO try to parse ACK
def hello_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    res = session.last_recv
    '''if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return'''
    print_dbg(res)
    #pprint(vars(session))
    #print_dbg(target.recv())


# -----------------------UTILS---------------------
def print_dbg(msg):
    print("\tDBG: "+str(msg))

def opcua_time():
    now = datetime.now()
    res_time = UNIX_TIME + (timegm(now.timetuple()) * 10000000)
    return res_time + (now.microsecond * 10)


if __name__ == "__main__":
    main()

