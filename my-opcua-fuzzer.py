#!/usr/bin/env python3

from constants import HELLO_MSG_BODY_NAME, HOST_ADDR, OPC_UA_PORT, ENDPOINT_STRING, CHUNK_TYPE
from constants import HELLO_MSG_NAME, HELLO_MSG_TYPE, HELLO_MSG_HEADER_NAME, HELLO_MSG_BODY_NAME
from constants import OPEN_MSG_NAME, OPEN_MSG_TYPE, OPEN_MSG_HEADER_NAME, OPEN_MSG_BODY_NAME, OPEN_MSG_SEC_POLICY_NONE
from constants import UNIX_TIME

#from constants import CLOSE_MSG_NAME, CLOSE_MSG_TYPE, CLOSE_MSG_HEADER_NAME, CLOSE_MSG_BODY_NAME

# TODO import only boofuz needed modules
from boofuzz import *

# Dates
from datetime import datetime
from calendar import timegm

def main():
    print("starting fuzzer")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(HOST_ADDR, OPC_UA_PORT)),
        index_start=0,
        index_end=3)

    print_dbg(session.web_port)

    hello_msg()

    session.connect(s_get(HELLO_MSG_NAME))

    with open('./myopcuaTest.png', 'wb') as file:
        file.write(session.render_graph_graphviz().create_png())

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass

# -----------------------MSGs DEF---------------------
def hello_msg():
    s_initialize(HELLO_MSG_NAME)

    with s_block(HELLO_MSG_HEADER_NAME):
        s_bytes(HELLO_MSG_TYPE, name='Hello magic', fuzzable=False)
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
        s_bytes(OPEN_MSG_TYPE, name='Open magic', fuzzable=False)
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
        #OpenSecureChannelRequest > RequestHeader > NodeId
        s_bytes(b'\x00\x00', name='Authentication Token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        # TODO remaining fields




'''def close_msg():
    s_initialize(CLOSE_MSG_NAME)

    with s_block(CLOSE_MSG_HEADER_NAME):
        s_bytes(CLOSE_MSG_TYPE, name='Close channel magic', fuzzable=False)
        s_bytes(CHUNK_TYPE, name='Chunk type', fuzzable=False)
        s_size(CLOSE_MSG_BODY_NAME, offset=8, name='body size', fuzzable=False)

    with s_block(CLOSE_MSG_BODY_NAME):
        s_dword(0, name='Protocol version')'''



# -----------------------UTILS---------------------
def print_dbg(msg):
    print("DBG: "+str(msg))

def opcua_time():
    now = datetime.now()
    res_time = UNIX_TIME + (timegm(now.timetuple()) * 10000000)
    return res_time + (now.microsecond * 10)


if __name__ == "__main__":
    main()

