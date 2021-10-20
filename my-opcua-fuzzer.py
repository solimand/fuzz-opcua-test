#!/usr/bin/env python3

import constants

from boofuzz import *

def main():
    print("starting fuzzer")
    session = Session(
    target=Target(
        connection=TCPSocketConnection(constants.HOST_ADDR, constants.OPC_UA_PORT)))

    #print("DBG: "+str(session.web_port))
    print_dbg(session.web_port)
    print_dbg("close")

# -----------------------MSGs DEF---------------------
# TODO use constants for msgs definitions
def hello_definition():
    s_initialize('Hello')

    with s_block('h-header'):
        s_bytes(b'HEL', name='Hello magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('h-body', offset=8, name='body size', fuzzable=False)

    with s_block('h-body'):
        s_dword(0, name='Protocol version')
        s_dword(65536, name='Receive buffer size')
        s_dword(65536, name='Send buffer size')
        s_dword(0, name='Max message size')
        s_dword(0, name='Max chunk count')
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='Url length')
        s_bytes(endpoint, name='Endpoint url')

# -----------------------UTILS---------------------
def print_dbg(msg):
    print("DBG: "+str(msg))

if __name__ == "__main__":
    main()

