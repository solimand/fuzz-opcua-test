#!/usr/bin/env python3

import constants

from boofuzz import *

def main():
    print("starting fuzzer")
    session = Session(
    target=Target(
        connection=TCPSocketConnection(constants.HOST_ADDR, constants.OPC_UA_PORT)))


if __name__ == "__main__":
    main()

