# Fuzzing OPC UA protocol

A black-box fuzzer for the OPC UA protocol.

## Usage
```
python myOpcuaFuzzer.py [-h] ip-addr [port]

positional arguments:
  ip-addr     The server host IP address
  port        The server host port

optional arguments:
  -h, --help  show this help message and exit
```

## Requirements
- python3 
- boofuzz
- ...