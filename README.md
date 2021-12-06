# Fuzzing OPC UA protocol

A black-box fuzzer for the OPC UA protocol.

## Usage
```
python myOpcuaFuzzer.py [-h] [-m] ip-addr [port]

positional arguments:
  ip-addr     The server host IP address
  port        The server host port

optional arguments:
  -h, --help  show this help message and exit
  -m, --info  Test the information model instead of implementation
```

## Requirements
- python3 
- boofuzz
- ...