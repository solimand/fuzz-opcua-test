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

## Environment for testing
- Download and run the container ```docker pull open62541/open62541:master```
- create a virtual env ```python3 -m venv env``` activate (fish) ```source ./env/bin/activate.fish``` install dependencies ```pip install -r requirements.txt```
- Copy ```fuzz_logger_db_mod``` in ```./env/lib/python3.10/site-packages/boofuzz/fuzz_logger_db.py```. Due to the multiple calls of the ```fuzz()``` function for the information model use case, we need to check in the same DB if the tables exist during their creation