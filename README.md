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
- Copy ```fuzz_logger_db_mod``` in ```./env/lib/python3.10/site-packages/boofuzz/fuzz_logger_db.py```. Due to the multiple calls of the ```fuzz()``` function for the information model use case, we need to check in the same DB if the tables exist during their creation
- WINDOWS Only: install curses from [source](https://www.lfd.uci.edu/~gohlke/pythonlibs/#curses)g

## Environment for testing
- Download and run the container with the server implementations
  - for open62541 > ```docker pull msolimandounibo/opcua-os-servers:open62541_v1.0``` > ```docker run -d -it -p 4840:4840 --name openopcua msolimandounibo/opcua-os-servers:open62541_v1.0```
  - for python opcua > ```docker pull msolimandounibo/opcua-os-servers:pythopcua_v1.0``` > ```docker run -d -it -p 4840:4840 --name openopcua msolimandounibo/opcua-os-servers:pythopcua_v1.0```
- create a virtual env ```python3 -m venv env``` activate (fish) ```source ./env/bin/activate.fish``` install dependencies ```pip install -r requirements.txt```
- launch with python command and specified address (container or localhost:<redirection_port>) and port (container exposed port)


# Main TODOs
- arrange single msg fuzz (check which fields mutate)
- asynch issues with Information Model fuzz