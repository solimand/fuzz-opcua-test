# CALLBACKS
- ```get_endpoint()``` callback: it could be useful to fuzz using different endpoints
- ```generic_callback()``` it might be useful to keep track of errors type occurring at the end of each chain

# INFORMATION MODEL FUZZING
- fuzzing of variables at a depth level > 1
- fuzzing of methods
- fuzzing variable values type different from Int32

# IMPLEMENTATION FUZZING
- Fuzzing other service sets...

# SMALL Fixes
- fix cross-implementation variable names searching
- analyze the error of creating new sessions in opc62541 - is a vulnerability? will this prevent other operations?
- analyze all the fields of all messages to check what can be fuzzed without errors 
- meaning of the INT in Activate Session Msg (```s_dword(30, name='an int'```) 
- fuzz_constants -> ```ENDPOINT_STRING``` based on main args