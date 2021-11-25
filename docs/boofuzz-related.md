# Boofuzz related functions

## connect(src, dst=None, callback=None)
Create a connection between the two requests (nodes) and register an optional callback to process in between transmissions of the source and destination request. The session class maintains a top level node that all initial requests must be connected to.
    
Example:

```sess = sessions.session() ```
```sess.connect(sess.root, s_get("HTTP"))```

If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node. This is a convenient alias. The following line is identical to the second line from the above example:

```sess.connect(s_get("HTTP"))```

Leverage callback methods to handle situations such as challenge response systems. A callback method must follow the message signature of Session.example_test_case_callback(). Remember to in- clude **kwargs for forward-compatibility. 

### Parameters
* ```src (str or Request (pgrah.Node))``` – Source request name or request node
* ```dst (str or Request (pgrah.Node), optional)``` – Destination request name or re-
quest node
* ```callback (def , optional)``` – Callback function to pass received data to between node xmits. Default None. 

### Returns 
The edge between the src and dst.

### Return type
pgraph.Edge

### example_test_case_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs)
Example call signature for methods given to connect() or register_post_test_case_callback()
Parameters
* ```target (Target)``` – Target with sock-like interface.
* ```fuzz_data_logger (ifuzz_logger.IFuzzLogger)``` – Allows logging of test checks and
passes/failures. Provided with a test case and test step already opened.
* ```session (Session)``` – Session object calling post_send.
 Useful properties include
last_send and last_recv.
* ```test_case_context (ProtocolSession)``` – Context for test case-scoped data.
ProtocolSession session_variables values are generally set within a callback and
referenced in elements via default values of type ProtocolSessionReference.
* ```args``` – Implementations should include *args and **kwargs for forward-compatibility.
* ```kwargs``` – Implementations should include *args and **kwargs for forward-compatibility.

## Process Monitor
It can be used to start, monitor, and restart target programs. It uses [pydbg](https://pypi.org/project/pydbg/) to get information about crashed programs.