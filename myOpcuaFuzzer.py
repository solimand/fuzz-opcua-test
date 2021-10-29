#!/usr/bin/env python3

from fuzzConstants import HOST_ADDR, OPC_UA_PORT, HELLO_MSG_NAME, OPEN_MSG_NAME, ACK_MSG_TYPE, ERR_MSG_TYPE

from boofuzz import Session, Target, TCPSocketConnection, s_get

from msgDefinitions import hello_msg, hello_msg_nf, open_msg, open_msg_nf, close_msg, print_dbg

# struct — Interpret bytes as packed binary data
import struct

#DBG
from pprint import pprint #print obj attributes -> pprint(vars(obj))

# -----------------------MAIN---------------------
# TODO add args to select which tests
def main():
    print_dbg("starting fuzzer")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(HOST_ADDR, OPC_UA_PORT)),
        post_test_case_callbacks=[err_callback],
        #sleep_time=5, #sleep between tests
        receive_data_after_fuzz=True,
        keep_web_open=False,
        web_port=None,
        index_start=291,
        index_end=293)
        

    hello_msg_nf()
    #hello_msg()
    #print_dbg("num muts hello = " + str(s_num_mutations()))
    #open_msg_nf()
    open_msg()
    #print_dbg("num muts open = " + str(s_num_mutations()))
    #close_msg()

    #session.connect(s_get(HELLO_MSG_NAME), callback=hello_callback)
    session.connect(s_get(HELLO_MSG_NAME))

    session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME), callback=hello_callback)
    #session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME))

    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)
    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME))

    # session graph PNG creation
    #with open(PNG_GRAPH_OUT_FILE, 'wb') as file:
    #    file.write(session.render_graph_graphviz().create_png())

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass


# -----------------------CallBacks------------------
def open_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    #print_dbg( "res= "+str(res))
    try:
        msg_type_tuple = struct.unpack('ccc', res[0:3])
        msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
        # 8B=header, 4B=ch id + 4B=policy len
        channel_id, policy_len = struct.unpack('ii', res[8:16])
        # 16B=before + policylen + 4B=senderCert + 4B=receiverCert -> policylen+24
        sequence_offset = 24 + policy_len
        # seqNum=4B and reqid =4B
        seq_num, req_id = struct.unpack('ii', res[sequence_offset:sequence_offset + 8])
        # before=24+policyLen+8(seqNum+reqId)=32+policyLen
        # 32+policyLen+4(typeid)+8(time)+4(reqHandle)+4(ServRes)+1(diagnostic)+4(stringTable)+
            # +3(additionalHeader)+4(servProtVer)->policyLen+64->start of sec_ch_id
        request_header_length = 8 + 4 + 4 + 1 + 4 + 3 #(24)
        token_offset = sequence_offset + 8 + 4 + request_header_length + 4 #(24+8+4+24+4=64)
        sec_channel_id, token_id = struct.unpack('ii', res[token_offset:token_offset + 8])
        print_dbg(msg_type)
        #print_dbg("ch id = "+str(channel_id))
        #print_dbg("sec ch id = "+str(sec_channel_id))
        #print_dbg("tok id = "+str(token_id))

    except struct.error:
        fuzz_data_logger.log_error('ERR - could not unpack response')
    '''else:
        test_case_context.stack[1].stack[0]._value = sec_channel_id
        test_case_context.stack[1].stack[1]._value = token_id
        test_case_context.stack[1].stack[2]._value = seq_num + 1
        test_case_context.stack[1].stack[3]._value = req_id + 1'''
    
    #print_dbg("test case = "+str(pprint(vars(test_case_context))))
    print_dbg("test case = "+str(test_case_context.session_variables))

def hello_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    msg_type_tuple = struct.unpack('ccc', res[0:3])
    msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
    print_dbg(kwargs)
    print_dbg("target" + str(pprint(vars(target))))
    print_dbg("session" + str(pprint(vars(session))))
    if (msg_type == ACK_MSG_TYPE):
        print_dbg("ACK received!")

def err_callback(target, fuzz_data_logger, session, test_case_context=None, *args, **kwargs):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    msg_type_tuple = struct.unpack('ccc', res[0:3])
    msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
    if (msg_type == ERR_MSG_TYPE):
        print_dbg("ERR received!")
        #TODO kinds of error


if __name__ == "__main__":
    main()

