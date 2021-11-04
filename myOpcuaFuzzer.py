#!/usr/bin/env python3

from fuzzConstants import HOST_ADDR, OPC_UA_PORT, HELLO_MSG_NAME, OPEN_MSG_NAME, ACK_MSG_TYPE, ERR_MSG_TYPE, CLOSE_MSG_NAME, OPEN_MSG_TYPE

from boofuzz import Session, Target, TCPSocketConnection, s_get

from msgDefinitions import hello_msg, hello_msg_nf, open_msg, open_msg_nf, close_msg, print_dbg, CLOSE_MSG_BODY_NAME

# struct - Interpret bytes as packed binary data -- for callbacks
import struct

#DBG
from pprint import pprint #print obj attributes -> pprint(vars(obj))


# -----------------------CallBacks------------------
def open_callback(target, fuzz_data_logger, session, node, *_, **__):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
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
        #print_dbg("sequence num  "+str(seq_num)+" req id "+str(req_id))
        #print_dbg("sec ch id "+str(sec_channel_id)+" token id "+str(token_id))
    except struct.error:
        fuzz_data_logger.log_error('ERR - could not unpack response')
    else:
        #node.stack[1] -> msg Body
        # TODO PROBLEM the next packet is not set         
        #node.names['Close.c-body.secure channel id'] = sec_channel_id
        node.stack[1].stack[0]._default_value = sec_channel_id
        node.stack[1].stack[1]._value = token_id
        node.stack[1].stack[2]._value = seq_num + 1
        node.stack[1].stack[3]._value = req_id + 1
    print_dbg("sec ch from node names " + str(node.names['Close.c-body.secure channel id']))
    print_dbg("sec ch from session " + str(session.nodes[3].names['Close.c-body.secure channel id']))
    print_dbg("all values of sec ch id " + str(pprint(vars(node.stack[1].stack[0]))))


def hello_callback(target, fuzz_data_logger, session, node, *_, **__):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    msg_type_tuple = struct.unpack('ccc', res[0:3])
    msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
    if (msg_type == ACK_MSG_TYPE):
        print_dbg("ACK received!")
    

def generic_callback(target, fuzz_data_logger, session, node=None, *_, **__):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    msg_type_tuple = struct.unpack('ccc', res[0:3])
    msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
    if (msg_type == ERR_MSG_TYPE):
        print_dbg("ERR received!")
        #TODO kinds of error
    if (msg_type == OPEN_MSG_TYPE):
        print_dbg("OPN received!")
    if (msg_type == ACK_MSG_TYPE):
        print_dbg("ACK received!")


# -----------------------MAIN---------------------
# TODO add args to select which tests
def main():
    print_dbg("starting fuzzer")    

    hello_msg_nf()
    #hello_msg()
    open_msg_nf()
    #open_msg()
    close_msg()
    
    session = Session(
        target=Target(
            connection=TCPSocketConnection(HOST_ADDR, OPC_UA_PORT)),
        #post_test_case_callbacks=[generic_callback],
        sleep_time=0, #sleep at the end of the graph
        receive_data_after_fuzz=True, #receive last response if there is
        keep_web_open=False, #close web UI at the end of the graph
        #web_port=None,
        index_start=1,
        index_end=3)
        #index_start=291,
        #index_end=293)
        
    #session.connect(s_get(HELLO_MSG_NAME), callback=hello_callback)
    session.connect(s_get(HELLO_MSG_NAME))

    #session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME), callback=hello_callback)
    session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME))

    session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)
    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME))

    # session graph PNG creation
    #with open(PNG_GRAPH_OUT_FILE, 'wb') as file:
    #    file.write(session.render_graph_graphviz().create_png())

    # TODO procmon and netmon

    session.fuzz()

    '''try:
        session.fuzz()
    except KeyboardInterrupt:
        pass'''

if __name__ == "__main__":
    main()

