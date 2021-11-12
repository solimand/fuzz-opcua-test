#!/usr/bin/env python3

from fuzzConstants import ACTIVATE_SESSION_MSG_NAME, OPC_UA_PORT, HELLO_MSG_NAME, OPEN_MSG_NAME, ACK_MSG_TYPE, ERR_MSG_TYPE, OPEN_MSG_TYPE

from fuzzConstants import CLOSE_MSG_SEQ_NUM_NODE_FIELD, CLOSE_MSG_TOKEN_ID_NODE_FIELD, CLOSE_MSG_SEC_CH_ID_NODE_FIELD, CLOSE_MSG_SEQ_REQ_ID_NODE_FIELD, CLOSE_MSG_BODY_NAME, CLOSE_MSG_NAME

from fuzzConstants import GET_ENDPOINTS_MSG_NAME, GET_ENDPOINTS_MSG_BODY_NAME, GET_ENDPOINTS_MSG_SEC_CH_ID_NODE_FIELD,GET_ENDPOINTS_MSG_TOKEN_ID_NODE_FIELD, GET_ENDPOINTS_MSG_SEQ_NUM_NODE_FIELD, GET_ENDPOINTS_MSG_SEQ_REQ_ID_NODE_FIELD

from fuzzConstants import CREATE_SESSION_MSG_BODY_NAME, CREATE_SESSION_MSG_NAME, CREATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD, CREATE_SESSION_MSG_TOKEN_ID_NODE_FIELD, CREATE_SESSION_MSG_SEQ_NUM_NODE_FIELD, CREATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD

from fuzzConstants import ACTIVATE_SESSION_MSG_NAME, ACTIVATE_SESSION_MSG_BODY_NAME, ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD, ACTIVATE_SESSION_MSG_TOKEN_ID_NODE_FIELD, ACTIVATE_SESSION_MSG_SEQ_NUM_NODE_FIELD, ACTIVATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD

from boofuzz import Session, Target, TCPSocketConnection, s_get

from msgDefinitions import print_dbg, hello_msg, hello_msg_nf, open_msg, open_msg_nf, close_msg, close_msg_nf, get_endpoints_msg, get_endpoints_msg_nf, create_session_msg, create_session_msg_nf, activate_session_msg

# struct - Interpret bytes as packed binary data -- for callbacks
import struct

from argparse import ArgumentParser
from ipaddress import ip_address
#import argparse, ipaddress

#DBG
from pprint import pprint #print obj attributes -> pprint(vars(obj))


# -----------------------CallBacks------------------
#TODO callback for endpoint url
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
        # node.stack[1] -> msg Body
        if (node.stack[1]._name == GET_ENDPOINTS_MSG_BODY_NAME):
            print_dbg('getendpoint version')
            node.names[GET_ENDPOINTS_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[GET_ENDPOINTS_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[GET_ENDPOINTS_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[GET_ENDPOINTS_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            print_dbg("sec ch from node names " + str(node.names[GET_ENDPOINTS_MSG_SEC_CH_ID_NODE_FIELD]))
        elif (node.stack[1]._name == CLOSE_MSG_BODY_NAME):
            print_dbg('close version')
            node.names[CLOSE_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[CLOSE_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[CLOSE_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[CLOSE_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            print_dbg("sec ch from node names " + str(node.names[CLOSE_MSG_SEC_CH_ID_NODE_FIELD]))
        elif (node.stack[1]._name == CREATE_SESSION_MSG_BODY_NAME):
            print_dbg('create session version')
            node.names[CREATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[CREATE_SESSION_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[CREATE_SESSION_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[CREATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            print_dbg("sec ch from node names " + str(node.names[CREATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]))
            '''elif (node.stack[1]._name == ACTIVATE_SESSION_MSG_BODY_NAME):
            print_dbg('activate session version')
            node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[ACTIVATE_SESSION_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[ACTIVATE_SESSION_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[ACTIVATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            print_dbg("sec ch from node names " + str(node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]))'''
        else:
            fuzz_data_logger.log_error('ERR - callback not implementated for msg')
            print('ERR on msg body %s', node.stack[1]._name)
open_callback.__doc__ = "Callback setting parameters of secure channel"

def create_callback(target, fuzz_data_logger, session, node, *_, **__):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    try:
        msg_type_tuple = struct.unpack('ccc', res[0:3])
        msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
        sec_channel_id, token_id, seq_num, req_id= struct.unpack('iiii', res[8:24])
        if (node.stack[1]._name == ACTIVATE_SESSION_MSG_BODY_NAME):
            print_dbg('activare sess version')
            node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[ACTIVATE_SESSION_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[ACTIVATE_SESSION_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[ACTIVATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            print_dbg("sec ch from node names " + str(node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]))
        else:
            fuzz_data_logger.log_error('ERR - callback not implementated for msg')
            print('ERR on msg body %s', node.stack[1]._name)
    except struct.error:
        fuzz_data_logger.log_error('ERR - could not unpack response') 

def hello_callback(target, fuzz_data_logger, session, node, *_, **__):
    res = session.last_recv
    if not res:
        fuzz_data_logger.log_fail('ERR - empty response')
        return
    msg_type_tuple = struct.unpack('ccc', res[0:3])
    msg_type = msg_type_tuple[0]+msg_type_tuple[1]+msg_type_tuple[2]
    if (msg_type == ACK_MSG_TYPE):
        print_dbg("ACK received!")
hello_callback.__doc__ = "Callback to check the ACK"

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
    elif (msg_type == OPEN_MSG_TYPE):
        print_dbg("OPN received!")
    elif (msg_type == ACK_MSG_TYPE):
        print_dbg("ACK received!")
generic_callback.__doc__ = "Callback executed after each session graph test case"


# -----------------------MAIN---------------------
# TODO add args to select which tests
def main():
    # ARGS parsing----------
    parser = ArgumentParser(description='Fuzzing OPC UA server.')
    parser.add_argument('addr', metavar='ip-addr', type=str, help='The server host IP address')
    args = parser.parse_args()

    # IP ADDR validiation----------
    try:
        HOST_ADDR = ip_address(args.addr)
        print_dbg('%s is starting fuzzing the OPC UA server at %s IPv%s address.' % (parser.prog, HOST_ADDR, HOST_ADDR.version))
    except ValueError:
        print('address/netmask is invalid: %s' % args.addr)
        print('Usage : %s ipAddress' % parser.prog)
        return
    except:
        print('Usage : %s ipAddress' % args.addr)
        return

    # MSGs building----------
    hello_msg_nf()
    #hello_msg()

    open_msg_nf()
    #open_msg()

    close_msg_nf()
    #close_msg()

    get_endpoints_msg_nf()
    #get_endpoints_msg()
    
    create_session_msg_nf()
    #create_session_msg()
    
    #activate_session_msg_nf()
    activate_session_msg()

    # SESSION building----------
    session = Session(
        target=Target(
            connection=TCPSocketConnection(str(HOST_ADDR), OPC_UA_PORT)),
        #post_test_case_callbacks=[generic_callback], #executed at the end of the chain
        sleep_time=0, #sleep at the end of the graph
        receive_data_after_fuzz=True, #receive last response if there is
        keep_web_open=False, #close web UI at the end of the graph
        #web_port=None,
        index_start=1,
        index_end=1)
        #index_start=291,
        #index_end=293)
        
    # GRAPH building----------
    ''' OPC client initiatied comm protocol
        C                                       S
                            HEL-->
                            <--ACK

                    OPEN Req (sec ch)-->
                    <--OPEN Res (sec ch)

                    CREATE Req (sess)-->
                    <--CREATE Res (sess)

                    ACTIVATE Req (sess)-->
                    <--ACTIVATE Res (sess)

                    READ Req-->
                    <--READ res

                    CLOSE Sess Req-->
                    <--CLOSE Sess Res

                    CLOSE Sec Ch Req-->
                    <--CLOSE Sec ch Res
    '''
    session.connect(s_get(HELLO_MSG_NAME))

    session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME), callback=hello_callback)
    #session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME)) # ACK callback only for debug 

    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)
    #session.connect(s_get(OPEN_MSG_NAME), s_get(GET_ENDPOINTS_MSG_NAME), callback=open_callback)

    session.connect(s_get(OPEN_MSG_NAME), s_get(CREATE_SESSION_MSG_NAME), callback=open_callback)
    session.connect(s_get(CREATE_SESSION_MSG_NAME), s_get(ACTIVATE_SESSION_MSG_NAME), callback=create_callback)
    #session.connect(s_get(ACTIVATE_SESSION_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)


    # TODO procmon and netmon
    # session graph PNG creation
    #with open(PNG_GRAPH_OUT_FILE, 'wb') as file:
    #    file.write(session.render_graph_graphviz().create_png())

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
