#!/usr/bin/env python3

from ctypes import sizeof
from os import truncate, write
import boofuzz
from boofuzz import blocks

from six import print_
from fuzzConstants import HELLO_MSG_NAME, OPEN_MSG_NAME, ACK_MSG_TYPE, ERR_MSG_TYPE, OPEN_MSG_TYPE, PROC_MON_PORT

from fuzzConstants import CLOSE_MSG_SEQ_NUM_NODE_FIELD, CLOSE_MSG_TOKEN_ID_NODE_FIELD, CLOSE_MSG_SEC_CH_ID_NODE_FIELD, CLOSE_MSG_SEQ_REQ_ID_NODE_FIELD, CLOSE_MSG_BODY_NAME, CLOSE_MSG_NAME

from fuzzConstants import GET_ENDPOINTS_MSG_NAME, GET_ENDPOINTS_MSG_BODY_NAME, GET_ENDPOINTS_MSG_SEC_CH_ID_NODE_FIELD,GET_ENDPOINTS_MSG_TOKEN_ID_NODE_FIELD, GET_ENDPOINTS_MSG_SEQ_NUM_NODE_FIELD, GET_ENDPOINTS_MSG_SEQ_REQ_ID_NODE_FIELD

from fuzzConstants import CREATE_SESSION_MSG_BODY_NAME, CREATE_SESSION_MSG_NAME, CREATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD, CREATE_SESSION_MSG_TOKEN_ID_NODE_FIELD, CREATE_SESSION_MSG_SEQ_NUM_NODE_FIELD, CREATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD

from fuzzConstants import ACTIVATE_SESSION_MSG_NAME, ACTIVATE_SESSION_MSG_BODY_NAME, ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD, ACTIVATE_SESSION_MSG_TOKEN_ID_NODE_FIELD, ACTIVATE_SESSION_MSG_SEQ_NUM_NODE_FIELD, ACTIVATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD, ACTIVATE_AUTH_TOKEN_ID_GUID_NODE_FIELD

from fuzzConstants import READ_MSG_NAME, READ_MSG_BODY_NAME, READ_MSG_SEC_CH_ID_NODE_FIELD, READ_MSG_TOKEN_ID_NODE_FIELD, READ_MSG_SEQ_NUM_NODE_FIELD, READ_MSG_SEQ_REQ_ID_NODE_FIELD, READ_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD

from fuzzConstants import BROWSE_MSG_NAME, BROWSE_MSG_BODY_NAME, BROWSE_MSG_SEC_CH_ID_NODE_FIELD, BROWSE_MSG_TOKEN_ID_NODE_FIELD, BROWSE_MSG_SEQ_NUM_NODE_FIELD, BROWSE_MSG_SEQ_REQ_ID_NODE_FIELD, BROWSE_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD

from fuzzConstants import WRITE_MSG_NAME, WRITE_MSG_FAKE_NAME, WRITE_MSG_BODY_NAME, WRITE_MSG_FAKE_BODY_NAME, WRITE_MSG_SEC_CH_ID_NODE_FIELD, WRITE_MSG_TOKEN_ID_NODE_FIELD, WRITE_MSG_SEQ_NUM_NODE_FIELD, WRITE_MSG_SEQ_REQ_ID_NODE_FIELD, WRITE_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD, WRITE_MSG_FAKE_SEC_CH_ID_NODE_FIELD, WRITE_MSG_FAKE_TOKEN_ID_NODE_FIELD, WRITE_MSG_FAKE_SEQ_NUM_NODE_FIELD, WRITE_MSG_FAKE_SEQ_REQ_ID_NODE_FIELD, WRITE_MSG_FAKE_AUTH_TOKEN_ID_GUID_NODE_FIELD


from boofuzz import Session, Target, TCPSocketConnection, s_get, ProcessMonitor

from msgDefinitions import print_dbg, hello_msg, hello_msg_nf, open_msg, open_msg_nf, close_msg, close_msg_nf, get_endpoints_msg, get_endpoints_msg_nf, create_session_msg, create_session_msg_nf, activate_session_msg, activate_session_msg_nf, read_objects_msg, browse_objects_msg, browse_objects_msg_nf, write_variable_msg, write_variable_msg_nf

# struct - Interpret bytes as packed binary data -- for callbacks
import struct

from argparse import ArgumentParser
from ipaddress import ip_address

# for DBG
from pprint import pprint #print obj attributes -> pprint(vars(obj))

# global vars that must survive to callback execs
auth_token_read_req = ''
servVars = []
test_info_model = False
PNG_GRAPH_OUT_FILE = './mygraph.png'


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
        # 4B (typeid) + 24B (ResHeader) + 3B (first part of SessID) -> next 16B are the SessId-IdGuid
        #   = 31 + 16B [from 55 to 71]
        # 1B (encoding mask) + 2B (namespace id) -> next 16B are the AuthId-IdGuid
        #   = 3 + 16B [from 74 to 90]
            # first 4B are reversed A B C D -> D C B A
            # following two couples of 2B are reversed AB CD -> BA DC
            # last 8B are the same as on wire

        # I don't need further decoding/encoding (struct.unpack) because I must send them as Bytes
        #sessId_IdGuid_string = struct.unpack('16c', res[55:71])
        #print_dbg('sessid string plain' + str(sessId_IdGuid_string))

        #sessId_plain = res[55:71] # I don't know if in future I will need the sessionID 
        #print_dbg('sessid plain ' + str(sessId_plain))
        authId_plain = res[74:90]
        if (node.stack[1]._name == ACTIVATE_SESSION_MSG_BODY_NAME):
            print_dbg('activate sess version')
            node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[ACTIVATE_SESSION_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[ACTIVATE_SESSION_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[ACTIVATE_SESSION_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            node.names[ACTIVATE_AUTH_TOKEN_ID_GUID_NODE_FIELD]._default_value = authId_plain
            print_dbg("sec ch from node names " + str(node.names[ACTIVATE_SESSION_MSG_SEC_CH_ID_NODE_FIELD]))
            # in my chain activate_sess_req always follows a create_sess_res
            #   I save the token only when a new create_sess_res occurs
            global auth_token_read_req
            auth_token_read_req = authId_plain
        elif ((node.stack[1]._name == READ_MSG_BODY_NAME)):
            print_dbg('read req version')
            # the msg activate_session_response (occurring before read_request in the fuzzing chain)
            #   has the same security params of create_res but no auth token id
            node.names[READ_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[READ_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[READ_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[READ_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            node.names[READ_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD]._default_value = auth_token_read_req
        elif ((node.stack[1]._name == BROWSE_MSG_BODY_NAME)):
            print_dbg('browse req version')
            # the msg activate_session_response (occurring before browse_request in the fuzzing chain)
            #   has the same security params of create_res but no auth token id
            node.names[BROWSE_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[BROWSE_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[BROWSE_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[BROWSE_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            node.names[BROWSE_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD]._default_value = auth_token_read_req
        elif ((node.stack[1]._name == WRITE_MSG_BODY_NAME)):
            print_dbg('write req version')
            # the msg browse_response (occurring before write_request in the fuzzing chain)
            #   has the same security params of create_res but no auth token id
            node.names[WRITE_MSG_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[WRITE_MSG_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[WRITE_MSG_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[WRITE_MSG_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            node.names[WRITE_MSG_AUTH_TOKEN_ID_GUID_NODE_FIELD]._default_value = auth_token_read_req
        elif ((node.stack[1]._name == WRITE_MSG_FAKE_BODY_NAME)):
            print_dbg('write FAKE req version')
            # the msg browse_response (occurring before write_request in the fuzzing chain)
            #   has the same security params of create_res but no auth token id
            node.names[WRITE_MSG_FAKE_SEC_CH_ID_NODE_FIELD]._default_value = sec_channel_id
            node.names[WRITE_MSG_FAKE_TOKEN_ID_NODE_FIELD]._default_value = token_id
            node.names[WRITE_MSG_FAKE_SEQ_NUM_NODE_FIELD]._default_value = seq_num +1
            node.names[WRITE_MSG_FAKE_SEQ_REQ_ID_NODE_FIELD]._default_value = req_id +1
            node.names[WRITE_MSG_FAKE_AUTH_TOKEN_ID_GUID_NODE_FIELD]._default_value = auth_token_read_req
            # SEARCHING Variables at first lvl
            #   Browse Res from Browse Object => size ArrayOfBrowseResult=1, analyzing ArrayOfRefDescr
            #       size ArrayOfRefDescr 40B after reqId
            startRefDescr = 68
            arrayOfRefDescrSize = struct.unpack('i', res[64:startRefDescr])[0]
            print_dbg('arraySize = ' + str(arrayOfRefDescrSize))
            accu = 0
            varNameBool = False
            for x in range(arrayOfRefDescrSize):
                    # The referenceType encodingMask
                    #   0 - 2B
                    #   1 - 4B
                    #   2 - numeric arbitrary length 7B
                    #   next encoding mask: if 00-skip2B, if 01-skip4B
                if (x==0):
                    refTypeEncMask = accu +startRefDescr
                    #expandedNodeIdMask = accu + startRefDescr + 3
                else:
                    refTypeEncMask = accu +startRefDescr -67 # -67 because I must del the Bytes before 'MSG'
                    #expandedNodeIdMask =  accu + startRefDescr + 3 - 67 
                if (res[refTypeEncMask] == 0):
                    expandedNodeIdMask = refTypeEncMask + 3
                elif (res[refTypeEncMask] == 1):
                    expandedNodeIdMask = refTypeEncMask + 4
                elif (res[refTypeEncMask] == 2):
                    expandedNodeIdMask = refTypeEncMask + 8
                    # expandedNode encoding mask: if 00-skip2B, if 01-skip4B, if 02-skip6B
                if (res[expandedNodeIdMask] == 0): # two B encoded numeric
                    startBrowseName = expandedNodeIdMask + 1
                elif (res[expandedNodeIdMask] == 1): # four B encoded numeric
                    startBrowseName = expandedNodeIdMask + 3
                elif (res[expandedNodeIdMask] == 2): # numeric of arbitrary lenght
                    startBrowseName = expandedNodeIdMask + 6
                elif (res[expandedNodeIdMask] == 3): # 1B mask + 2B namespace - 4B dim + string
                    varNameBool = True
                    startDimVarName = expandedNodeIdMask + 3
                    endDimVarName = startDimVarName + 4
                    dimVarName = struct.unpack('i', res[startDimVarName:endDimVarName])[0]
                    '''startVarName = endDimVarName
                    endVarName = startVarName + dimVarName
                    varName = res[startVarName:endVarName].decode("utf-8")'''
                    endVarName = endDimVarName + dimVarName
                    varName = res[endDimVarName:endVarName].decode("utf-8")
                    print_dbg('var name: '+varName)# ok -> save these vars for WRITE_RES
                    servVars.append(varName)
                    startBrowseName = endVarName
                else:
                    fuzz_data_logger.log_error('ERR - expandedNodeIdMask1 not implemented')
                    # QualifiedName = 2B(ID) + 4B (size) + QualifiedNameString
                if (varNameBool):
                    startSizeQualifiedName = startBrowseName + 2
                else:
                    startSizeQualifiedName = startBrowseName + 3
                endSizeQualifiedName = startSizeQualifiedName + 4
                sizeQualifiedName = struct.unpack('i', res[startSizeQualifiedName:endSizeQualifiedName])[0]
                '''startQualifiedName = endSizeQualifiedName
                endQualifiedName = startQualifiedName + sizeQualifiedName
                qualifiedName = res[startQualifiedName:endQualifiedName].decode("utf-8")'''
                endQualifiedName = endSizeQualifiedName + sizeQualifiedName
                qualifiedName = res[endSizeQualifiedName:endQualifiedName].decode("utf-8")
                print_dbg('qual name ' + str(x) + ' ' + qualifiedName)

                # TODO FIX:
                # opc: all good with locTxtEncMask = endQualifiedName
                # python: good but there is expandedNodeIdMask2 not implemented

                locTxtEncMask = endQualifiedName #+ 1
                print_dbg('locTxtEncMask '+str(res[locTxtEncMask]))
                if (res[locTxtEncMask] == 10 or res[locTxtEncMask] == 2): # 02 -> not locale, has txt
                    startSizeLocText = locTxtEncMask + 1
                    #print_dbg('should be here ' + str(res[startSizeLocText-1]))
                elif (res[locTxtEncMask] == 3): # has locale and has text
                    # check if locale is a string
                    startDimLocale = endQualifiedName+1
                    endDimLocale = startDimLocale + 4
                    dimLocale = struct.unpack('i', res[startDimLocale:endDimLocale])[0]
                    if(dimLocale!=0):
                        startLocale = endQualifiedName + 5
                        endLocale = startLocale + dimLocale
                        locale = res[startLocale:endLocale].decode("utf-8")
                        startSizeLocText = endLocale
                    else:
                        startSizeLocText = endQualifiedName + 5
                else:
                    fuzz_data_logger.log_error('ERR - locale txt enc mask not implemented')

                endSizeLocText = startSizeLocText + 4
                sizeLocText = struct.unpack('i', res[startSizeLocText:endSizeLocText])[0]
                #print_dbg('size loc txt '+str(sizeLocText))
                '''startLocText = endSizeLocText
                endLocText = startLocText + sizeLocText
                locTxt = res[startLocText:endLocText].decode("utf-8")'''
                endLocText = endSizeLocText + sizeLocText
                locTxt = res[endSizeLocText:endLocText].decode("utf-8")
                print_dbg('loc txt ' + locTxt)

                nodeClassType = struct.unpack('i', res[endLocText:endLocText+4])[0]
                print_dbg('nodeclass id ' + str(nodeClassType))
                expandedNodeIdMask2 = endLocText + 4 # 4B NodeClass
                if (res[expandedNodeIdMask2] == 0): # two B encoded numeric
                    itemTail = expandedNodeIdMask2 + 1
                elif (res[expandedNodeIdMask2] == 1): # four B encoded numeric
                    itemTail = expandedNodeIdMask2 + 3
                else:
                    fuzz_data_logger.log_error('ERR - expandedNodeIdMask2 not implemented')
                # set accu for next for loop
                accu=itemTail
        else:
            fuzz_data_logger.log_error('ERR - callback not implementated for msg')
            print('ERR on msg body %s', node.stack[1]._name)
    except struct.error:
        fuzz_data_logger.log_error('ERR - could not unpack response') 
create_callback.__doc__ = "Callback to set the Auth token ID from Create Session Msg. Used for ActivateReq-ReadReq-BrowseReq"


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
def main():
    # ARGS parsing----------
    parser = ArgumentParser(description='Fuzzing OPC UA server.')
    parser.add_argument('addr', metavar='ip-addr', type=str, help='The server host IP address')
    parser.add_argument('port', metavar='port', type=int, help='The server host port', default=4840, nargs='?')
    parser.add_argument('-m', '--info', action="store_true", help='Test the information model instead of implementation')
    args = parser.parse_args()

    # IP ADDR validiation----------
    try:
        HOST_ADDR = ip_address(args.addr)
        OPC_UA_PORT = args.port
        print_dbg('%s is starting fuzzing the OPC UA server at %s IPv%s address on port %s' % (parser.prog, HOST_ADDR, HOST_ADDR.version, OPC_UA_PORT))
    except ValueError:
        print('address/netmask is invalid: %s' % args.addr)
        print('Usage : %s ipAddress' % parser.prog)
        return
    except:
        print('Usage : %s ipAddress' % args.addr)
        return


    
    # Basic MSGs building------------------------------
    if(args.info):      # TEST INFORMATION MODEL
        hello_msg_nf()
        open_msg_nf()
        close_msg_nf()
        # get_endpoints_msg_nf()
        create_session_msg_nf()
        activate_session_msg_nf()
        # read_objects_msg_nf()
        browse_objects_msg_nf()

    else:               # TEST IMPLEMENTATION
        hello_msg()
        open_msg()    
        close_msg()    
        get_endpoints_msg()    
        create_session_msg()
        activate_session_msg()
        read_objects_msg()
        browse_objects_msg()

    session = build_session(args.info, HOST_ADDR, OPC_UA_PORT)
    # session graph PNG creation
    with open(PNG_GRAPH_OUT_FILE, 'wb') as file:
        file.write(session.render_graph_graphviz().create_png())

    try:
        if (args.info):     # TEST INFORMATION MODEL
            print_dbg('fuzzing information model')
            session.fuzz() # first run finds variables, second run fuzz the write_msg
            print_dbg('server vars ' + str(servVars))
            for var in servVars:
                # A 'Write' block already exists, I delete it before build_session can add it with a new variableName
                try:
                    del blocks.REQUESTS[WRITE_MSG_NAME]
                except:
                    pass
                session = build_session(args.info,  HOST_ADDR, OPC_UA_PORT, var)
                session.fuzz()
        else:               # TEST IMPLEMENTATION
            print_dbg('fuzzing implementation')
            session.fuzz()
    except KeyboardInterrupt:
        pass

def build_session(infoModelFlag, host, port, variableName=None) -> Session:
    if (variableName != None):
            write_variable_msg(variableName)
    else:
        write_variable_msg_nf()

    # SESSION building------------------------------
    session = None
    session = Session(
        target=Target(
            connection=TCPSocketConnection(str(host), port)),
        #post_test_case_callbacks=[generic_callback], #executed at the end of the chain
        sleep_time=0, #sleep at the end of the graph
        receive_data_after_fuzz=True, #receive last response if there is
        keep_web_open=False, #close web UI at the end of the graph
        #web_port=None,
        index_start=1, index_end=1,     #single run
        #index_start=2270*140*280,      #start at certain point
        #index_start=0, index_end=3,     #single run
        #index_end=293
        )

    # GRAPH building------------------------------
    session.connect(s_get(HELLO_MSG_NAME))
    session.connect(s_get(HELLO_MSG_NAME), s_get(OPEN_MSG_NAME), callback=hello_callback)# ACK callback only for debug

    #session.connect(s_get(OPEN_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)
    #session.connect(s_get(OPEN_MSG_NAME), s_get(GET_ENDPOINTS_MSG_NAME), callback=open_callback)

    session.connect(s_get(OPEN_MSG_NAME), s_get(CREATE_SESSION_MSG_NAME), callback=open_callback)
    session.connect(s_get(CREATE_SESSION_MSG_NAME), s_get(ACTIVATE_SESSION_MSG_NAME), callback=create_callback)
    
    #session.connect(s_get(ACTIVATE_SESSION_MSG_NAME), s_get(READ_MSG_NAME), callback=create_callback)

    if (infoModelFlag):                 # TEST INFORMATION MODEL
        session.connect(s_get(ACTIVATE_SESSION_MSG_NAME), s_get(BROWSE_MSG_NAME), callback=create_callback)
        #session.connect(s_get(BROWSE_MSG_NAME), s_get(CLOSE_MSG_NAME))
        if (variableName == None):
            session.connect(s_get(BROWSE_MSG_NAME), s_get(WRITE_MSG_FAKE_NAME), callback=create_callback)
        else:
            session.connect(s_get(BROWSE_MSG_NAME), s_get(WRITE_MSG_NAME), callback=create_callback)
    else:
        session.connect(s_get(ACTIVATE_SESSION_MSG_NAME), s_get(CLOSE_MSG_NAME), callback=open_callback)

    return session

if __name__ == "__main__":
    main()
