# Message Formats from Wireshark tcpdump
## OPEN-SECURE-CHANNEL-OPN-Req
    Message Type: OPN
    Chunk Type: F
    Message Size: 133
    SecureChannelId: 0
    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#None
    SenderCertificate: <MISSING>[OpcUa Null ByteString]
    ReceiverCertificateThumbprint: <MISSING>[OpcUa Null ByteString]
    SequenceNumber: 51
    RequestId: 1
    Message : Encodeable Object                                                 --->Not a field
        TypeId : ExpandedNodeId                                                 --->Not a field
            NodeId EncodingMask: Four byte encoded Numeric (0x01)               --->01
            NodeId Namespace Index: 0                                           --->00
            NodeId Identifier Numeric: OpenSecureChannelRequest (446)           --->01BE--->BE01
        OpenSecureChannelRequest                                                --->Not a field
            RequestHeader: RequestHeader                                        --->Not a field
                AuthenticationToken: NodeId                                     --->Not a field
                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)    --->00
                    Identifier Numeric: 0                                       --->00
                Timestamp: Oct 22, 2021 15:23:20.617548700 CEST
                RequestHandle: 0
                Return Diagnostics: 0x00000000
                    .... .... .... ...0 = ServiceLevel / SymbolicId: False
                    .... .... .... ..0. = ServiceLevel / LocalizedText: False
                    .... .... .... .0.. = ServiceLevel / AdditionalInfo: False
                    .... .... .... 0... = ServiceLevel / Inner StatusCode: False
                    .... .... ...0 .... = ServiceLevel / Inner Diagnostics: False
                    .... .... ..0. .... = OperationLevel / SymbolicId: False
                    .... .... .0.. .... = OperationLevel / LocalizedText: False
                    .... .... 0... .... = OperationLevel / AdditionalInfo: False
                    .... ...0 .... .... = OperationLevel / Inner StatusCode: False
                    .... ..0. .... .... = OperationLevel / Inner Diagnostics: False
                AuditEntryId: [OpcUa Null String]
                TimeoutHint: 0
                AdditionalHeader: ExtensionObject                               --->Not a field
                    TypeId: ExpandedNodeId                                      --->Not a field
                        EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric--->00
                            .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                            .0.. .... = has server index: False
                            0... .... = has namespace uri: False
                        Identifier Numeric: 0                                   --->00
                    EncodingMask: 0x00                                          --->00
                        .... ...0 = has binary body: False
                        .... ..0. = has xml body: False
            ClientProtocolVersion: 0                                            --->dword
            SecurityTokenRequestType: Issue (0x00000000)                        --->dword
            MessageSecurityMode: None (0x00000001)
            ClientNonce: 00                                                     --->??
            RequestedLifetime: 300000                                           --->??

## CLOSE-MSG-Req
    Message Type: CLO
    Chunk Type: F
    Message Size: 57
    SecureChannelId: 3
    Security Token Id: 4
    Security Sequence Number: 53
    Security RequestId: 3
    Message : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: CloseSecureChannelRequest (452)
        CloseSecureChannelRequest
            RequestHeader: RequestHeader
                AuthenticationToken: NodeId
                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                    Identifier Numeric: 0
                Timestamp: Oct 22, 2021 15:23:20.618928300 CEST
                RequestHandle: 0
                Return Diagnostics: 0x00000000
                    .... .... .... ...0 = ServiceLevel / SymbolicId: False
                    .... .... .... ..0. = ServiceLevel / LocalizedText: False
                    .... .... .... .0.. = ServiceLevel / AdditionalInfo: False
                    .... .... .... 0... = ServiceLevel / Inner StatusCode: False
                    .... .... ...0 .... = ServiceLevel / Inner Diagnostics: False
                    .... .... ..0. .... = OperationLevel / SymbolicId: False
                    .... .... .0.. .... = OperationLevel / LocalizedText: False
                    .... .... 0... .... = OperationLevel / AdditionalInfo: False
                    .... ...0 .... .... = OperationLevel / Inner StatusCode: False
                    .... ..0. .... .... = OperationLevel / Inner Diagnostics: False
                AuditEntryId: [OpcUa Null String]
                TimeoutHint: 0
                AdditionalHeader: ExtensionObject
                    TypeId: ExpandedNodeId
                        EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                            .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                            .0.. .... = has server index: False
                            0... .... = has namespace uri: False
                        Identifier Numeric: 0
                    EncodingMask: 0x00
                        .... ...0 = has binary body: False
                        .... ..0. = has xml body: False

## GET-ENDPOINTS-MSG-Req
    Message Type: MSG
    Chunk Type: F
    Message Size: 100
    SecureChannelId: 3
    Security Token Id: 4
    Security Sequence Number: 52
    Security RequestId: 2
    OpcUa Service : Encodeable Object                                           --->Not field
        TypeId : ExpandedNodeId                                                 --->Not field
            NodeId EncodingMask: Four byte encoded Numeric (0x01)               --->01
            NodeId Namespace Index: 0                                           --->00
            NodeId Identifier Numeric: GetEndpointsRequest (428)                --->??
        GetEndpointsRequest                                                     --->Not field
            RequestHeader: RequestHeader                                        --->Not field
                AuthenticationToken: NodeId                                     --->Not field
                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)    --->00
                    Identifier Numeric: 0                                       --->00
                Timestamp: Oct 22, 2021 15:23:20.618189700 CEST
                RequestHandle: 1
                Return Diagnostics: 0x00000000
                    .... .... .... ...0 = ServiceLevel / SymbolicId: False
                    .... .... .... ..0. = ServiceLevel / LocalizedText: False
                    .... .... .... .0.. = ServiceLevel / AdditionalInfo: False
                    .... .... .... 0... = ServiceLevel / Inner StatusCode: False
                    .... .... ...0 .... = ServiceLevel / Inner Diagnostics: False
                    .... .... ..0. .... = OperationLevel / SymbolicId: False
                    .... .... .0.. .... = OperationLevel / LocalizedText: False
                    .... .... 0... .... = OperationLevel / AdditionalInfo: False
                    .... ...0 .... .... = OperationLevel / Inner StatusCode: False
                    .... ..0. .... .... = OperationLevel / Inner Diagnostics: False
                AuditEntryId: [OpcUa Null String]
                TimeoutHint: 10000
                AdditionalHeader: ExtensionObject
                    TypeId: ExpandedNodeId
                        EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                            .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                            .0.. .... = has server index: False
                            0... .... = has namespace uri: False
                        Identifier Numeric: 0
                    EncodingMask: 0x00
                        .... ...0 = has binary body: False
                        .... ..0. = has xml body: False
            EndpointUrl: opc.tcp://150.140.188.188:4840/
            LocaleIds: Array of String
                ArraySize: 0
            ProfileUris: Array of String
                ArraySize: 0

## Activate-Session-Msg-Req
    Message Type: MSG
    Chunk Type: F
    Message Size: 146
    SecureChannelId: 47
    Security Token Id: 47
    Security Sequence Number: 53
    Security RequestId: 3
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: ActivateSessionRequest (467)
        ActivateSessionRequest
            RequestHeader: RequestHeader
                AuthenticationToken: NodeId
                    .... 0100 = EncodingMask: GUID (0x4)
                    Namespace Index: 1
                    Identifier Guid: c7bd3734-2a3a-374a-75a7-0a00a8da6d26
                Timestamp: Nov  9, 2021 10:41:58.370239500 CET
                RequestHandle: 1000002
                Return Diagnostics: 0x00000000
                AuditEntryId: [OpcUa Null String]
                TimeoutHint: 10000
                AdditionalHeader: ExtensionObject
                    TypeId: ExpandedNodeId
                        EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                            .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                            .0.. .... = has server index: False
                            0... .... = has namespace uri: False
                        Identifier Numeric: 0
                    EncodingMask: 0x00
                        .... ...0 = has binary body: False
                        .... ..0. = has xml body: False
            ClientSignature: SignatureData
                Algorithm: [OpcUa Null String]
                Signature: <MISSING>[OpcUa Null ByteString]
            ClientSoftwareCertificates: Array of SignedSoftwareCertificate
                ArraySize: 0
            LocaleIds: Array of String
                ArraySize: 1
                [0]: LocaleIds: en-US
            UserIdentityToken: ExtensionObject
                TypeId: ExpandedNodeId
                    EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric
                        .... 0001 = EncodingMask: Four byte encoded Numeric (0x1)
                        .0.. .... = has server index: False
                        0... .... = has namespace uri: False
                    Namespace Index: 0
                    Identifier Numeric: 321
                EncodingMask: 0x01, has binary body
                    .... ...1 = has binary body: True
                    .... ..0. = has xml body: False
                AnonymousIdentityToken: AnonymousIdentityToken
                    PolicyId: open62541-anonymous-policy
            UserTokenSignature: SignatureData
                Algorithm: [OpcUa Null String]
                Signature: <MISSING>[OpcUa Null ByteString]


# Create Session Req/Res
## Service Parameters
| Name |       Type       |    Description    | 
|:------:|:------------------:|:-----------------:|
| clientNonce      | ByteString           |   A random number that should never be used in any other request. This number shall have a minimum length of **32 bytes**. Profiles may increase the required length. The Server shall use this value to prove possession of its Application Instance Certificate in the response. |

## Create Session Res Msg
Has two identifier IDs:
- Session ID = printed by server in output 
- Auth token ID = used inside the next Activate Session Request

# Read Request MSG
## Browse the AddressSpace default nodes (all servers have)
The default NodeIDs of every AddressSpace
- ns=0, i =84 --> Root Node
- ns=0, i =85 --> Objects
- ns=0, i =86 --> Types 
- ns=0, i =87 --> Views

## Read Val ID in read Req MSG
The field ReadValID has following sub-fields:
- NodeID (xB) identifies the kind of NodeID (two bytes integer 0000, four bytes integer 0001, string 0011 ...) and the value of NodeID (2B, 4B, len(str))
- AttributeID (4B)
- Index Range (4B)
- DataEncoding (6B)

## Default AttributeIDs Constants
| Attribute Name |    Identifier    |
|-:|:-:|
|NodeId|1|
|NodeClass|2|
|Browse Name|3|
|Display Name|4|
|Description|5|
|Write Mask|6|
|User Write Mask|7|
|Role Permission|18|
|User Role Permission|19|
|Access Restriction |26(1a)|
|Event Notifier|12(0c)|
| | |
| | |
|IsAbstract|8|
|Symmetric|9|
|InverseName|10|
|ContainsNoLoops|11|
|Value|13|
|DataType|14|
|ValueRank|15|
|ArrayDimensions|16|
|AccessLevel|17|
|UserAccessLevel|18|
|MinimumSamplingInterval|19|
|Historizing|20|
|Executable|21|
|UserExecutable|22|
|DataTypeDefinition|23|
|RolePermissions|24|
|UserRolePermissions|25|
|AccessLevelEx|27


# C/S Communication Protocol
## Client initiated comm protocol
OPC client initiatied comm protocol

```
Client                      Server
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
```

# DEfault Errors & Error Codes (TODO)
- BadDecodingError -> occurs when (...); error code (...)
- BadInternalError -> occurs when (...); error code (...)
- BadSecureChannelIdInvalid -> occurs when (...); error code (...)