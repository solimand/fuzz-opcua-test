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

# CLOSE-MSG-Req
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

# GET-ENDPOINTS-MSG-Req

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
