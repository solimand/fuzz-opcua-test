# CloseSecureChannel Messages
- This Service is used to terminate a SecureChannel.

## Wireshark Request example
    OpcUa Binary Protocol
    Message Type: CLO
    Chunk Type: F
    Message Size: 57
    SecureChannelId: 34
    Security Token Id: 34
    Security Sequence Number: 2
    Security RequestId: 2
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
                Timestamp: Nov  9, 2021 10:39:34.644210000 W. Europe Standard Time
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

## Wireshark Response
...

## Request/Response parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
| **Request** |  |  |
|    requestHeader | RequestHeader | Common request parameters. The authenticationToken is always null. The type RequestHeader is defined in 7.28. |
|    secureChannelId | BaseDataType | The identifier for the SecureChannel to close. The concrete security protocol definition in OPC 10000-6 chooses the concrete DataType. |
| **Response** |  |  |
|    responseHeader | ResponseHeader | Common response parameters (see 7.29 for ResponseHeader definition). |
