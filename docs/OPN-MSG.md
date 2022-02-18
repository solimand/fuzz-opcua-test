# OpenSecureChannel Messages
- This Service is used to open or renew a SecureChannel that can be used to ensure Confidentiality and Integrity for Message exchange during a Session. 
- Each SecureChannel has a globally-unique identifier and is valid for a specific combination of Client and Server application instances. 

## Wireshark Request example
    OpcUa Binary Protocol
    Message Type: OPN
    Chunk Type: F
    Message Size: 132
    SecureChannelId: 0
    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#None
    SenderCertificate: <MISSING>[OpcUa Null ByteString]
    ReceiverCertificateThumbprint: <MISSING>[OpcUa Null ByteString]
    SequenceNumber: 1
    RequestId: 1
    Message : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: OpenSecureChannelRequest (446)
        OpenSecureChannelRequest
            RequestHeader: RequestHeader
                AuthenticationToken: NodeId
                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                    Identifier Numeric: 0
                Timestamp: Feb 16, 2022 12:07:05.362753000 W. Europe Standard Time
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
                TimeoutHint: 1000
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
            ClientProtocolVersion: 0
            SecurityTokenRequestType: Issue (0x00000000)
            MessageSecurityMode: None (0x00000001)
            ClientNonce: <MISSING>[OpcUa Empty ByteString]
            RequestedLifetime: 3600000

## Request parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|   requestHeader | RequestHeader | Common request parameters. The authenticationToken is always null. The type RequestHeader is defined in 7.28. |
|    clientCertificate | ApplicationInstanceCertificate | A Certificate that identifies the Client. The OpenSecureChannel request shall be signed with the private key for this Certificate. The ApplicationInstanceCertificate type is defined in 7.2. If the securityPolicyUri is None, the Server shall ignore the ApplicationInstanceCertificate. |
|    requestType | Enum SecurityToken RequestType | The type of SecurityToken request: An enumeration that shall be one of the following:    ISSUE_0	creates a new SecurityToken for a new SecureChannel.    RENEW_1	creates a new SecurityToken for an existing SecureChannel.  |
|    secureChannelId | BaseDataType | The identifier for the SecureChannel that the new token should belong to. This parameter shall be null when creating a new SecureChannel. The concrete security protocol definition in OPC 10000-6 chooses the concrete DataType. |
|    securityMode | Enum MessageSecurityMode | The type of security to apply to the messages.  The type MessageSecurityMode type is defined in 7.15. A SecureChannel may have to be created even if the securityMode is NONE. The exact behaviour depends on the mapping used and is described in the OPC 10000-6. |
|    securityPolicyUri | String | The URI for SecurityPolicy to use when securing messages sent over the SecureChannel. The set of known URIs and the SecurityPolicies associated with them are defined in OPC 10000-7. |
|    clientNonce | ByteString | A random number that shall not be used in any other request. A new clientNonce shall be generated for each time a SecureChannel is renewed. This parameter shall have a length equal to the SecureChannelNonceLength defined for the SecurityPolicy in OPC 10000-7. The SecurityPolicy is identified by the securityPolicyUri. |
|    requestedLifetime | Duration | The requested lifetime, in milliseconds, for the new SecurityToken. It specifies when the Client expects to renew the SecureChannel by calling the OpenSecureChannel Service again. If a SecureChannel is not renewed, then all Messages sent using the current SecurityTokens shall be rejected by the receiver. Several  cryptanalytic attacks become easier as more material encrypted with a  specific key is available. By limiting the amount of data processed  using a particular key, those attacks are made more difficult. Therefore  the volume of data exchanged between Client and Server must be limited by establishing a new SecurityToken after the lifetime. The  setting of the requested lifetime depends on the expected number of  exchanged messages and their size in the lifetime. A higher volume of  data requires shorter lifetime. |


## Wireshark Response
    OpcUa Binary Protocol
    Message Type: OPN
    Chunk Type: F
    Message Size: 135
    SecureChannelId: 3
    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#None
    SenderCertificate: <MISSING>[OpcUa Null ByteString]
    ReceiverCertificateThumbprint: <MISSING>[OpcUa Null ByteString]
    SequenceNumber: 1
    RequestId: 1
    Message : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: OpenSecureChannelResponse (449)
        OpenSecureChannelResponse
            ResponseHeader: ResponseHeader
                Timestamp: Feb 16, 2022 13:07:05.384677000 W. Europe Standard Time
                RequestHandle: 1
                ServiceResult: 0x00000000 [Good]
                ServiceDiagnostics: DiagnosticInfo
                    EncodingMask: 0x00
                        .... ...0 = has symbolic id: False
                        .... ..0. = has namespace: False
                        .... .0.. = has localizedtext: False
                        .... 0... = has locale: False
                        ...0 .... = has additional info: False
                        ..0. .... = has inner statuscode: False
                        .0.. .... = has inner diagnostic info: False
                StringTable: Array of String
                    ArraySize: -1
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
            ServerProtocolVersion: 0
            SecurityToken: ChannelSecurityToken
                ChannelId: 3
                TokenId: 3
                CreatedAt: Feb 16, 2022 13:07:05.384677000 W. Europe Standard Time
                RevisedLifetime: 600000
            ServerNonce: <MISSING>[OpcUa Null ByteString]

## Response parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|  responseHeader | ResponseHeader | Common response parameters (see 7.29 for ResponseHeader type definition). |
|    securityToken | ChannelSecurityToken | Describes the new SecurityToken issued by the Server. This structure is defined in-line with the following indented items. |
|       channelId | BaseDataType | A unique identifier for the SecureChannel. This is the identifier that shall be supplied whenever the SecureChannel is renewed. The concrete security protocol definition in OPC 10000-6 chooses the concrete DataType. |
|       tokenId | ByteString | A unique identifier for a single SecurityToken within the channel. This is the identifier that shall be passed with each Message secured with the SecurityToken. |
|       createdAt | UtcTime | The time when the SecurityToken was created. |
|       revisedLifetime | Duration | The lifetime of the SecurityToken in milliseconds. The UTC expiration time for the token may be calculated by adding the lifetime to the createdAt time. |
|    serverNonce | ByteString | A random number that shall not be used in any other request. A new serverNonce shall be generated for each time a SecureChannel is renewed. This parameter shall have a length equal to the SecureChannelNonceLength defined for the SecurityPolicy in OPC 10000-7. The SecurityPolicy is identified by the securityPolicyUri. |


## Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Bad_SecurityChecksFailed | See Table 177 for the description of this result code. |
| Bad_CertificateTimeInvalid | See Table 177 for the description of this result code. |
| Bad_CertificateIssuerTimeInvalid | See Table 177 for the description of this result code. |
| Bad_CertificateHostNameInvalid | See Table 177 for the description of this result code. |
| Bad_CertificateUriInvalid | See Table 177 for the description of this result code. |
| Bad_CertificateUseNotAllowed | See Table 177 for the description of this result code. |
| Bad_CertificateIssuerUseNotAllowed | See Table 177 for the description of this result code. |
| Bad_CertificateUntrusted | See Table 177 for the description of this result code. |
| Bad_CertificateRevocationUnknown | See Table 177 for the description of this result code. |
| Bad_CertificateIssuerRevocationUnknown | See Table 177 for the description of this result code. |
| Bad_CertificateRevoked | See Table 177 for the description of this result code. |
| Bad_CertificateIssuerRevoked | See Table 177 for the description of this result code. |
| Bad_RequestTypeInvalid | The security token request type is not valid. |
| Bad_SecurityModeRejected | The security mode does not meet the requirements set by the Server. |
| Bad_SecurityPolicyRejected | The security policy does not meet the requirements set by the Server. |
| Bad_SecureChannelIdInvalid | See Table 177 for the description of this result code. |
| Bad_NonceInvalid | See Table 177 for the description of this result code. A Server shall check the minimum length of the Client nonce and return this status if the length is below 32 bytes. A check for duplicated nonce can only be done in OpenSecureChannel calls with the request type RENEW_1. |