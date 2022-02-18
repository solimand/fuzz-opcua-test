# ActivateSession Messages
- This Service is used by the Client to specify the identity of the user associated with the Session. This Service request shall be issued by the Client before it issues any Service request other than CloseSession after CreateSession. Failure to do so shall cause the Server to close the Session.
- Whenever the Client calls this Service the Client shall prove that it is the same application that called the CreateSession Service. The Client does this by creating a signature with the private key associated with the clientCertificate specified in the CreateSession request. This signature is created by appending the last serverNonce provided by the Server to the serverCertificate and calculating the signature of the resulting sequence of bytes. Once used, a serverNonce cannot be used again. For that reason, the Server returns a new serverNonce each time the ActivateSession Service is called.
- When the ActivateSession Service is called for the first time then the Server shall reject the request if the SecureChannel is not same as the one associated with the CreateSession request. In addition, the Server shall verify that the Client supplied a UserIdentityToken that is identical to the token currently associated with the Session.
- The ActivateSession Service is used to associate a user identity with a Session. Clients can change the identity of a user associated with a Session by calling the ActivateSession Service. The Server validates the signatures provided with the request and then validates the new user identity. If no errors occur the Server replaces the user identity for the Session. Changing the user identity for a Session may cause discontinuities in active Subscriptions because the Server may have to tear down connections to an underlying system and re-establish them using the new credentials.
- When a Client supplies a list of locale ids in the request, each locale id is required to contain the language component. It may optionally contain the <country/region> component. When the Server returns a LocalizedText in the context of the Session, it also may return both the language and the country/region or just the language as its default locale id.

## Wireshark Request example
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 146
    SecureChannelId: 12
    Security Token Id: 32
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
                    Identifier Guid: eae0b5a6-7f33-45be-6a36-e35e9159b59b
                Timestamp: Nov 15, 2021 14:09:49.881486800 W. Europe Standard Time
                RequestHandle: 1000002
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


## Request parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|    requestHeader | RequestHeader | Common request parameters. The type RequestHeader is defined in 7.28. |
|    clientSignature | SignatureData | This is a signature generated with the private key associated with the clientCertificate. This parameter is calculated by appending the serverNonce to the serverCertificate and signing the resulting sequence of bytes. If the serverCertificate contains a chain, the signature calculation shall be done only with the leaf Certificate. For backward compatibility a Server shall check the signature with the full chain if the check with the leaf Certificate fails. The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified in the SecurityPolicy for the Endpoint. The SignatureData type is defined in 7.32. |
|    clientSoftwareCertificates [] | SignedSoftwareCertificate | Reserved for future use. The SignedSoftwareCertificate type is defined in 7.33. |
|    localeIds [] | LocaleId | List of locale ids in priority order for localized strings. The first LocaleId in the list has the highest priority. If the Server returns a localized string to the Client, the Server  shall return the translation with the highest priority that it can. If  it does not have a translation for any of the locales identified in this  list, then it shall return the string value that it has and include the  locale id with the string. See OPC 10000-3 for more detail on locale ids. If the Client fails to specify at least one locale id, the Server shall use any that it has.  This parameter only needs to be specified during the first call to ActivateSession during a single application Session. If it is not specified the Server shall keep using the current localeIds for the Session. |
|    userIdentityToken | Extensible Parameter UserIdentityToken | The credentials of the user associated with the Client application. The Server uses these credentials to determine whether the Client should be allowed to activate a Session and what resources the Client has access to during this Session. The UserIdentityToken is an extensible parameter type defined in 7.36. The EndpointDescription specifies what UserIdentityTokens the Server shall accept. Null or empty user token shall always be interpreted as anonymous. |
|    userTokenSignature | SignatureData | If the Client specified a user identity token that  supports digital signatures, then it shall create a signature and pass  it as this parameter. Otherwise the parameter is null. The SignatureAlgorithm depends on the identity token type. The SignatureData type is defined in 7.32. |

## Wireshark Response
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 96
    SecureChannelId: 12
    Security Token Id: 32
    Security Sequence Number: 3
    Security RequestId: 3
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: ActivateSessionResponse (470)
        ActivateSessionResponse
            ResponseHeader: ResponseHeader
                Timestamp: Nov 15, 2021 14:09:49.881148000 W. Europe Standard Time
                RequestHandle: 1000002
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
            ServerNonce: 9cb6315d45516bd7829338639efae771ca37b3c744ffefc512a22f725435362c
            Results: Array of StatusCode
                ArraySize: -1
            DiagnosticInfos: Array of DiagnosticInfo
                ArraySize: -1

## Response parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|   responseHeader | ResponseHeader | Common response parameters (see 7.29 for ResponseHeader definition). |
|    serverNonce | ByteString | A random number that should never be used in any other request. This number shall have a minimum length of 32 bytes. The Client shall use this value to prove possession of its Application Instance Certificate in the next call to ActivateSession request. |
|    results [] | StatusCode | List of validation results for the SoftwareCertificates (see 7.34 for StatusCode definition). |
|    diagnosticInfos [] | DiagnosticInfo | List of diagnostic information associated with SoftwareCertificate validation errors (see 7.8 for DiagnosticInfo  definition). This list is empty if diagnostics information was not  requested in the request header or if no diagnostic information was  encountered in processing of the request. |

## Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Bad_IdentityTokenInvalid | See Table 177 for the description of this result code. |
| Bad_IdentityTokenRejected | See Table 177 for the description of this result code. |
| Bad_UserAccessDenied | See Table 177 for the description of this result code. |
| Bad_ApplicationSignatureInvalid | The signature provided by the Client application is missing or invalid. |
| Bad_UserSignatureInvalid | The user token signature is missing or invalid. |
| Bad_NoValidCertificates | The Client did not provide at least one Software Certificate that is valid and meets the profile requirements for the Server. |
| Bad_IdentityChangeNotSupported | The Server does not support changing the user identity assigned to the session. |