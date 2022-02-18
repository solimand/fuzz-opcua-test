# CreateSession Messages
- This Service is used by an OPC UA Client to create a Session and the Server returns two values which uniquely identify the Session. The first value is the **sessionId** which is used to identify the Session in the audit logs and in the Server’s AddressSpace. The second is the **authenticationToken** which is used to associate an incoming request with a Session.
- Before calling this Service, the Client shall create a SecureChannel with the OpenSecureChannel Service to ensure the Integrity of all Messages exchanged during a Session. This SecureChannel has a unique identifier which the Server shall associate with the authenticationToken. The Server may accept requests with the authenticationToken only if they are associated with the same SecureChannel that was used to create the Session. The Client may associate a new SecureChannel with the Session by calling the ActivateSession method.
- A Server application should limit the number of Sessions. To protect against misbehaving Clients and denial of service attacks, the Server shall close the oldest Session that is not activated before reaching the maximum number of supported Sessions. 
- When a Session is created, the Server adds an entry for the Client in its **SessionDiagnosticsArray Variable**. Sessions are terminated by the Server automatically if the Client fails to issue a Service request on the Session within the timeout period negotiated by the Server in the CreateSession Service response. This protects the Server against Client failures and against situations where a failed underlying connection cannot be re-established. Clients shall be prepared to submit requests in a timely manner to prevent the Session from closing automatically. Clients may explicitly terminate Sessions using the CloseSession Service. 
- When a Session is terminated, all outstanding requests on the Session are aborted and Bad_SessionClosed StatusCodes are returned to the Client. In addition, the Server deletes the entry for the Client from its SessionDiagnosticsArray Variable and notifies any other Clients who were subscribed to this entry. If a Client invokes the CloseSession Service then all Subscriptions associated with the Session are also deleted if the deleteSubscriptions flag is set to TRUE. If a Server terminates a Session for any other reason, Subscriptions associated with the Session, are not deleted. Each Subscription has its own lifetime to protect against data loss in the case of a Session termination. In these cases, the Subscription can be reassigned to another Client before its lifetime expires.

## Wireshark Request example
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 250
    SecureChannelId: 3
    Security Token Id: 3
    Security Sequence Number: 2
    Security RequestId: 2
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: CreateSessionRequest (461)
        CreateSessionRequest
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
            ClientDescription: ApplicationDescription
                ApplicationUri: urn:pcname:producer:appname
                ProductUri: urn:producer:appname
                ApplicationName: LocalizedText
                    EncodingMask: 0x02, has text
                        .... ...0 = has locale information: False
                        .... ..1. = has text: True
                    Text: producer appname
                ApplicationType: Client (0x00000001)
                GatewayServerUri: [OpcUa Null String]
                DiscoveryProfileUri: [OpcUa Null String]
                DiscoveryUrls: Array of String
                    ArraySize: 0
            ServerUri: [OpcUa Null String]
            EndpointUrl: opc.tcp://localhost:4840/
            SessionName: producer appname
            ClientNonce: <MISSING>[OpcUa Empty ByteString]
            ClientCertificate: <MISSING>[OpcUa Empty ByteString]
            RequestedSessionTimeout: 0
            MaxResponseMessageSize: 0

## Request parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|    requestHeader | RequestHeader | Common request parameters. The authenticationToken is always null. The type RequestHeader is defined in 7.28. |
|    clientDescription | Application Description | Information that describes the Client application. The type ApplicationDescription is defined in 7.1. |
|    serverUri | String | This value is only specified if the EndpointDescription has a gatewayServerUri.  This value is the applicationUri from the EndpointDescription which is the applicationUri for the underlying Server. The type EndpointDescription is defined in 7.10. |
|    endpointUrl | String | The network address that the Client used to access the Session Endpoint. The HostName portion of the URL should be one of the HostNames for the application that are specified in the Server’s ApplicationInstanceCertificate (see 7.2). The Server shall raise an AuditUrlMismatchEventType event if the URL does not match the Server’s HostNames. AuditUrlMismatchEventType event type is defined in OPC 10000-5. The Server uses this information for diagnostics and to determine the set of EndpointDescriptions to return in the response. |
|    sessionName | String | Human readable string that identifies the Session. The Server makes this name and the sessionId visible in its AddressSpace for diagnostic purposes. The Client should provide a name that is unique for the instance of the Client. If this parameter is not specified the Server shall assign a value. |
|    clientNonce | ByteString | A random number that should never be used in any other  request. This number shall have a minimum length of 32 bytes. Profiles  may increase the required length. The Server shall use this value to prove possession of its Application Instance Certificate in the response. |
|    clientCertificate | ApplicationInstance Certificate | The Application Instance Certificate issued to the Client. The ApplicationInstanceCertificate type is defined in 7.2. If the securityPolicyUri is None, the Server shall ignore the ApplicationInstanceCertificate. |
|    Requested    SessionTimeout | Duration | Requested maximum number of milliseconds that a Session should remain open without activity. If the Client fails to issue a Service request within this interval, then the Server shall automatically terminate the Client Session. |
|    maxResponse    MessageSize | UInt32 | The maximum size, in bytes, for the body of any response message. The Server should return a Bad_ResponseTooLarge service fault if a response message exceeds this limit. The value zero indicates that this parameter is not used. The transport protocols defined in OPC 10000-6 may imply minimum message sizes. More information on the use of this parameter is provided in 5.3. |
|  |  |  |

## Wireshark Response
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 8462
    SecureChannelId: 3
    Security Token Id: 3
    Security Sequence Number: 2
    Security RequestId: 2
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: CreateSessionResponse (464)
        CreateSessionResponse
            ResponseHeader: ResponseHeader
                Timestamp: Feb 16, 2022 13:07:05.389156000 W. Europe Standard Time
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
            SessionId: NodeId
                .... 0100 = EncodingMask: GUID (0x4)
                Namespace Index: 1
                Identifier Guid: 94f9d8ec-87b7-ae5f-1631-2332143153e5
            AuthenticationToken: NodeId
                .... 0100 = EncodingMask: GUID (0x4)
                Namespace Index: 1
                Identifier Guid: 80e28566-dfa9-62b9-f6df-1d912072f71f
            RevisedSessionTimeout: 3600000
            ServerNonce: 07351734ccfc3867d1aca11f5dbd9c072992575ee0e9fb504ac22d6a46ec89a4
            ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
            ServerEndpoints: Array of EndpointDescription
                ArraySize: 5
                [0]: EndpointDescription
                    EndpointUrl: opc.tcp://localhost:4840/
                    Server: ApplicationDescription
                        ApplicationUri: urn:open62541.server.application
                        ProductUri: http://open62541.org
                        ApplicationName: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: en
                            Text: open62541-based OPC UA Application
                        ApplicationType: Server (0x00000000)
                        GatewayServerUri: [OpcUa Null String]
                        DiscoveryProfileUri: [OpcUa Null String]
                        DiscoveryUrls: Array of String
                            ArraySize: -1
                    ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
                    MessageSecurityMode: None (0x00000001)
                    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#None
                    UserIdentityTokens: Array of UserTokenPolicy
                        ArraySize: 2
                        [0]: UserTokenPolicy
                            PolicyId: open62541-anonymous-policy
                            UserTokenType: Anonymous (0x00000000)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: [OpcUa Null String]
                        [1]: UserTokenPolicy
                            PolicyId: open62541-username-policy
                            UserTokenType: UserName (0x00000001)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    TransportProfileUri: http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
                    SecurityLevel: 1
                [1]: EndpointDescription
                    EndpointUrl: opc.tcp://localhost:4840/
                    Server: ApplicationDescription
                        ApplicationUri: urn:open62541.server.application
                        ProductUri: http://open62541.org
                        ApplicationName: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: en
                            Text: open62541-based OPC UA Application
                        ApplicationType: Server (0x00000000)
                        GatewayServerUri: [OpcUa Null String]
                        DiscoveryProfileUri: [OpcUa Null String]
                        DiscoveryUrls: Array of String
                            ArraySize: -1
                    ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
                    MessageSecurityMode: SignAndEncrypt (0x00000003)
                    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    UserIdentityTokens: Array of UserTokenPolicy
                        ArraySize: 2
                        [0]: UserTokenPolicy
                            PolicyId: open62541-anonymous-policy
                            UserTokenType: Anonymous (0x00000000)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: [OpcUa Null String]
                        [1]: UserTokenPolicy
                            PolicyId: open62541-username-policy
                            UserTokenType: UserName (0x00000001)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    TransportProfileUri: http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
                    SecurityLevel: 3
                [2]: EndpointDescription
                    EndpointUrl: opc.tcp://localhost:4840/
                    Server: ApplicationDescription
                        ApplicationUri: urn:open62541.server.application
                        ProductUri: http://open62541.org
                        ApplicationName: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: en
                            Text: open62541-based OPC UA Application
                        ApplicationType: Server (0x00000000)
                        GatewayServerUri: [OpcUa Null String]
                        DiscoveryProfileUri: [OpcUa Null String]
                        DiscoveryUrls: Array of String
                            ArraySize: -1
                    ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
                    MessageSecurityMode: Sign (0x00000002)
                    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    UserIdentityTokens: Array of UserTokenPolicy
                        ArraySize: 2
                        [0]: UserTokenPolicy
                            PolicyId: open62541-anonymous-policy
                            UserTokenType: Anonymous (0x00000000)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: [OpcUa Null String]
                        [1]: UserTokenPolicy
                            PolicyId: open62541-username-policy
                            UserTokenType: UserName (0x00000001)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    TransportProfileUri: http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
                    SecurityLevel: 2
                [3]: EndpointDescription
                    EndpointUrl: opc.tcp://localhost:4840/
                    Server: ApplicationDescription
                        ApplicationUri: urn:open62541.server.application
                        ProductUri: http://open62541.org
                        ApplicationName: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: en
                            Text: open62541-based OPC UA Application
                        ApplicationType: Server (0x00000000)
                        GatewayServerUri: [OpcUa Null String]
                        DiscoveryProfileUri: [OpcUa Null String]
                        DiscoveryUrls: Array of String
                            ArraySize: -1
                    ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
                    MessageSecurityMode: SignAndEncrypt (0x00000003)
                    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
                    UserIdentityTokens: Array of UserTokenPolicy
                        ArraySize: 2
                        [0]: UserTokenPolicy
                            PolicyId: open62541-anonymous-policy
                            UserTokenType: Anonymous (0x00000000)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: [OpcUa Null String]
                        [1]: UserTokenPolicy
                            PolicyId: open62541-username-policy
                            UserTokenType: UserName (0x00000001)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    TransportProfileUri: http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
                    SecurityLevel: 3
                [4]: EndpointDescription
                    EndpointUrl: opc.tcp://localhost:4840/
                    Server: ApplicationDescription
                        ApplicationUri: urn:open62541.server.application
                        ProductUri: http://open62541.org
                        ApplicationName: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: en
                            Text: open62541-based OPC UA Application
                        ApplicationType: Server (0x00000000)
                        GatewayServerUri: [OpcUa Null String]
                        DiscoveryProfileUri: [OpcUa Null String]
                        DiscoveryUrls: Array of String
                            ArraySize: -1
                    ServerCertificate: 308203ee308202d6a00302010202141d5a8033139404e8a3f1c5aae104070f2fee141830…
                    MessageSecurityMode: Sign (0x00000002)
                    SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
                    UserIdentityTokens: Array of UserTokenPolicy
                        ArraySize: 2
                        [0]: UserTokenPolicy
                            PolicyId: open62541-anonymous-policy
                            UserTokenType: Anonymous (0x00000000)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: [OpcUa Null String]
                        [1]: UserTokenPolicy
                            PolicyId: open62541-username-policy
                            UserTokenType: UserName (0x00000001)
                            IssuedTokenType: [OpcUa Null String]
                            IssuerEndpointUrl: [OpcUa Null String]
                            SecurityPolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep
                    TransportProfileUri: http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary
                    SecurityLevel: 2
            ServerSoftwareCertificates: Array of SignedSoftwareCertificate
                ArraySize: -1
            ServerSignature: SignatureData
                Algorithm: [OpcUa Null String]
                Signature: <MISSING>[OpcUa Null ByteString]
            MaxRequestMessageSize: 0

## Response parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
| ponseHeader | ResponseHeader | Common response parameters (see 7.29 for ResponseHeader type). |
|    sessionId | NodeId | A unique NodeId assigned by the Server to the Session. This identifier is used to access the diagnostics information for the Session in the Server AddressSpace. It is also used in the audit logs and any events that report information related to the Session. The Session diagnostic information is described in OPC 10000-5. Audit logs and their related events are described in 6.5. |
|    authentication Token | Session AuthenticationToken | A unique identifier assigned by the Server to the Session. This identifier shall be passed in the RequestHeader of each request and is used with the SecureChannelId to determine whether a Client has access to the Session. This identifier shall not be reused in a way that the Client or the Server has a chance of confusing them with a previous or existing Session. The SessionAuthenticationToken type is described in 7.31. |
|    revisedSession Timeout | Duration | Actual maximum number of milliseconds that a Session shall remain open without activity. The Server should attempt to honour the Client request for this parameter, but may negotiate this value up or down to meet its own constraints. |
|    serverNonce | ByteString | A random number that should never be used in any other request. This number shall have a minimum length of 32 bytes. The Client shall use this value to prove possession of its Application Instance Certificate in the ActivateSession request.  This value may also be used to prove possession of the userIdentityToken it specified in the ActivateSession request. |
|    serverCertificate | ApplicationInstance Certificate | The Application Instance Certificate issued to the Server. A Server shall prove possession by using the private key to sign the Nonce provided by the Client in the request. The Client shall verify that this Certificate is the same as the one it used to create the SecureChannel. The ApplicationInstanceCertificate type is defined in 7.2. If the securityPolicyUri is NONE and none of the UserTokenPolicies requires encryption, the Client shall ignore the ApplicationInstanceCertificate. |
|    serverEndpoints [] | EndpointDescription | List of Endpoints that the Server supports. The Server shall return a set of EndpointDescriptions available for the serverUri specified in the request. The EndpointDescription type is defined in 7.10. The Client shall verify this list with the list from a DiscoveryEndpoint if it used a DiscoveryEndpoint to fetch the EndpointDescriptions. It is recommended that Servers only include the server.applicationUri, endpointUrl, securityMode, securityPolicyUri, userIdentityTokens, transportProfileUri and securityLevel with all other parameters set to null. Only the recommended parameters shall be verified by the client. |
|    serverSoftware    Certificates [] | SignedSoftware Certificate | This parameter is deprecated and the array shall be empty. The SoftwareCertificates are provided in the Server AddressSpace as defined in OPC 10000-5. |
|    serverSignature | SignatureData | This is a signature generated with the private key associated with the serverCertificate. This parameter is calculated by appending the clientNonce to the clientCertificate and signing the resulting sequence of bytes. If the clientCertificate contains a chain, the signature calculation shall be done only with the leaf Certificate. For backward compatibility a Client shall check the signature with the full chain if the check with the leaf Certificate fails. The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified in the SecurityPolicy for the Endpoint. The SignatureData type is defined in 7.32. |
|    maxRequest    MessageSize | UInt32 | The maximum size, in bytes, for the body of any request message. The Client Communication Stack should return a Bad_RequestTooLarge error to the application if a request message exceeds this limit.  The value zero indicates that this parameter is not used. See OPC 10000-6 for protocol specific minimum or default values. 5.3 provides more information on the use of this parameter. |

## Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Bad_SecureChannelIdInvalid | See Table 177 for the description of this result code. |
| Bad_NonceInvalid | See Table 177 for the description of this result code. A Server shall check the minimum length of the Client  nonce and return this status if the length is below 32 bytes. A check  for a duplicated nonce is optional and requires access to the nonce used  to create the secure channel. |
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
| Bad_TooManySessions | The Server has reached its maximum number of Sessions. |
| Bad_ServerUriInvalid | See Table 177 for the description of this result code. |