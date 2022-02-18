# Common Headers
## RequestHeader
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
| RequestHeader | structure | Common parameters for all requests submitted on a Session. |
| authenticationToken | Session AuthenticationToken | The secret Session identifier used to verify that the request is associated with the Session. The SessionAuthenticationToken type is defined in 7.31. |
|    timestamp | UtcTime | The time the Client sent the request. The parameter is only used for diagnostic and logging purposes in the server. |
|    requestHandle | IntegerId | A requestHandle associated with the request. This Client defined handle can be used to cancel the request. It is also returned in the response. |
|    returnDiagnostics | UInt32 | A bit mask that identifies the types of vendor-specific diagnostics to be returned in diagnosticInfo response parameters. The  value of this parameter may consist of zero, one or more of the  following values. No value indicates that diagnostics are not to be  returned.    Bit Value			Diagnostics to return    0x0000 0001	ServiceLevel / SymbolicId    0x0000 0002	ServiceLevel / LocalizedText    0x0000 0004	ServiceLevel / AdditionalInfo    0x0000 0008	ServiceLevel / Inner StatusCode    0x0000 0010	ServiceLevel / Inner Diagnostics    0x0000 0020	OperationLevel / SymbolicId    0x0000 0040	OperationLevel / LocalizedText    0x0000 0080	OperationLevel / AdditionalInfo    0x0000 0100	OperationLevel / Inner StatusCode    0x0000 0200	OperationLevel / Inner Diagnostics Each of these values is composed of two components, level and type,  as described below. If none are requested, as indicated by a 0 value,  or if no diagnostic information was encountered in processing of the  request, then diagnostics information is not returned. Level:    ServiceLevel	return diagnostics in the diagnosticInfo of the Service.    OperationLevel	return diagnostics in the diagnosticInfo defined for individual operations requested in the Service.  Type:    SymbolicId 		return a namespace-qualified, symbolic identifier for an error or  condition. The maximum length of this identifier is 32 characters.    LocalizedText	return up to 256 bytes of localized text that describes the symbolic id.    AdditionalInfo 	return a byte string that contains additional diagnostic information,  such as a memory image. The format of this byte string is  vendor-specific, and may depend on the type of error or condition  encountered.    InnerStatusCode	return the inner StatusCode associated with the operation or Service.    InnerDiagnostics	return the inner diagnostic info associated with the operation or Service.  The contents of the inner diagnostic info structure are determined by  other bits in the mask. Note that setting this bit could cause multiple  levels of nested diagnostic info structures to be returned.                     |
|    auditEntryId | String | An identifier that identifies the Client’s security audit log entry associated with this request. An empty string value means that this parameter is not used. The auditEntryId typically contains who initiated the action and from where it was initiated. The auditEntryId is included in the AuditEvent to allow human readers to correlate an Event with the initiating action. More details of the Audit mechanisms are defined in 6.5 and in OPC 10000-3. |
|    timeoutHint | UInt32 | This timeout in milliseconds is used in the Client side Communication Stack to set the timeout on a per-call base. For a Server  this timeout is only a hint and can be used to cancel long running  operations to free resources. If the Server detects a timeout, he can  cancel the operation by sending the Service result Bad_Timeout. The Server should wait at minimum the timeout after he received the request before cancelling the operation. The Server shall check the timeoutHint parameter of a Publish request before processing a Publish response. If the request timed out, a Bad_Timeout Service result is sent and another Publish request is used.  The value of 0 indicates no timeout. |
|    additionalHeader | Extensible Parameter AdditionalHeader | Reserved for future use. Applications that do not understand the header should ignore it. |

## ResponseHeader
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
| ResponseHeader | structure | Common parameters for all responses. |
|    timestamp | UtcTime | The time the Server sent the response. |
|    requestHandle | IntegerId | The requestHandle given by the Client to the request. |
|    serviceResult | StatusCode | OPC UA-defined result of the Service invocation. The StatusCode type is defined in 7.34. |
|    serviceDiagnostics | DiagnosticInfo | Diagnostic information for the Service invocation. This parameter is empty if diagnostics information was not requested in the request header. The DiagnosticInfo type is defined in 7.8. |
|    stringTable [] | String | There is one string in this list for each unique namespace,  symbolic identifier, and localized text string contained in all of the  diagnostics information parameters contained in the response (see 7.8). Each is identified within this table by its zero-based index. |
|    additionalHeader | Extensible Parameter AdditionalHeader | Reserved for future use. Applications that do not understand the header should ignore it. |


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


# Read Request MSG
## Browse the AddressSpace default nodes (all servers have)
The default NodeIDs of every AddressSpace
- ns=0, i =84 --> Root Node
- ns=0, i =85 --> Objects
- ns=0, i =86 --> Types 
- ns=0, i =87 --> Views

## Read Val ID in 'Read Req MSG'
The field ReadValID has following sub-fields:
- NodeID (xB) identifies the kind of NodeID (two bytes integer 0000, four bytes integer 0001, string 0011 ...) and the value of NodeID (2B, 4B, len(str))
- AttributeID (4B)
- Index Range (4B)
- DataEncoding (6B)

## Default AttributeIDs Constants
Every node in an OPC UA information model contains attributes depending on the node type. Possible attributes are as follows:
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


# Common Service Result Codes
| **Symbolic Id** | Description |
|:---:|:---:|
| Good | The operation was successful. |
| Good_CompletesAsynchronously | The processing will complete asynchronously. |
| Good_SubscriptionTransferred | The subscription was transferred to another session. |
|   |   |
| Bad_CertificateHostNameInvalid | The HostName used to connect to a Server does not match a HostName in the Certificate. |
| Bad_CertificateChainIncomplete | The Certificate chain is incomplete. |
| Bad_CertificateIssuerRevocationUnknown | It was not possible to determine if the Issuer Certificate has been revoked. |
| Bad_CertificateIssuerUseNotAllowed | The Issuer Certificate may not be used for the requested operation. |
| Bad_CertificateIssuerTimeInvalid | An Issuer Certificate has expired or is not yet valid. |
| Bad_CertificateIssuerRevoked | The Issuer Certificate has been revoked. |
| Bad_CertificateInvalid | The Certificate provided as a parameter is not valid. |
| Bad_CertificateRevocationUnknown | It was not possible to determine if the Certificate has been revoked. |
| Bad_CertificateRevoked | The Certificate has been revoked. |
| Bad_CertificateTimeInvalid | The Certificate has expired or is not yet valid. |
| Bad_CertificateUriInvalid | The URI specified in the ApplicationDescription does not match the URI in the Certificate. |
| Bad_CertificateUntrusted | The Certificate is not trusted. |
| Bad_CertificateUseNotAllowed | The Certificate may not be used for the requested operation. |
| Bad_CommunicationError | A low level communication error occurred. |
| Bad_DataTypeIdUnknown | The ExtensionObject cannot be (de)serialized because the data type id is not recognized. |
| Bad_DecodingError | Decoding halted because of invalid data in the stream. |
| Bad_EncodingError | Encoding halted because of invalid data in the objects being serialized. |
| Bad_EncodingLimitsExceeded | The message encoding/decoding limits imposed by the Communication Stack have been exceeded. |
|   |   |
| Bad_IdentityTokenInvalid | The user identity token is not valid. |
| Bad_IdentityTokenRejected | The user identity token is valid but the Server has rejected it. |
| Bad_InternalError | An internal error occurred as a result of a programming or configuration error. |
| Bad_InvalidArgument | One or more arguments are invalid. Each service defines parameter-specific StatusCodes and these StatusCodes shall be used instead of this general error code. This error code shall be used only by the Communication Stack and in services where it is defined in the list of valid StatusCodes for the service. |
| Bad_InvalidState | The operation cannot be completed because the object is closed, uninitialized or in some other invalid state. |
| Bad_InvalidTimestamp | The timestamp is outside the range allowed by the Server. |
| Bad_LicenseExpired | The UA Server requires a license to operate in general or to perform a service or operation, but existing license is expired |
| Bad_LicenseLimitsExceeded | The UA Server has limits on number of allowed operations /  objects, based on installed licenses, and these limits where exceeded. |
| Bad_LicenseNotAvailable | The UA Server does not have a license which is required to operate in general or to perform a service or operation. |
| Bad_NothingToDo | There was nothing to do because the Client passed a list of operations with no elements. |
| Bad_OutOfMemory | Not enough memory to complete the operation. |
| Bad_RequestCancelledByClient | The request was cancelled by the client. |
| Bad_RequestTooLarge | The request message size exceeds limits set by the Server. |
| Bad_ResponseTooLarge | The response message size exceeds limits set by the client. |
| Bad_RequestHeaderInvalid | The header for the request is missing or invalid. |
| Bad_ResourceUnavailable | An operating system resource is not available. |
| Bad_SecureChannelIdInvalid | The specified secure channel is no longer valid. |
| Bad_SecurityChecksFailed | An error occurred while verifying security. |
| Bad_ServerHalted | The Server has stopped and cannot process any requests. |
| Bad_ServerNotConnected | The operation could not complete because the Client is not connected to the Server. |
| Bad_ServerUriInvalid | The Server URI is not valid. |
| Bad_ServiceUnsupported | The Server does not support the requested service. |
| Bad_SessionIdInvalid | The Session id is not valid. |
| Bad_SessionClosed | The Session was closed by the client. |
| Bad_SessionNotActivated | The Session cannot be used because ActivateSession has not been called. |
| Bad_Shutdown | The operation was cancelled because the application is shutting down. |
| Bad_SubscriptionIdInvalid | The subscription id is not valid. |
| Bad_Timeout | The operation timed out. |
| Bad_TimestampsToReturnInvalid | The timestamps to return parameter is invalid. |
| Bad_TooManyOperations | The request could not be processed because it specified too many operations. |
| Bad_UnexpectedError | An unexpected error occurred. |
| Bad_UnknownResponse | An unrecognized response was received from the Server. |
| Bad_UserAccessDenied | User does not have permission to perform the requested operation. |
| Bad_ViewIdUnknown | The view id does not refer to a valid view Node. |
| Bad_ViewTimestampInvalid | The view timestamp is not available or not supported. |
| Bad_ViewParameterMismatchInvalid | The view parameters are not consistent with each other. |
| Bad_ViewVersionInvalid | The view version is not available or not supported. |

# Common Operation Level Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Good_Clamped | The value written was accepted but was clamped. |
| Good_Overload | Sampling has slowed down due to resource limitations. |
| Uncertain | The value is uncertain but no specific reason is known. |
| Bad | The value is bad but no specific reason is known. |
| Bad_AttributeIdInvalid | The attribute is not supported for the specified node. |
| Bad_BrowseDirectionInvalid | The browse direction is not valid. |
| Bad_BrowseNameInvalid | The browse name is invalid. |
| Bad_ContentFilterInvalid | The content filter is not valid. |
| Bad_ContinuationPointInvalid | The continuation point provided is no longer valid. This status is returned if the continuation point was deleted or the address space was changed between the browse calls. |
| Bad_DataEncodingInvalid | The data encoding is invalid. This result is used if no dataEncoding can be applied because an Attribute other than Value was requested or the DataType of the Value Attribute is not a subtype of the Structure DataType. |
| Bad_DataEncodingUnsupported | The Server does not support the requested data encoding for the node. This result is used if a dataEncoding can be applied but the passed data encoding is not known to the Server. |
| Bad_EventFilterInvalid | The event filter is not valid. |
| Bad_FilterNotAllowed | A monitoring filter cannot be used in combination with the attribute specified. |
| Bad_FilterOperandInvalid | The operand used in a content filter is not valid. |
| Bad_HistoryOperationInvalid | The history details parameter is not valid. |
| Bad_HistoryOperationUnsupported | The Server does not support the requested operation. |
| Bad_IndexRangeInvalid | The syntax of the index range parameter is invalid. |
| Bad_IndexRangeNoData | No data exists within the range of indexes specified. |
| Bad_MonitoredItemFilterInvalid | The monitored item filter parameter is not valid. |
| Bad_MonitoredItemFilterUnsupported | The Server does not support the requested monitored item filter. |
| Bad_MonitoredItemIdInvalid | The monitoring item id does not refer to a valid monitored item. |
| Bad_MonitoringModeInvalid | The monitoring mode is invalid. |
| Bad_NoCommunication | Communication with the data source is defined, but not established, and there is no last known value available. This  status/sub-status is used for cached values before the first value is  received or for Write and Call if the communication is not established. |
| Bad_NoContinuationPoints | The operation could not be processed because all continuation points have been allocated. |
| Bad_NodeClassInvalid | The node class is not valid. |
| Bad_NodeIdInvalid | The syntax of the node id is not valid. |
| Bad_NodeIdUnknown | The node id refers to a node that does not exist in the Server address space. |
| Bad_NoDeleteRights | The Server will not allow the node to be deleted. |
| Bad_NodeNotInView | The nodesToBrowse is not part of the view. |
| Bad_NotFound | A requested item was not found or a search operation ended without success. |
| Bad_NotImplemented | Requested operation is not implemented. |
| Bad_NotReadable | The access level does not allow reading or subscribing to the Node. |
| Bad_NotSupported | The requested operation is not supported. |
| Bad_NotWritable | The access level does not allow writing to the Node. |
| Bad_ObjectDeleted | The Object cannot be used because it has been deleted. |
| Bad_OutOfRange | The value was out of range. |
| Bad_ReferenceTypeIdInvalid | The reference type id does not refer to a valid reference type node. |
| Bad_SecurityModeInsufficient | The SecurityPolicy and/or MessageSecurityMode do not match the Server requirements to complete the operation. For  example, a user may have the right to receive the data but the data can  only be transferred through an encrypted channel with an appropriate SecurityPolicy. |
| Bad_SourceNodeIdInvalid | The source node id does not refer to a valid node. |
| Bad_StructureMissing | A mandatory structured parameter was missing or null. |
| Bad_TargetNodeIdInvalid | The target node id does not refer to a valid node. |
| Bad_TypeDefinitionInvalid | The type definition node id does not reference an appropriate type node. |
| Bad_TypeMismatch | The value supplied for the attribute is not of the same type as the attribute’s value. |
| Bad_WaitingForInitialData | Waiting for the Server to obtain values from the underlying data source. After creating a MonitoredItem or after setting the MonitoringMode from DISABLED to REPORTING or SAMPLING, it may take some time for the Server to actually obtain values for these items. In such cases the Server can send a Notification with this status prior to the Notification with the first value or status from the data source. |