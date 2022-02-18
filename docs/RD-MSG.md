# Read Messages
- This Service is used to read one or more Attributes of one or more Nodes. For constructed Attribute values whose elements are indexed, such as an array, this Service allows Clients to read the entire set of indexed values as a composite, to read individual elements or to read ranges of elements of the composite.
- The **maxAge** parameter is used to direct the Server to access the value from the underlying data source, such as a device, if its copy of the data is older than that which the maxAge specifies. If the Server cannot meet the requested maximum age, it returns its “best effort” value rather than rejecting the request.

## Wireshark Request
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 266
    SecureChannelId: 10
    Security Token Id: 10
    Security Sequence Number: 113
    Security RequestId: 63
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: ReadRequest (631)
        ReadRequest
            RequestHeader: RequestHeader
                AuthenticationToken: NodeId
                    .... 0100 = EncodingMask: GUID (0x4)
                    Namespace Index: 1
                    Identifier Guid: 71ff011e-1316-a504-3e23-7277c98c68d6
                Timestamp: Nov 23, 2021 10:57:43.636301800 W. Europe Standard Time
                RequestHandle: 1000062
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
            MaxAge: 0
            TimestampsToReturn: Both (0x00000002)
            NodesToRead: Array of ReadValueId
                ArraySize: 11
                [0]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: NodeId (0x00000001)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [1]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: NodeClass (0x00000002)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [2]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: BrowseName (0x00000003)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [3]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: DisplayName (0x00000004)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [4]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: Description (0x00000005)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [5]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: WriteMask (0x00000006)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [6]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: UserWriteMask (0x00000007)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [7]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: RolePermissions (0x00000018)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [8]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: UserRolePermissions (0x00000019)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [9]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: AccessRestrictions (0x0000001a)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]
                [10]: ReadValueId
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    AttributeId: EventNotifier (0x0000000c)
                    IndexRange: [OpcUa Null String]
                    DataEncoding: QualifiedName
                        Id: 0
                        Name: [OpcUa Null String]


## Wireshark response
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 224
    SecureChannelId: 10
    Security Token Id: 10
    Security Sequence Number: 61
    Security RequestId: 63
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: ReadResponse (634)
        ReadResponse
            ResponseHeader: ResponseHeader
                Timestamp: Nov 23, 2021 10:57:43.634223000 W. Europe Standard Time
                RequestHandle: 1000062
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
            Results: Array of DataValue
                ArraySize: 11
                [0]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: NodeId (0x11)
                        Value: NodeId
                            .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                            Identifier Numeric: 85
                    ServerTimestamp: Nov 23, 2021 10:57:43.634217000 W. Europe Standard Time
                [1]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: Int32 (0x06)
                        Int32: 1
                    ServerTimestamp: Nov 23, 2021 10:57:43.634218000 W. Europe Standard Time
                [2]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: QualifiedName (0x14)
                        Value: QualifiedName
                            Id: 0
                            Name: Objects
                    ServerTimestamp: Nov 23, 2021 10:57:43.634220000 W. Europe Standard Time
                [3]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: LocalizedText (0x15)
                        Value: LocalizedText
                            EncodingMask: 0x03, has locale information, has text
                                .... ...1 = has locale information: True
                                .... ..1. = has text: True
                            Locale: [OpcUa Empty String]
                            Text: Objects
                    ServerTimestamp: Nov 23, 2021 10:57:43.634220000 W. Europe Standard Time
                [4]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: LocalizedText (0x15)
                        Value: LocalizedText
                            EncodingMask: 0x00
                                .... ...0 = has locale information: False
                                .... ..0. = has text: False
                    ServerTimestamp: Nov 23, 2021 10:57:43.634221000 W. Europe Standard Time
                [5]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: UInt32 (0x07)
                        UInt32: 0
                    ServerTimestamp: Nov 23, 2021 10:57:43.634221000 W. Europe Standard Time
                [6]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: UInt32 (0x07)
                        UInt32: 0
                    ServerTimestamp: Nov 23, 2021 10:57:43.634222000 W. Europe Standard Time
                [7]: DataValue
                    EncodingMask: 0x0a, has statuscode, has server timestamp
                        .... ...0 = has value: False
                        .... ..1. = has statuscode: True
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    StatusCode: 0x80350000 [BadAttributeIdInvalid]
                    ServerTimestamp: Nov 23, 2021 10:57:43.634222000 W. Europe Standard Time
                [8]: DataValue
                    EncodingMask: 0x0a, has statuscode, has server timestamp
                        .... ...0 = has value: False
                        .... ..1. = has statuscode: True
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    StatusCode: 0x80350000 [BadAttributeIdInvalid]
                    ServerTimestamp: Nov 23, 2021 10:57:43.634222000 W. Europe Standard Time
                [9]: DataValue
                    EncodingMask: 0x0a, has statuscode, has server timestamp
                        .... ...0 = has value: False
                        .... ..1. = has statuscode: True
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    StatusCode: 0x80350000 [BadAttributeIdInvalid]
                    ServerTimestamp: Nov 23, 2021 10:57:43.634222000 W. Europe Standard Time
                [10]: DataValue
                    EncodingMask: 0x09, has value, has server timestamp
                        .... ...1 = has value: True
                        .... ..0. = has statuscode: False
                        .... .0.. = has source timestamp: False
                        .... 1... = has server timestamp: True
                        ...0 .... = has source picoseconds: False
                        ..0. .... = has server picoseconds: False
                    Value: Variant
                        Variant Type: Byte (0x03)
                        Byte: 0
                    ServerTimestamp: Nov 23, 2021 10:57:43.634222000 W. Europe Standard Time
            DiagnosticInfos: Array of DiagnosticInfo
                ArraySize: -1


## Service parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
| **Request** | |  |
|    requestHeader | RequestHeader | Common request parameters (see 7.28 for RequestHeader definition). |
|    maxAge | Duration | Maximum age of the value to be read in milliseconds. The age of the value is based on the difference between the ServerTimestamp and the time when the Server starts processing the request. For example if the Client specifies a maxAge of 500 milliseconds and it takes 100 milliseconds until the Server starts processing the request, the age of the returned value could be 600 milliseconds prior to the time it was requested. If the Server has one or more values of an Attribute  that are within the maximum age, it can return any one of the values or  it can read a new value from the data source. The number of values of  an Attribute that a Server has depends on the number of MonitoredItems that are defined for the Attribute. In any case, the Client can make no assumption about which copy of the data will be returned.  If the Server does not have a value that is within the maximum age, it shall attempt to read a new value from the data source.  If the Server cannot meet the requested maxAge, it returns its “best effort” value rather than rejecting the request. This may occur when the time it takes the Server to process and return the new data value after it has been accessed is greater than the specified maximum age. If maxAge is set to 0, the Server shall attempt to read a new value from the data source. If maxAge is set to the max Int32 value or greater, the Server shall attempt to get a cached value. Negative values are invalid for maxAge. |
|    timestampsTo    Return | Enum TimestampsTo Return | An enumeration that specifies the Timestamps to be returned for each requested Variable Value Attribute. The TimestampsToReturn enumeration is defined in 7.35. |
|    nodesToRead [] | ReadValueId | List of Nodes and their Attributes to read. For each entry in this list, a StatusCode is returned, and if it indicates success, the Attribute Value is also returned. The ReadValueId parameter type is defined in 7.24. |
| **Response** | |  |
|    responseHeader | ResponseHeader | Common response parameters (see 7.29 for ResponseHeader definition). |
|    results [] | DataValue | List of Attribute values (see 7.7 for DataValue definition). The size and order of this list matches the size and order of the nodesToRead request parameter. There is one entry in this list for each Node contained in the nodesToRead parameter. |
|    diagnosticInfos [] | DiagnosticInfo | List of diagnostic information (see 7.8 for DiagnosticInfo definition). The size and order of this list matches the size and order of the nodesToRead request parameter. There is one entry in this list for each Node contained in the nodesToRead  parameter. This list is empty if diagnostics information was not  requested in the request header or if no diagnostic information was  encountered in processing of the request. |

## Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Bad_ViewIdUnknown | See Table 177 for the description of this result code. |
| Bad_ViewTimestampInvalid | See Table 177 for the description of this result code. |
| Bad_ViewParameterMismatchInvalid | See Table 177 for the description of this result code. |
| Bad_ViewVersionInvalid | See Table 177 for the description of this result code. |
| Bad_NothingToDo | See Table 177 for the description of this result code. |
| Bad_TooManyOperations | See Table 177 for the description of this result code. |

## Operation Level Result Codes
| **Symbolic Id** | **Description** |
|:---:|:---:|
| Bad_NothingToDo | See Table 177 for the description of this result code. |
| Bad_TooManyOperations | See Table 177 for the description of this result code. |
| Bad_MaxAgeInvalid | The max age parameter is invalid. |
| Bad_TimestampsToReturnInvalid | See Table 177 for the description of this result code. |
