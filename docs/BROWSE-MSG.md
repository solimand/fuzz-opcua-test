# Browse Messages
- This Service is used to discover the References of a specified Node. The browse can be further limited by the use of a View. This Browse Service also supports a primitive filtering capability.
- In some cases it may take longer than the Client timeout hint to process all nodes to browse. In this case the Server may return zero results with a continuation point for the affected nodes before the timeout expires.

## Wireshark Request example
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 113
    SecureChannelId: 10
    Security Token Id: 10
    Security Sequence Number: 114
    Security RequestId: 64
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: BrowseRequest (527)
        BrowseRequest
            RequestHeader: RequestHeader
                AuthenticationToken: NodeId
                    .... 0100 = EncodingMask: GUID (0x4)
                    Namespace Index: 1
                    Identifier Guid: 71ff011e-1316-a504-3e23-7277c98c68d6
                Timestamp: Nov 23, 2021 10:57:43.636345900 W. Europe Standard Time
                RequestHandle: 1000063
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
            View: ViewDescription
                ViewId: NodeId
                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                    Identifier Numeric: 0
                Timestamp: No time specified (0)
                ViewVersion: 0
            RequestedMaxReferencesPerNode: 100
            NodesToBrowse: Array of BrowseDescription
                ArraySize: 1
                [0]: BrowseDescription
                    NodeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 85
                    BrowseDirection: Forward (0x00000000)
                    ReferenceTypeId: NodeId
                        .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                        Identifier Numeric: 31
                    IncludeSubtypes: True
                    Node Class Mask: All (0x00000000)
                    Result Mask: All (0x0000003f)

## Request parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|    requestHeader | RequestHeader | Common request parameters (see 7.28 for RequestHeader definition). |
|    View | ViewDescription | Description of the View to browse (see 7.39 for ViewDescription definition). An empty ViewDescription value indicates the entire AddressSpace. Use of the empty ViewDescription value causes all References of the nodesToBrowse to be returned. Use of any other View causes only the References of the nodesToBrowse that are defined for that View to be returned. |
|    requestedMax    ReferencesPerNode | Counter | Indicates the maximum number of references to return for each  starting Node specified in the request. The value 0 indicates that the Client is imposing no limitation (see 7.5 for Counter definition). |
|    nodesToBrowse [] | BrowseDescription | A list of nodes to Browse. This structure is defined in-line with the following indented items. |
|       nodeId | NodeId | NodeId   of the Node to be browsed. If a view is provided, it shall include this Node. |
|       browseDirection | Enum BrowseDirection | An enumeration that specifies the direction of References to follow. It has the following values:    FORWARD_0	select only forward References.    INVERSE_1			select only inverse References.    BOTH_2				select forward and inverse References.     INVALID_3			no value specified. The returned References do indicate the direction the Server followed in the isForward parameter of the ReferenceDescription. Symmetric References are always considered to be in forward direction therefore the isForward flag is always set to TRUE and symmetric References are not returned if browseDirection is set to INVERSE_1.           |
|       referenceTypeId | NodeId | Specifies the NodeId of the ReferenceType to follow. Only instances of this ReferenceType or its subtypes are returned. If not specified then all References are returned and includeSubtypes is ignored. |
|       includeSubtypes | Boolean | Indicates whether subtypes of the ReferenceType should be included in the browse. If TRUE, then instances of referenceTypeId and all of its subtypes are returned. |
|       nodeClassMask | UInt32 | Specifies the NodeClasses of the TargetNodes. Only TargetNodes with the selected NodeClasses are returned. The NodeClasses are assigned the following bits:    Bit   NodeClass    0   Object    1   Variable    2   Method    3   ObjectType    4   VariableType    5   ReferenceType    6   DataType    7   View If set to zero, then all NodeClasses are returned. If the NodeClass is unknown for a remote Node, the nodeClassMask is ignored. |
|       resultMask | UInt32 | Specifies the fields in the ReferenceDescription structure that should be returned. The fields are assigned the following bits:    Bit   Result    0   ReferenceType    1   IsForward    2   NodeClass    3   BrowseName    4   DisplayName    5   TypeDefinition The ReferenceDescription type is defined in 7.25. |

## Wireshark Response
    OpcUa Binary Protocol
    Message Type: MSG
    Chunk Type: F
    Message Size: 345
    SecureChannelId: 10
    Security Token Id: 10
    Security Sequence Number: 62
    Security RequestId: 64
    OpcUa Service : Encodeable Object
        TypeId : ExpandedNodeId
            NodeId EncodingMask: Four byte encoded Numeric (0x01)
            NodeId Namespace Index: 0
            NodeId Identifier Numeric: BrowseResponse (530)
        BrowseResponse
            ResponseHeader: ResponseHeader
                Timestamp: Nov 23, 2021 10:57:43.634303000 W. Europe Standard Time
                RequestHandle: 1000063
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
            Results: Array of BrowseResult
                ArraySize: 1
                [0]: BrowseResult
                    StatusCode: 0x00000000 [Good]
                    ContinuationPoint: <MISSING>[OpcUa Null ByteString]
                    References: Array of ReferenceDescription
                        ArraySize: 5
                        [0]: ReferenceDescription
                            ReferenceTypeId: NodeId
                                .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                Identifier Numeric: 40
                            IsForward: True
                            NodeId: ExpandedNodeId
                                EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Identifier Numeric: 61
                            BrowseName: QualifiedName
                                Id: 0
                                Name: FolderType
                            DisplayName: LocalizedText
                                EncodingMask: 0x03, has locale information, has text
                                    .... ...1 = has locale information: True
                                    .... ..1. = has text: True
                                Locale: [OpcUa Empty String]
                                Text: FolderType
                            NodeClass: ObjectType (0x00000008)
                            TypeDefinition: ExpandedNodeId
                                EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Identifier Numeric: 0
                        [1]: ReferenceDescription
                            ReferenceTypeId: NodeId
                                .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                Identifier Numeric: 35
                            IsForward: True
                            NodeId: ExpandedNodeId
                                EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric
                                    .... 0001 = EncodingMask: Four byte encoded Numeric (0x1)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 0
                                Identifier Numeric: 23470
                            BrowseName: QualifiedName
                                Id: 0
                                Name: Aliases
                            DisplayName: LocalizedText
                                EncodingMask: 0x03, has locale information, has text
                                    .... ...1 = has locale information: True
                                    .... ..1. = has text: True
                                Locale: [OpcUa Empty String]
                                Text: Aliases
                            NodeClass: Object (0x00000001)
                            TypeDefinition: ExpandedNodeId
                                EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric
                                    .... 0001 = EncodingMask: Four byte encoded Numeric (0x1)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 0
                                Identifier Numeric: 23456
                        [2]: ReferenceDescription
                            ReferenceTypeId: NodeId
                                .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                Identifier Numeric: 35
                            IsForward: True
                            NodeId: ExpandedNodeId
                                EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric
                                    .... 0001 = EncodingMask: Four byte encoded Numeric (0x1)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 0
                                Identifier Numeric: 2253
                            BrowseName: QualifiedName
                                Id: 0
                                Name: Server
                            DisplayName: LocalizedText
                                EncodingMask: 0x03, has locale information, has text
                                    .... ...1 = has locale information: True
                                    .... ..1. = has text: True
                                Locale: [OpcUa Empty String]
                                Text: Server
                            NodeClass: Object (0x00000001)
                            TypeDefinition: ExpandedNodeId
                                EncodingMask: 0x01, EncodingMask: Four byte encoded Numeric
                                    .... 0001 = EncodingMask: Four byte encoded Numeric (0x1)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 0
                                Identifier Numeric: 2004
                        [3]: ReferenceDescription
                            ReferenceTypeId: NodeId
                                .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                Identifier Numeric: 35
                            IsForward: True
                            NodeId: ExpandedNodeId
                                EncodingMask: 0x03, EncodingMask: String
                                    .... 0011 = EncodingMask: String (0x3)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 1
                                Identifier String: the.answer
                            BrowseName: QualifiedName
                                Id: 1
                                Name: the answer
                            DisplayName: LocalizedText
                                EncodingMask: 0x03, has locale information, has text
                                    .... ...1 = has locale information: True
                                    .... ..1. = has text: True
                                Locale: en-US
                                Text: the answer
                            NodeClass: Variable (0x00000002)
                            TypeDefinition: ExpandedNodeId
                                EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Identifier Numeric: 63
                        [4]: ReferenceDescription
                            ReferenceTypeId: NodeId
                                .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                Identifier Numeric: 35
                            IsForward: True
                            NodeId: ExpandedNodeId
                                EncodingMask: 0x03, EncodingMask: String
                                    .... 0011 = EncodingMask: String (0x3)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Namespace Index: 1
                                Identifier String: double.matrix
                            BrowseName: QualifiedName
                                Id: 1
                                Name: double matrix
                            DisplayName: LocalizedText
                                EncodingMask: 0x03, has locale information, has text
                                    .... ...1 = has locale information: True
                                    .... ..1. = has text: True
                                Locale: en-US
                                Text: Double Matrix
                            NodeClass: Variable (0x00000002)
                            TypeDefinition: ExpandedNodeId
                                EncodingMask: 0x00, EncodingMask: Two byte encoded Numeric
                                    .... 0000 = EncodingMask: Two byte encoded Numeric (0x0)
                                    .0.. .... = has server index: False
                                    0... .... = has namespace uri: False
                                Identifier Numeric: 63
            DiagnosticInfos: Array of DiagnosticInfo
                ArraySize: -1

## Response parameters
| **Name** | **Type** | **Description** |
|:---:|:---:|:---:|
|  responseHeader | Response Header | Common response parameters (see 7.29 for ResponseHeader definition). |
|    results [] | BrowseResult | A list of BrowseResults. The size and order of the list matches the size and order of the nodesToBrowse specified in the request. The BrowseResult type is defined in 7.3. |
|    diagnosticInfos [] | Diagnostic Info | List of diagnostic information for the results (see 7.8 for DiagnosticInfo definition). The size and order of the list matches the size and order of the results  response parameter. This list is empty if diagnostics information was  not requested in the request header or if no diagnostic information was  encountered in processing of the request. |

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
| Bad_NodeIdInvalid | See Table 178 for the description of this result code. |
| Bad_NodeIdUnknown | See Table 178 for the description of this result code. |
| Bad_ReferenceTypeIdInvalid | See Table 178 for the description of this result code. |
| Bad_BrowseDirectionInvalid | See Table 178 for the description of this result code. |
| Bad_NodeNotInView | See Table 178 for the description of this result code. |
| Bad_NoContinuationPoints | See Table 178 for the description of this result code. |
| Uncertain_NotAllNodesAvailable | Browse results may be incomplete because of the unavailability of a subsystem. |