# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.2.2
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details.
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : formats/RANAP.py
# * Created : 2013-01-03
# * Authors : Benoit Michau
# *-
#!/usr/bin/env python

###
# the format provided here is very simplified compared to the real RANAP.
# Fields' length do not always correspond to TS 25.413 and ASN.1 PER coding,
# however, this seems to work well against wireshark RANAP example pcap
# http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=3gpp_mc.cap
#

from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.L3Mobile import parse_L3

# some fixed values from TS 25.413 ASN.1 description
ElementProc_dict = IANA_dict({
    0 : 'id-RAB-Assignment',
    1 : 'id-Iu-Release',
    2 : 'id-RelocationPreparation',
    3 : 'id-RelocationResourceAllocation',
    4 : 'id-RelocationCancel',
    5 : 'id-SRNS-ContextTransfer',
    6 : 'id-SecurityModeControl',
    7 : 'id-DataVolumeReport',
    9 : 'id-Reset',
    10 : 'id-RAB-ReleaseRequest',
    11 : 'id-Iu-ReleaseRequest',
    12 : 'id-RelocationDetect',
    13 : 'id-RelocationComplete',
    14 : 'id-Paging',
    15 : 'id-CommonID',
    16 : 'id-CN-InvokeTrace',
    17 : 'id-LocationReportingControl',
    18 : 'id-LocationReport',
    19 : 'id-InitialUE-Message',
    20 : 'id-DirectTransfer',
    21 : 'id-OverloadControl',
    22 : 'id-ErrorIndication',
    23 : 'id-SRNS-DataForward',
    24 : 'id-ForwardSRNS-Context',
    25 : 'id-privateMessage',
    26 : 'id-CN-DeactivateTrace',
    27 : 'id-ResetResource',
    28 : 'id-RANAP-Relocation',
    29 : 'id-RAB-ModifyRequest',
    30 : 'id-LocationRelatedData',
    31 : 'id-InformationTransfer',
    32 : 'id-UESpecificInformation',
    33 : 'id-UplinkInformationExchange',
    34 : 'id-DirectInformationTransfer',
    35 : 'id-MBMSSessionStart',
    36 : 'id-MBMSSessionUpdate',
    37 : 'id-MBMSSessionStop',
    38 : 'id-MBMSUELinking',
    39 : 'id-MBMSRegistration',
    40 : 'id-MBMSCNDe-Registration-Procedure',
    41 : 'id-MBMSRABEstablishmentIndication',
    42 : 'id-MBMSRABRelease',
    43 : 'id-enhancedRelocationComplete',
    44 : 'id-enhancedRelocationCompleteConfirm',
    45 : 'id-RANAPenhancedRelocation',
    46 : 'id-SRVCCPreparation',
    })

IE_dict = IANA_dict({
    0 : "id-AreaIdentity",
    3 : "id-CN-DomainIndicator",
    4 : "id-Cause",
    5 : "id-ChosenEncryptionAlgorithm",
    6 : "id-ChosenIntegrityProtectionAlgorithm",
    7 : "id-ClassmarkInformation2",
    8 : "id-ClassmarkInformation3",
    9 : "id-CriticalityDiagnostics",
    10 : "id-DL-GTP-PDU-SequenceNumber",
    11 : "id-EncryptionInformation",
    12 : "id-IntegrityProtectionInformation",
    13 : "id-IuTransportAssociation",
    14 : "id-L3-Information",
    15 : "id-LAI",
    16 : "id-NAS-PDU",
    17 : "id-NonSearchingIndication",
    18 : "id-NumberOfSteps",
    19 : "id-OMC-ID",
    20 : "id-OldBSS-ToNewBSS-Information",
    21 : "id-PagingAreaID",
    22 : "id-PagingCause",
    23 : "id-PermanentNAS-UE-ID",
    24 : "id-RAB-ContextItem",
    25 : "id-RAB-ContextList",
    26 : "id-RAB-DataForwardingItem",
    27 : "id-RAB-DataForwardingItem-SRNS-CtxReq",
    28 : "id-RAB-DataForwardingList",
    29 : "id-RAB-DataForwardingList-SRNS-CtxReq",
    30 : "id-RAB-DataVolumeReportItem",
    31 : "id-RAB-DataVolumeReportList",
    32 : "id-RAB-DataVolumeReportRequestItem",
    33 : "id-RAB-DataVolumeReportRequestList",
    34 : "id-RAB-FailedItem",
    35 : "id-RAB-FailedList",
    36 : "id-RAB-ID",
    37 : "id-RAB-QueuedItem",
    38 : "id-RAB-QueuedList",
    39 : "id-RAB-ReleaseFailedList",
    40 : "id-RAB-ReleaseItem",
    41 : "id-RAB-ReleaseList",
    42 : "id-RAB-ReleasedItem",
    43 : "id-RAB-ReleasedList",
    44 : "id-RAB-ReleasedList-IuRelComp",
    45 : "id-RAB-RelocationReleaseItem",
    46 : "id-RAB-RelocationReleaseList",
    47 : "id-RAB-SetupItem-RelocReq",
    48 : "id-RAB-SetupItem-RelocReqAck",
    49 : "id-RAB-SetupList-RelocReq",
    50 : "id-RAB-SetupList-RelocReqAck",
    51 : "id-RAB-SetupOrModifiedItem",
    52 : "id-RAB-SetupOrModifiedList",
    53 : "id-RAB-SetupOrModifyItem",
    54 : "id-RAB-SetupOrModifyList",
    55 : "id-RAC",
    56 : "id-RelocationType",
    57 : "id-RequestType",
    58 : "id-SAI",
    59 : "id-SAPI",
    60 : "id-SourceID",
    61 : "id-Source-ToTarget-TransparentContainer",
    62 : "id-TargetID",
    63 : "id-Target-ToSource-TransparentContainer",
    64 : "id-TemporaryUE-ID",
    65 : "id-TraceReference",
    66 : "id-TraceType",
    67 : "id-TransportLayerAddress",
    68 : "id-TriggerID",
    69 : "id-UE-ID",
    70 : "id-UL-GTP-PDU-SequenceNumber",
    71 : "id-RAB-FailedtoReportItem",
    72 : "id-RAB-FailedtoReportList",
    75 : "id-KeyStatus",
    76 : "id-DRX-CycleLengthCoefficient",
    77 : "id-IuSigConIdList",
    78 : "id-IuSigConIdItem",
    79 : "id-IuSigConId",
    80 : "id-DirectTransferInformationItem-RANAP-RelocInf",
    81 : "id-DirectTransferInformationList-RANAP-RelocInf",
    82 : "id-RAB-ContextItem-RANAP-RelocInf",
    83 : "id-RAB-ContextList-RANAP-RelocInf",
    84 : "id-RAB-ContextFailedtoTransferItem",
    85 : "id-RAB-ContextFailedtoTransferList",
    86 : "id-GlobalRNC-ID",
    87 : "id-RAB-ReleasedItem-IuRelComp",
    88 : "id-MessageStructure",
    89 : "id-Alt-RAB-Parameters",
    90 : "id-Ass-RAB-Parameters",
    91 : "id-RAB-ModifyList",
    92 : "id-RAB-ModifyItem",
    93 : "id-TypeOfError",
    94 : "id-BroadcastAssistanceDataDecipheringKeys",
    95 : "id-LocationRelatedDataRequestType",
    96 : "id-GlobalCN-ID",
    97 : "id-LastKnownServiceArea",
    98 : "id-SRB-TrCH-Mapping",
    99 : "id-InterSystemInformation-TransparentContainer",
    100 : "id-NewBSS-To-OldBSS-Information",
    103 : "id-SourceRNC-PDCP-context-info",
    104 : "id-InformationTransferID",
    105 : "id-SNA-Access-Information",
    106 : "id-ProvidedData",
    107 : "id-GERAN-BSC-Container",
    108 : "id-GERAN-Classmark",
    109 : "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item",
    110 : "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse",
    111 : "id-VerticalAccuracyCode",
    112 : "id-ResponseTime",
    113 : "id-PositioningPriority",
    114 : "id-ClientType",
    115 : "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode",
    116 : "id-SignallingIndication",
    117 : "id-hS-DSCH-MAC-d-Flow-ID",
    118 : "id-UESBI-Iu",
    119 : "id-PositionData",
    120 : "id-PositionDataSpecificToGERANIuMode",
    121 : "id-CellLoadInformationGroup",
    122 : "id-AccuracyFulfilmentIndicator",
    123 : "id-InformationTransferType",
    124 : "id-TraceRecordingSessionInformation",
    125 : "id-TracePropagationParameters",
    126 : "id-InterSystemInformationTransferType",
    127 : "id-SelectedPLMN-ID",
    128 : "id-RedirectionCompleted",
    129 : "id-RedirectionIndication",
    130 : "id-NAS-SequenceNumber",
    131 : "id-RejectCauseValue",
    132 : "id-APN",
    133 : "id-CNMBMSLinkingInformation",
    134 : "id-DeltaRAListofIdleModeUEs",
    135 : "id-FrequenceLayerConvergenceFlag",
    136 : "id-InformationExchangeID",
    137 : "id-InformationExchangeType",
    138 : "id-InformationRequested",
    139 : "id-InformationRequestType",
    140 : "id-IPMulticastAddress",
    141 : "id-JoinedMBMSBearerServicesList",
    142 : "id-LeftMBMSBearerServicesList",
    143 : "id-MBMSBearerServiceType",
    144 : "id-MBMSCNDe-Registration",
    145 : "id-MBMSServiceArea",
    146 : "id-MBMSSessionDuration",
    147 : "id-MBMSSessionIdentity",
    148 : "id-PDP-TypeInformation",
    149 : "id-RAB-Parameters",
    150 : "id-RAListofIdleModeUEs",
    151 : "id-MBMSRegistrationRequestType",
    152 : "id-SessionUpdateID",
    153 : "id-TMGI",
    154 : "id-TransportLayerInformation",
    155 : "id-UnsuccessfulLinkingList",
    156 : "id-MBMSLinkingInformation",
    157 : "id-MBMSSessionRepetitionNumber",
    158 : "id-AlternativeRABConfiguration",
    159 : "id-AlternativeRABConfigurationRequest",
    160 : "id-E-DCH-MAC-d-Flow-ID",
    161 : "id-SourceBSS-ToTargetBSS-TransparentContainer",
    162 : "id-TargetBSS-ToSourceBSS-TransparentContainer",
    163 : "id-TimeToMBMSDataTransfer",
    164 : "id-IncludeVelocity",
    165 : "id-VelocityEstimate",
    166 : "id-RedirectAttemptFlag",
    167 : "id-RAT-Type",
    168 : "id-PeriodicLocationInfo",
    169 : "id-MBMSCountingInformation",
    170 : "id-170-not-to-be-used-for-IE-ids",
    171 : "id-ExtendedRNC-ID",
    172 : "id-Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf",
    173 : "id-Alt-RAB-Parameter-ExtendedMaxBitrateInf",
    174 : "id-Ass-RAB-Parameter-ExtendedGuaranteedBitrateList",
    175 : "id-Ass-RAB-Parameter-ExtendedMaxBitrateList",
    176 : "id-RAB-Parameter-ExtendedGuaranteedBitrateList",
    177 : "id-RAB-Parameter-ExtendedMaxBitrateList",
    178 : "id-Requested-RAB-Parameter-ExtendedMaxBitrateList",
    179 : "id-Requested-RAB-Parameter-ExtendedGuaranteedBitrateList",
    180 : "id-LAofIdleModeUEs",
    181 : "id-newLAListofIdleModeUEs",
    182 : "id-LAListwithNoIdleModeUEsAnyMore",
    183 : "id-183-not-to-be-used-for-IE-ids",
    184 : "id-GANSS-PositioningDataSet",
    185 : "id-RequestedGANSSAssistanceData",
    186 : "id-BroadcastGANSSAssistanceDataDecipheringKeys",
    187 : "id-d-RNTI-for-NoIuCSUP",
    188 : "id-RAB-SetupList-EnhancedRelocCompleteReq",
    189 : "id-RAB-SetupItem-EnhancedRelocCompleteReq",
    190 : "id-RAB-SetupList-EnhancedRelocCompleteRes",
    191 : "id-RAB-SetupItem-EnhancedRelocCompleteRes",
    192 : "id-RAB-SetupList-EnhRelocInfoReq",
    193 : "id-RAB-SetupItem-EnhRelocInfoReq",
    194 : "id-RAB-SetupList-EnhRelocInfoRes",
    195 : "id-RAB-SetupItem-EnhRelocInfoRes",
    196 : "id-OldIuSigConId",
    197 : "id-RAB-FailedList-EnhRelocInfoRes",
    198 : "id-RAB-FailedItem-EnhRelocInfoRes",
    199 : "id-Global-ENB-ID",
    200 : "id-UE-History-Information",
    201 : "id-MBMSSynchronisationInformation",
    202 : "id-SubscriberProfileIDforRFP",
    203 : "id-CSG-Id",
    204 : "id-OldIuSigConIdCS",
    205 : "id-OldIuSigConIdPS",
    206 : "id-GlobalCN-IDCS",
    207 : "id-GlobalCN-IDPS",
    208 : "id-SourceExtendedRNC-ID",
    209 : "id-RAB-ToBeReleasedItem-EnhancedRelocCompleteRes",
    210 : "id-RAB-ToBeReleasedList-EnhancedRelocCompleteRes",
    211 : "id-SourceRNC-ID",
    212 : "id-Relocation-TargetRNC-ID",
    213 : "id-Relocation-TargetExtendedRNC-ID",
    214 : "id-Alt-RAB-Parameter-SupportedGuaranteedBitrateInf",
    215 : "id-Alt-RAB-Parameter-SupportedMaxBitrateInf",
    216 : "id-Ass-RAB-Parameter-SupportedGuaranteedBitrateList",
    217 : "id-Ass-RAB-Parameter-SupportedMaxBitrateList",
    218 : "id-RAB-Parameter-SupportedGuaranteedBitrateList",
    219 : "id-RAB-Parameter-SupportedMaxBitrateList",
    220 : "id-Requested-RAB-Parameter-SupportedMaxBitrateList",
    221 : "id-Requested-RAB-Parameter-SupportedGuaranteedBitrateList",
    222 : "id-Relocation-SourceRNC-ID",
    223 : "id-Relocation-SourceExtendedRNC-ID",
    224 : "id-EncryptionKey",
    225 : "id-IntegrityProtectionKey",
    226 : "id-SRVCC-HO-Indication",
    227 : "id-SRVCC-Information",
    228 : "id-SRVCC-Operation-Possible",
    229 : "id-CSG-Id-List",
    230 : "id-PSRABtobeReplaced",
    231 : "id-E-UTRAN-Service-Handover",
    236 : "id-IP-Source-Address",
    })

Critic_dict = IANA_dict({
    0x40 : 'ignore',
    })

# RANAP Packet Data Unit
class PDU(Block):
    
    def __init__(self):
        Block.__init__(self, 'RANAP')
        self.append(PDU_HDR())
    
    def parse(self, s=''):
        self.__init__()
        self.map(s)
        s=s[len(self[0]):]
        if self[0].length() != len(s)+4:
            #print('invalid PDU_HDR.length')
            s = s[:self[0].length()-4]
        while len(s) > 0:
            self.append(IE())
            self[-1].hierarchy = self[0].hierarchy + 1
            self[-1].map(s)
            s = s[len(self[-1]):]

# RANAP header
class PDU_HDR(Layer):
    constructorList = [
        Int('procedureCode', Type='uint16', Dict=ElementProc_dict),
        Int('criticality', Type='uint8', Dict=Critic_dict),
        Int('length', Type='uint8'),
        Int('items', Type='uint24'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.get_payload
        self.length.PtFunc = lambda pay: len(pay())+4

# RANAP information element
class IE(Layer):
    constructorList = [
        Int('id', Type='uint16', Dict=IE_dict),
        Int('criticality', Type='uint8', Dict=Critic_dict),
        Int('length', Type='uint8'),
        Str('value', Pt='', Repr='hex'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.value
        self.length.PtFunc = lambda v: len(v)
        self.value.Len = self.length
        self.value.LenFunc = lambda l: int(l)
    
    def map(self, s=''):
        Layer.map(self, s)
        if self.id() == 16:
            # NAS-PDU, try to parse it
            naspdu = NAS_PDU()
            naspdu.map(self.value())
            self.value.Pt = naspdu
            self.value.Val = None
            self.value.Repr = 'hum'
            #self.remove(self.value)
            #for elt in naspdu:
            # self.append(elt)
            # update length : pointing to naspdu
            #self[2].Len = self.naspdu
            #self[2].LenFunc = lambda n: len(n)+1

# specific NAS-PDU IE, containing mobile L3 signalling
class NAS_PDU(Layer):
    constructorList = [
        Int('length', Type='uint8'),
        Str('naspdu', Repr='hex'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.naspdu
        self.length.PtFunc = lambda nas: len(nas)
        self.naspdu.Len = self.length
        self.naspdu.LenFunc = lambda l: int(l)
    
    def map(self, s=''):
        Layer.map(self, s)
        # try to parse it as L3Mobile
        try:
            nas = parse_L3(self.naspdu())
        except:
            pass
        else:
            self.naspdu.Pt = nas
            self.naspdu.Val = None
            self.naspdu.Repr = 'hum'
#
