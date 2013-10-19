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
# * File Name : formats/S1AP.py
# * Created : 2013-09-26
# * Authors : Benoit Michau
# *-
#!/usr/bin/env python

# exporting
__all__ = ['GlobalENBID', 'SupportedTAs', 'PagingDRX', 
           'S1AP_PDU', 'S1AP_HDR', 'S1AP_IE',
           ]


# This is a naive and quick implementation of the S1AP protocol:
# This is firstly developped to interoperate with the lteenb application
# from amarisoft (F. Bellard SDR LTE implementation)
#
# message formatting is taken from TS 36.413 11.2.0
 
from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show
from libmich.core.IANA_dict import IANA_dict
#from libmich.formats.L3Mobile import parse_L3
from libmich.formats.L3Mobile_IE import PLMN
#
from binascii import *


Type_dict = {
    0x00 : 'InitiatingMessage',
    0x20 : 'SuccessfulOutcome',
    0x40 : 'UnsuccessfulOutcome',
    }

Critic_dict = IANA_dict({
    0x00 : 'reject',
    0x40 : 'ignore',
    })

ProcedureCode_dict = IANA_dict({
     0 : "id-HandoverPreparation",
     1 : "id-HandoverResourceAllocation",
     2 : "id-HandoverNotification",
     3 : "id-PathSwitchRequest",
     4 : "id-HandoverCancel",
     5 : "id-E-RABSetup",
     6 : "id-E-RABModify",
     7 : "id-E-RABRelease",
     8 : "id-E-RABReleaseIndication",
     9 : "id-InitialContextSetup",
    10 : "id-Paging",
    11 : "id-downlinkNASTransport",
    12 : "id-initialUEMessage",
    13 : "id-uplinkNASTransport",
    14 : "id-Reset",
    15 : "id-ErrorIndication",
    16 : "id-NASNonDeliveryIndication",
    17 : "id-S1Setup",
    18 : "id-UEContextReleaseRequest",
    19 : "id-DownlinkS1cdma2000tunneling",
    20 : "id-UplinkS1cdma2000tunneling",
    21 : "id-UEContextModification",
    22 : "id-UECapabilityInfoIndication",
    23 : "id-UEContextRelease",
    24 : "id-eNBStatusTransfer",
    25 : "id-MMEStatusTransfer",
    26 : "id-DeactivateTrace",
    27 : "id-TraceStart",
    28 : "id-TraceFailureIndication",
    29 : "id-ENBConfigurationUpdate",
    30 : "id-MMEConfigurationUpdate",
    31 : "id-LocationReportingControl",
    32 : "id-LocationReportingFailureIndication",
    33 : "id-LocationReport",
    34 : "id-OverloadStart",
    35 : "id-OverloadStop",
    36 : "id-WriteReplaceWarning",
    37 : "id-eNBDirectInformationTransfer",
    38 : "id-MMEDirectInformationTransfer",
    39 : "id-PrivateMessage",
    40 : "id-eNBConfigurationTransfer",
    41 : "id-MMEConfigurationTransfer",
    42 : "id-CellTrafficTrace",
    43 : "id-Kill",
    44 : "id-downlinkUEAssociatedLPPaTransport",
    45 : "id-uplinkUEAssociatedLPPaTransport",
    46 : "id-downlinkNonUEAssociatedLPPaTransport",
    47 : "id-uplinkNonUEAssociatedLPPaTransport",
    48 : "id-UERadioCapabilityMatch",
    })

IE_dict = IANA_dict({
     0 : "id-MME-UE-S1AP-ID",
     1 : "id-HandoverType",
     2 : "id-Cause",
     3 : "id-SourceID",
     4 : "id-TargetID",
     8 : "id-eNB-UE-S1AP-ID",
    12 : "id-E-RABSubjecttoDataForwardingList",
    13 : "id-E-RABtoReleaseListHOCmd",
    14 : "id-E-RABDataForwardingItem",
    15 : "id-E-RABReleaseItemBearerRelComp",
    16 : "id-E-RABToBeSetupListBearerSUReq",
    17 : "id-E-RABToBeSetupItemBearerSUReq",
    18 : "id-E-RABAdmittedList",
    19 : "id-E-RABFailedToSetupListHOReqAck",
    20 : "id-E-RABAdmittedItem",
    21 : "id-E-RABFailedtoSetupItemHOReqAck",
    22 : "id-E-RABToBeSwitchedDLList",
    23 : "id-E-RABToBeSwitchedDLItem",
    24 : "id-E-RABToBeSetupListCtxtSUReq",
    25 : "id-TraceActivation",
    26 : "id-NAS-PDU",
    27 : "id-E-RABToBeSetupItemHOReq",
    28 : "id-E-RABSetupListBearerSURes",
    29 : "id-E-RABFailedToSetupListBearerSURes",
    30 : "id-E-RABToBeModifiedListBearerModReq",
    31 : "id-E-RABModifyListBearerModRes",
    32 : "id-E-RABFailedToModifyList",
    33 : "id-E-RABToBeReleasedList",
    34 : "id-E-RABFailedToReleaseList",
    35 : "id-E-RABItem",
    36 : "id-E-RABToBeModifiedItemBearerModReq",
    37 : "id-E-RABModifyItemBearerModRes",
    38 : "id-E-RABReleaseItem",
    39 : "id-E-RABSetupItemBearerSURes",
    40 : "id-SecurityContext",
    41 : "id-HandoverRestrictionList",
    43 : "id-UEPagingID",
    44 : "id-pagingDRX",
    46 : "id-TAIList",
    47 : "id-TAIItem",
    48 : "id-E-RABFailedToSetupListCtxtSURes",
    49 : "id-E-RABReleaseItemHOCmd",
    50 : "id-E-RABSetupItemCtxtSURes",
    51 : "id-E-RABSetupListCtxtSURes",
    52 : "id-E-RABToBeSetupItemCtxtSUReq",
    53 : "id-E-RABToBeSetupListHOReq",
    55 : "id-GERANtoLTEHOInformationRes",
    57 : "id-UTRANtoLTEHOInformationRes",
    58 : "id-CriticalityDiagnostics",
    59 : "id-Global-ENB-ID",
    60 : "id-eNBname",
    61 : "id-MMEname",
    63 : "id-ServedPLMNs",
    64 : "id-SupportedTAs",
    65 : "id-TimeToWait",
    66 : "id-uEaggregateMaximumBitrate",
    67 : "id-TAI",
    69 : "id-E-RABReleaseListBearerRelComp",
    70 : "id-cdma2000PDU",
    71 : "id-cdma2000RATType",
    72 : "id-cdma2000SectorID",
    73 : "id-SecurityKey",
    74 : "id-UERadioCapability",
    75 : "id-GUMMEI-ID",
    78 : "id-E-RABInformationListItem",
    79 : "id-Direct-Forwarding-Path-Availability",
    80 : "id-UEIdentityIndexValue",
    83 : "id-cdma2000HOStatus",
    84 : "id-cdma2000HORequiredIndication",
    86 : "id-E-UTRAN-Trace-ID",
    87 : "id-RelativeMMECapacity",
    88 : "id-SourceMME-UE-S1AP-ID",
    89 : "id-Bearers-SubjectToStatusTransfer-Item",
    90 : "id-eNB-StatusTransfer-TransparentContainer",
    91 : "id-UE-associatedLogicalS1-ConnectionItem",
    92 : "id-ResetType",
    93 : "id-UE-associatedLogicalS1-ConnectionListResAck",
    94 : "id-E-RABToBeSwitchedULItem",
    95 : "id-E-RABToBeSwitchedULList",
    96 : "id-S-TMSI",
    97 : "id-cdma2000OneXRAND",
    98 : "id-RequestType",
    99 : "id-UE-S1AP-IDs",
    100 : "id-EUTRAN-CGI",
    101 : "id-OverloadResponse",
    102 : "id-cdma2000OneXSRVCCInfo",
    103 : "id-E-RABFailedToBeReleasedList",
    104 : "id-Source-ToTarget-TransparentContainer",
    105 : "id-ServedGUMMEIs",
    106 : "id-SubscriberProfileIDforRFP",
    107 : "id-UESecurityCapabilities",
    108 : "id-CSFallbackIndicator",
    109 : "id-CNDomain",
    110 : "id-E-RABReleasedList",
    111 : "id-MessageIdentifier",
    112 : "id-SerialNumber",
    113 : "id-WarningAreaList",
    114 : "id-RepetitionPeriod",
    115 : "id-NumberofBroadcastRequest",
    116 : "id-WarningType",
    117 : "id-WarningSecurityInfo",
    118 : "id-DataCodingScheme",
    119 : "id-WarningMessageContents",
    120 : "id-BroadcastCompletedAreaList",
    121 : "id-Inter-SystemInformationTransferTypeEDT",
    122 : "id-Inter-SystemInformationTransferTypeMDT",
    123 : "id-Target-ToSource-TransparentContainer",
    124 : "id-SRVCCOperationPossible",
    125 : "id-SRVCCHOIndication",
    126 : "id-NAS-DownlinkCount",
    127 : "id-CSG-Id",
    128 : "id-CSG-IdList",
    129 : "id-SONConfigurationTransferECT",
    130 : "id-SONConfigurationTransferMCT",
    131 : "id-TraceCollectionEntityIPAddress",
    132 : "id-MSClassmark2",
    133 : "id-MSClassmark3",
    134 : "id-RRC-Establishment-Cause",
    135 : "id-NASSecurityParametersfromE-UTRAN",
    136 : "id-NASSecurityParameterstoE-UTRAN",
    137 : "id-DefaultPagingDRX",
    138 : "id-Source-ToTarget-TransparentContainer-Secondary",
    139 : "id-Target-ToSource-TransparentContainer-Secondary",
    140 : "id-EUTRANRoundTripDelayEstimationInfo",
    141 : "id-BroadcastCancelledAreaList",
    142 : "id-ConcurrentWarningMessageIndicator",
    143 : "id-Data-Forwarding-Not-Possible",
    144 : "id-ExtendedRepetitionPeriod",
    145 : "id-CellAccessMode",
    146 : "id-CSGMembershipStatus",
    147 : "id-LPPa-PDU",
    148 : "id-Routing-ID",
    149 : "id-Time-Synchronization-Info",
    150 : "id-PS-ServiceNotAvailable",
    151 : "id-PagingPriority",
    152 : "id-x2TNLConfigurationInfo",
    153 : "id-eNBX2ExtendedTransportLayerAddresses",
    154 : "id-GUMMEIList",
    155 : "id-GW-TransportLayerAddress",
    156 : "id-Correlation-ID",
    157 : "id-SourceMME-GUMMEI",
    158 : "id-MME-UE-S1AP-ID-2",
    159 : "id-RegisteredLAI",
    160 : "id-RelayNode-Indicator",
    161 : "id-TrafficLoadReductionIndication",
    162 : "id-MDTConfiguration",
    163 : "id-MMERelaySupportIndicator",
    164 : "id-GWContextReleaseIndication",
    165 : "id-ManagementBasedMDTAllowed",
    166 : "id-PrivacyIndicator",
    167 : "id-Time-UE-StayedInCell-EnhancedGranularity",
    168 : "id-HO-Cause",
    169 : "id-VoiceSupportMatchIndicator",
    170 : "id-GUMMEIType",
    171 : "id-M3Configuration",
    172 : "id-M4Configuration",
    173 : "id-M5Configuration",
    174 : "id-MDT-Location-Info",
    175 : "id-MobilityInformation",
    176 : "id-Tunnel-Information-for-BBF",
    177 : "id-ManagementBasedMDTPLMNList",
    178 : "id-SignallingBasedMDTPLMNList",
    })

###
# some common S1AP IE
#
# 9.2.1.37
class GlobalENBID(Layer):
    _byte_aligned = False
    constructorList = [
        Int('F_PLMN', Type='uint8', Repr='hex'),
        PLMN(),
        Int('F_eNBID', Type='uint8', Repr='hex'),
        Bit('eNBID', BitLen=20, Repr='hum'),
        Bit('pad', BitLen=4, Repr='hex'),
        ]

# 9.1.8.4, WNG: this is not correctly coded...
class SupportedTAs(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('pad', BitLen=10, Repr='bin'),
        Bit('TAC', BitLen=16, Repr='hum'),
        Bit('F_PLMN', BitLen=6, Repr='bin'),
        PLMN(),
        ]

# 9.2.1.16
PagingDRX_dict = {
    0 : '32',
    1 : '64',
    2 : '128',
    3 : '256',
    } 
class PagingDRX(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('PagingDRX', BitLen=3, Repr='hum', Dict=PagingDRX_dict),
        Bit('pad', BitLen=5),
        ]

###
# S1AP Packet Data Unit
#
class S1AP_PDU(Block):
    
    # IE that we want to interpret more deeply when parsing a PDU
    IE = {
        59 : GlobalENBID,
        64 : SupportedTAs,
        137 : PagingDRX,
        }
    
    def __init__(self, **kwargs):
        Block.__init__(self, 'S1AP')
        self.append( S1AP_HDR(**kwargs) )
    
    def __lt__(self, newLayer):
        # to use when appending a payload with hierarchy 1, 
        # typical for S1AP_IE over S1AP_HDR
        self.append(newLayer)
        self[-1].hierarchy = self[0].hierarchy + 1
    
    def parse(self, s=''):
        self.__init__()
        # parse S1AP header
        self.map(s)
        s=s[len(self[0]):]
        if self[0].length() != len(s)+3:
            print('invalid S1AP_HDR.length')
            s = s[:self[0].length()-3]
        # parse S1AP IE iteratively
        while len(s) > 0:
            self < S1AP_IE()
            self[-1].map(s)
            s = s[len(self[-1]):]
        # interpret some more S1AP IE
        for ie in self[1:]:
            ident, val = ie.id(), ie.value()
            if ident in self.IE:
                ie_content = self.IE[ident]()
                ie_content.parse(val)
                if ie_content.bit_len() == len(val)*8:
                    ie.value < None
                    ie.value > ie_content
                    ie.value.Repr = 'hum'
                    ie._interpreted = True

###
# S1AP Header
#
# for length > 0x7F
# ASN.1 BASIC PER aligned encoding rule is applied
#
class S1AP_HDR(Layer):
    _byte_aligned = False
    constructorList = [
        Int('type', Pt=0, Type='uint8', Dict=Type_dict),
        Int('procedureCode', Pt=0, Type='uint8', Dict=ProcedureCode_dict),
        Int('criticality', Pt=0, Type='uint8', Dict=Critic_dict),
        Bit('l_ext', BitLen=1),
        Bit('length', BitLen=7, Repr='hum'),
        Int('protocolIEs', Type='uint24'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # trigger extension bits and adapt consequently length' BitLen attribute
        self.l_ext.Pt = self.get_payload
        self.l_ext.PtFunc = lambda p: 1 if len(p())+3 > 127 else 0
        self.length.BitLen = self.l_ext
        self.length.BitLenFunc = lambda e: 15 if e() else 7
        self.length.Pt = self.get_payload
        self.length.PtFunc = lambda p: len(p())+3
        self.protocolIEs.Pt = self.get_payload
        self.protocolIEs.PtFunc = lambda p: p().num() if len(p()) != 0 else 0

###
# S1AP Information Element
#

class S1AP_IE(Layer):
    _byte_aligned = False
    constructorList = [
        Int('id', Pt=0, Type='uint16', Dict=IE_dict),
        Int('criticality', Pt=0, Type='uint8', Dict=Critic_dict),
        Bit('l_ext', BitLen=1),
        Bit('length', BitLen=7, Repr='hum'),
        Str('value', Pt='', Repr='hex'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # trigger extension bits and adapt consequently id's BitLen attribute
        self.l_ext.Pt = self.value
        self.l_ext.PtFunc = lambda v: 1 if len(v) > 127 else 0
        self.length.BitLen = self.l_ext
        self.length.BitLenFunc = lambda e: 15 if e() else 7
        self.length.Pt = self.value
        self.length.PtFunc = lambda v: len(v)
        self.value.Len = self.length
        self.value.LenFunc = lambda l: int(l)
        # indicator to tell if IE content is interpreted
        self._interpreted = False


