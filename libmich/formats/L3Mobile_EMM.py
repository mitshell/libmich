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
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : formats/L3Mobile_EMM.py
# * Created : 2013-10-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# exporting
__all__ = ['EMMHeader', 'Layer3NASEMM',
           'ATTACH_REQUEST', 'ATTACH_ACCEPT',
           'ATTACH_COMPLETE', 'ATTACH_REJECT',
           'DETACH_REQUEST', 'DETACH_ACCEPT',
           'TRACKING_AREA_UPDATE_REQUEST', 'TRACKING_AREA_UPDATE_ACCEPT',
           'TRACKING_AREA_UPDATE_COMPLETE', 'TRACKING_AREA_UPDATE_REJECT',
           'SERVICE_REQUEST', 'EXTENDED_SERVICE_REQUEST', 'SERVICE_REJECT',
           'GUTI_REALLOCATION_COMMAND', 'GUTI_REALLOCATION_COMPLETE',
           'EPS_AUTHENTICATION_REQUEST', 'EPS_AUTHENTICATION_RESPONSE',
           'EPS_AUTHENTICATION_REJECT', 'EPS_AUTHENTICATION_FAILURE',
           'EPS_IDENTITY_REQUEST', 'EPS_IDENTITY_RESPONSE',
           'SECURITY_MODE_COMMAND', 'SECURITY_MODE_COMPLETE',
           'SECURITY_MODE_REJECT',
           'EMM_STATUS', 'EMM_INFORMATION',
           'DOWNLINK_NAS_TRANSPORT', 'UPLINK_NAS_TRANSPORT',
           'CS_SERVICE_NOTIFICATION',
           'DOWNLINK_GENERIC_NAS_TRANSPORT', 'UPLINK_GENERIC_NAS_TRANSPORT',
           'EMM_dict', 'EMMCause_dict'
           ]


from libmich.core.element import Element, Str, Int, Bit, Layer, RawLayer

# these are the libraries for the handling of L3 NAS msg
from .L3Mobile_24007 import Type1_TV, Type2, Type3_V, Type3_TV, Type4_LV, \
     Type4_TLV, Type6_LVE, Type6_TLVE, PD_dict, Layer3
from .L3Mobile_NAS import Layer3NAS, SecHdr_dict
#
# for handling ESM container
from .L3Mobile_ESM import *
#
# these are the libraries for IE interpretation
from .L3Mobile_IE import LAI, ID, MSCm1, MSCm2, MSCm3, PLMNList, BCDNumber, \
     NASKSI_dict
from .L3Mobile_IEdict import *

###
# TS 24.301, 11.5.0 specification
# NAS protocol for Evolved Packet System
# EMM procedures in section 5
# ESM procedures in section 6
# message function in section 8
# message format in section 9
###

# section 9.8
EMM_dict = {
    # attach / detach
    65 : "Attach request",
    66 : "Attach accept",
    67 : "Attach complete",
    68 : "Attach reject",
    69 : "Detach request",
    70 : "Detach accept",
    # TAU
    72 : "Tracking area update request",
    73 : "Tracking area update accept",
    74 : "Tracking area update complete",
    75 : "Tracking area update reject",
    # serv request
    76 : "Extended service request",
    78 : "Service reject",
    # identification / authentication
    80 : "GUTI reallocation command",
    81 : "GUTI reallocation complete",
    82 : "Authentication request",
    83 : "Authentication response",
    84 : "Authentication reject",
    92 : "Authentication failure",
    85 : "Identity request",
    86 : "Identity response",
    93 : "Security mode command",
    94 : "Security mode complete",
    95 : "Security mode reject",
    # misc
    96 : "EMM status",
    97 : "EMM information",
    98 : "Downlink NAS transport",
    99 : "Uplink NAS transport",
    100 : "CS Service notification",
    104 : "Downlink generic NAS transport",
    105 : "Uplink generic NAS transport"
    }

# section 9.9.3.9
EMMCause_dict = {
    2 : "IMSI unknown in HSS",
    3 : "Illegal UE",
    5 : "IMEI not accepted",
    6 : "Illegal ME",
    7 : "EPS services not allowed",
    8 : "EPS services and non-EPS services not allowed",
    9 : "UE identity cannot be derived by the network",
    10 : "Implicitly detached",
    11 : "PLMN not allowed",
    12 : "Tracking Area not allowed",
    13 : "Roaming not allowed in this tracking area",
    14 : "EPS services not allowed in this PLMN",
    15 : "No Suitable Cells In tracking area",
    16 : "MSC temporarily not reachable",
    17 : "Network failure",
    18 : "CS domain not available",
    19 : "ESM failure",
    20 : "MAC failure",
    21 : "Synch failure",
    22 : "Congestion",
    23 : "UE security capabilities mismatch",
    24 : "Security mode rejected, unspecified",
    25 : "Not authorized for this CSG",
    26 : "Non-EPS authentication unacceptable",
    35 : "Requested service option not authorized in this PLMN",
    39 : "CS service temporarily not available",
    40 : "No EPS bearer context activated",
    42 : "Severe network failure",
    95 : "Semantically incorrect message",
    96 : "Invalid mandatory information",
    97 : "Message type non-existent or not implemented",
    98 : "Message type not compatible with the protocol state",
    99 : "Information element non-existent or not implemented",
    100 : "Conditional IE error",
    101 : "Message not compatible with the protocol state",
    111 : "Protocol error, unspecified"
    }

###
# NAS EMM message can embed ESM message into ESMContainer
###

L3Mobile_ESM_Call = {
    193:ACTIVATE_DEFAULT_EPS_BEARER_CTX_REQUEST,
    194:ACTIVATE_DEFAULT_EPS_BEARER_CTX_ACCEPT,
    195:ACTIVATE_DEFAULT_EPS_BEARER_CTX_REJECT,
    197:ACTIVATE_DEDI_EPS_BEARER_CTX_REQUEST,
    198:ACTIVATE_DEDI_EPS_BEARER_CTX_ACCEPT,
    199:ACTIVATE_DEDI_EPS_BEARER_CTX_REJECT,
    201:MODIFY_EPS_BEARER_CTX_REQUEST,
    202:MODIFY_EPS_BEARER_CTX_ACCEPT,
    203:MODIFY_EPS_BEARER_CTX_REJECT,
    205:DEACTIVATE_EPS_BEARER_CTX_REQUEST,
    206:DEACTIVATE_EPS_BEARER_CTX_ACCEPT,
    208:PDN_CONNECTIVITY_REQUEST,
    209:PDN_CONNECTIVITY_REJECT,
    210:PDN_DISCONNECT_REQUEST,
    211:PDN_DISCONNECT_REJECT,
    212:BEARER_RESOURCE_ALLOC_REQUEST,
    213:BEARER_RESOURCE_ALLOC_REJECT,
    214:BEARER_RESOURCE_MODIF_REQUEST,
    215:BEARER_RESOURCE_MODIF_REJECT,
    217:ESM_INFORMATION_REQUEST,
    218:ESM_INFORMATION_RESPONSE,
    219:ESM_NOTIFICATION,
    232:ESM_STATUS
    }

class Layer3NASEMM(Layer3NAS):
    # this is done the dirty way...
    #
    def map(self, s=''):
        Layer3NAS.map(self, s)
        #
        # check for ESM container
        for ie in self[3:]:
            if ie.CallName == 'ESMContainer':
                cont = ie.getobj()
                if len(cont) < 3:
                    break
                # check for PD and Type references to ESM
                PD = ord(cont[0]) & 0x0F
                Type = ord(cont[2])
                if PD == 2 and Type in L3Mobile_ESM_Call:
                    esm = L3Mobile_ESM_Call[Type]()
                    esm.map(cont)
                    if str(esm) == cont:
                        ie.V < None
                        ie.V > esm

###
# NAS EMM standard header
# section 9.2
###

class EMMHeader(Layer):
    constructorList = [
        Bit('SH', ReprName='Security Header Type', Pt=0, BitLen=4, 
            Dict=SecHdr_dict, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=7, BitLen=4,
            Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=EMM_dict, Repr='hum'),
        ]

###
# NAS EMM messages
###

# section 8.2.4
class ATTACH_REQUEST(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=65)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Bit('NASKSI', ReprName='NAS Key Set Identifier', Pt=0, BitLen=4,
                Dict=NASKSI_dict, Repr='hum'),
            Bit('EPSAttType', ReprName='EPS Attach Type', Pt=1, BitLen=4, 
                Dict=EPSAttType_dict, Repr='hum'),
            Type4_LV('EPS_ID', ReprName='EPS Mobile Identity', V=4*'\0'),
            Type4_LV('UENetCap', ReprName='UE Network Capability', V='\0\0'),
            Type6_LVE('ESMContainer', V=3*'\0'),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI Signature', T=0x19,
                     V=3*'\0', Len=3),
            Type4_TLV('GUTI', ReprName='Additional GUTI', T=0x50, V=11*'\0'),
            Type3_TV('TAI', ReprName='Last Visited TAI', T=0x52,
                     V=5*'\0', Len=5),
            Type3_TV('DRX', ReprName='DRX Parameter', T=0x5C, V=2*'\0', Len=2),
            Type4_TLV('MSNetCap', ReprName='MS Network Capability', T=0x31,
                      V='\0\0'),
            Type3_TV('LAI', ReprName='Old LAI', T=0x13, V=LAI(), Len=5),
            Type1_TV('TMSIStat', ReprName='TMSI Status', T=0x9, V=0,
                     Dict=TMSIStatus_dict),
            Type4_TLV('MSCm2', T=0x11, V=MSCm2()),
            Type4_TLV('MSCm3', T=0x20, V=MSCm3()),
            Type4_TLV('SuppCodecs', ReprName='Supported Codecs List',
                      T=0x40, V='\0\0\0'),
            Type1_TV('AddUpdType', ReprName='Additional Update Type', T=0xF,
                     V=0, Dict=AddUpdType_dict),
            Type4_TLV('VoicePref', ReprName='Voice Domain Preference', T=0x5D,
                      V='\0'),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xD, V=0,
                     Dict=DevProp_dict),
            Type1_TV('GUTIType', ReprName='Old GUTI Type', T=0xE, V=0,
                     Dict=GUTIType_dict),
            Type1_TV('MSFeatSup', ReprName='MS Net Feature Support', 
                     T=0xC, V=0, Dict=MSFeatSup_dict),
            Type4_TLV('NRIContainer', ReprName='TMSI-based NRI Container',
                      T=0x10, V=2*'\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.1
class ATTACH_ACCEPT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=66)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('EPSAttRes', ReprName='EPS Attach Result', Pt=1, BitLen=4, 
                Dict=EPSAttRes_dict, Repr='hum'),
            Int('T3412', ReprName='GPRS Timer', Pt=0, Type='uint8'),
            Type4_LV('TAIList', ReprName='Tracking Area Identity List',
                     V=6*'\0'),
            Type6_LVE('ESMContainer', V=3*'\0'),
            Type4_TLV('GUTI', T=0x50, V=11*'\0'),
            Type3_TV('LAI', T=0x13, V=LAI(), Len=5),
            Type4_TLV('ID', T=0x23, V=ID()),
            Type3_TV('EMMCause', T=0x53, V='\0', Len=1),
            Type3_TV('T3402', T=0x17, V='\0', Len=1),
            Type3_TV('T3423', T=0x59, V='\0', Len=1),
            Type4_TLV('PLMNList', ReprName='Equivalent PLMNs', T=0x4A, 
                      V=PLMNList()),
            Type4_TLV('ECNList', ReprName='Emergency Number List', T=0x34,
                      V='\0\0\0'),
            Type4_TLV('EPSFeatSup', ReprName='EPS Network Feature Support',
                      T=0x64, V='\0'),
            Type1_TV('AddUpdRes', ReprName='Additional Update Result', T=0xF,
                     V=0),
            Type4_TLV('T3412ext', ReprName='GPRS Timer 3', T=0x5E, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.2
class ATTACH_COMPLETE(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=67)] + [
        Type6_LVE('ESMContainer', V=3*'\0')]

# section 8.2.3
class ATTACH_REJECT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=68)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('EMMCause', Pt=0, Type='uint8', Dict=EMMCause_dict),
            Type6_TLVE('ESMContainer', T=0x78, V=3*'\0'),
            Type4_TLV('T3346', T=0x5F, V='\0'), # timer with Length attribute but fixed length (1 byte)...
            Type4_TLV('T3402', T=0x16, V='\0') # and again...
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.11
class DETACH_REQUEST(Layer3NASEMM):
    '''
    Net <-> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=69)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        if self._initiator != 'Net':
            self.extend([
                Bit('NASKSI', ReprName='NAS Key Set Indentifier', Pt=0,
                    BitLen=4, Dict=NASKSI_dict, Repr='hum'),
                Bit('DetType', ReprName='Detach Type', Pt=0, BitLen=4,
                    Dict=MEDetType_dict, Repr='hum'),
                Type4_LV('EPS_ID', ReprName='EPS Mobile Identity', V=4*'\0')])
        else:
            self.extend([
                Bit('spare', Pt=0, BitLen=4),
                Bit('DetType', ReprName='Detach Type', Pt=0, BitLen=4,
                    Dict=NetDetType_dict, Repr='hum'),
                Type3_TV('EMMCause', T=0x53, V='\0', Len=1)])
        self._post_init(with_options, **kwargs)

# section 8.2.10
class DETACH_ACCEPT(Layer3NASEMM):
    '''
    Net <-> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=70)]

# section 8.2.29
class TRACKING_AREA_UPDATE_REQUEST(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=72)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Bit('NASKSI', ReprName='NAS Key Set Indentifier', Pt=0, BitLen=4,
                Dict=NASKSI_dict, Repr='hum'),
            Bit('EPSUpdType', ReprName='EPS Update Type', BitLen=4, 
                Dict=EPSUpdType_dict, Repr='hum'),
            Type4_LV('GUTI', ReprName='Old GUTI', V=11*'\0'),
            Type1_TV('NonCurNASKSI', ReprName='Non Current NAS KSI', T=0xB,
                     V=0, Dict=NASKSI_dict),
            Type1_TV('CKSN', ReprName='GPRS ciphering key sequence number',
                     T=0x8, V=0, Dict=CKSN_dict),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI signature', T=0x19,
                     V=3*'\0', Len=3),
            Type4_TLV('GUTI_2', ReprName='Additional GUTI', T=0x50, V=11*'\0'),
            Type3_TV('NonceUE', T=0x55, V=4*'\0', Len=4),
            Type4_TLV('UENetCap', ReprName='UE network capability', T=0x58, 
                      V='\0\0'),
            Type3_TV('TAI', ReprName='Last Visited Registered TAI', T=0x52,
                     V=5*'\0', Len=5),
            Type3_TV('DRX', ReprName='DRX Parameter', T=0x5C, V=2*'\0', Len=2),
            Type1_TV('UERadCapUpd', ReprName='UE Radio Capability Info Update '\
                     'Needed', T=0xA, V=0),
            Type4_TLV('EPSCtxStat', ReprName='EPS Bearer Context Status',
                      T=0x57, V=2*'\0'),
            Type4_TLV('MSNetCap', ReprName='MS network capability', T=0x31,
                      V='\0\0'),
            Type3_TV('LAI', ReprName='Old LAI', T=0x13, V=LAI(), Len=5),
            Type1_TV('TMSIStat', ReprName='TMSI status', T=0x9, V=0,
                     Dict=TMSIStatus_dict),
            Type4_TLV('MSCm2', T=0x11, V=MSCm2()),
            Type4_TLV('MSCm3', T=0x20, V=MSCm3()),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list',
                      T=0x40, V='\0\0\0'),
            Type1_TV('AddUpdType', ReprName='Additional Update Type', T=0xF,
                     V=0, Dict=AddUpdType_dict),
            Type4_TLV('VoicePref', ReprName='Voice domain preference', T=0x5D,
                      V='\0'),
            Type1_TV('GUTIType', ReprName='Old GUTI Type', T=0xE, V=0, 
                     Dict=GUTIType_dict),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xD, V=0,
                     Dict=DevProp_dict),
            Type1_TV('MSFeatSup', ReprName='MS Net Feature Support', 
                     T=0xC, V=0, Dict=MSFeatSup_dict),
            Type4_TLV('NRIContainer', ReprName='TMSI-based NRI Container',
                      T=0x10, V=2*'\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.26
class TRACKING_AREA_UPDATE_ACCEPT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=73)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('EPSUpdRes', ReprName='EPS Update Result', Pt=0, BitLen=4,
                Dict=EPSUpdRes_dict, Repr='hum'),
            Type3_TV('T3412', ReprName='GPRS Timer', T=0x5A, V='\0', Len=1),
            Type4_TLV('GUTI', T=0x50, V=11*'\0'),
            Type4_TLV('TAIList', ReprName='Tracking Area Identity List', T=0x54,
                      V=6*'\0'),
            Type4_TLV('EPSCtxStat', ReprName='EPS Bearer Context Status',
                      T=0x57, V=2*'\0'),
            Type3_TV('LAI', ReprName='Old LAI', T=0x13, V=LAI(), Len=5),
            Type4_TLV('ID', T=0x23, V=ID()),
            Type3_TV('EMMCause', T=0x53, V='\0', Len=1),
            Type3_TV('T3402', T=0x17, V='\0', Len=1),
            Type3_TV('T3423', T=0x59, V='\0', Len=1),
            Type4_TLV('PLMNList', ReprName='Equivalent PLMNs', T=0x4A, 
                      V=PLMNList()),
            Type4_TLV('ECNList', ReprName='Emergency Number List', T=0x34,
                      V='\0\0\0'),
            Type4_TLV('EPSFeatSup', ReprName='EPS Network Feature Support',
                      T=0x64, V='\0'),
            Type1_TV('AddUpdRes', ReprName='Additional Update Result', T=0xF,
                     V=0),
            Type4_TLV('T3412ext', ReprName='GPRS Timer 3', T=0x5E, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.27 
class TRACKING_AREA_UPDATE_COMPLETE(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=74)]

# section 8.2.28
class TRACKING_AREA_UPDATE_REJECT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=75)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('EMMCause', Pt=0, Type='uint8', Dict=EMMCause_dict),
            Type4_TLV('T3346', T=0x5F, V='\0') # timer with Length attribute but fixed length (1 byte)...
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.25
# Service Request: no standard EMM header
class SERVICE_REQUEST(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    special processing, sent during radio bearer establishment
    '''
    constructorList = [
        Bit('SH', ReprName='Security Header Type', Pt=1, BitLen=4, 
            Dict=SecHdr_dict, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=7, BitLen=4,
            Dict=PD_dict, Repr='hum'),
        Bit('NASKSI', Pt=0, BitLen=3, Dict=NASKSI_dict, Repr='hum'),
        Bit('SN', ReprName='NAS COUNT LSB', Pt=0, BitLen=5, Repr='hum'),
        Str('MAC', ReprName='Message Authentication Code LSB', Pt='\0\0', Len=2,
            Repr='hex')
        ]
 
# section 8.2.15
class EXTENDED_SERVICE_REQUEST(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=76)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Bit('NASKSI', ReprName='NAS Key Set Indentifier', Pt=0, BitLen=4,
                Dict=NASKSI_dict, Repr='hum'),
            Bit('ServType', ReprName='Service Type', Pt=0, BitLen=4,
                Dict=ServType_dict, Repr='hum'),
            Type4_LV('ID', ReprName='M-TMSI', V=ID()),
            Type1_TV('CSFBResp', T=0xB, V=0, Dict=CSFBResp_dict),
            Type4_TLV('EPSCtxStat', ReprName='EPS Bearer Context Status',
                      T=0x57, V=2*'\0'),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xD, V=0,
                     Dict=DevProp_dict)
            ])
        self._post_init(with_options, **kwargs)


# section 8.2.24
class SERVICE_REJECT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=78)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('EMMCause', Pt=0, Type='uint8', Dict=EMMCause_dict),
            Type3_TV('T3442', T=0x5B, V='\0', Len=1),
            Type4_TLV('T3346', T=0x5F, V='\0') # timer with Length attribute but fixed length (1 byte)...
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.16
class GUTI_REALLOCATION_COMMAND(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=80)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Type4_LV('GUTI', V=11*'\0'),
            Type4_TLV('TAIList', ReprName='Tracking Area Identity List', 
                      T=0x54, V=6*'\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.17
class GUTI_REALLOCATION_COMPLETE(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=81)]

# section 8.2.7
class EPS_AUTHENTICATION_REQUEST(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=82)] + [
        Bit('spare', Pt=0, BitLen=4),
        Bit('NASKSI', ReprName='NAS Key Set Indentifier', Pt=0, BitLen=4,
            Dict=NASKSI_dict, Repr='hum'),
        Str('RAND', Pt=16*'\0', Len=16, Repr='hex'),
        Type4_LV('AUTN', V=16*'\0') # the good old AUTN overflow capability...
        ]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3.__init__(self, **kwargs)
        self.AUTN.V.Repr = 'hex'

# section 8.2.8
class EPS_AUTHENTICATION_RESPONSE(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=83)] + [
        Type4_LV('RES', V=4*'\0')
        ]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3.__init__(self, **kwargs)
        self.RES.V.Repr = 'hex'

# section 8.2.6
class EPS_AUTHENTICATION_REJECT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=84)]

# section 8.2.5
class EPS_AUTHENTICATION_FAILURE(Layer3NASEMM):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=92)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('EMMCause', Pt=26, Type='uint8', Dict=EMMCause_dict),
            Type4_TLV('AUTS', T=0x30, V=14*'\0')
            ])
        self.AUTS.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 8.2.18
class EPS_IDENTITY_REQUEST(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=85)] + [
        Bit('spare', Pt=0, BitLen=4),
        Bit('IDType', Pt=1, BitLen=4, Dict=IDType_dict, Repr='hum')
        ]

# section 8.2.19
class EPS_IDENTITY_RESPONSE(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=86)] + [
        Type4_LV('ID', V=ID())]

# section 8.2.20
class SECURITY_MODE_COMMAND(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=93)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('NASSecAlg', ReprName='Selected NAS Security Algorithms',
                Pt=0, Type='uint8', Repr='hex'),
            Bit('spare', Pt=0, BitLen=4),
            Bit('NASKSI', ReprName='NAS Key Set Indentifier', Pt=0, BitLen=4,
                Dict=NASKSI_dict, Repr='hum'),
            Type4_LV('UESecCap', ReprName='Replayed UE Security Capabilities',
                     V=2*'\0'),
            Type1_TV('IMEISVReq', T=0x0C, V=0),
            Type3_TV('NonceUE', ReprName='Replayed Nonce UE', T=0x55, V=4*'\0',
                     Len=4),
            Type3_TV('NonceMME', T=0x56, V=4*'\0', Len=4)
            ])
        self._post_init(with_options, **kwargs)

# section  8.2.21
class SECURITY_MODE_COMPLETE(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=94)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Type4_TLV('ID', ReprName='IMEISV', T=0x23, V=ID())
            ])
        self._post_init(with_options, **kwargs)

# section 8.2.22
class SECURITY_MODE_REJECT(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=95)] + [
        Int('EMMCause', Pt=23, Type='uint8', Dict=EMMCause_dict)
        ]

# section 8.2.14
class EMM_STATUS(Layer3NASEMM):
    '''
    Net <-> UE
    Local
    '''
    constructorList = [ie for ie in EMMHeader(Type=96)] + [
        Int('EMMCause', Pt=0, Type='uint8', Dict=EMMCause_dict)]

# section 8.2.13
class EMM_INFORMATION(Layer3NASEMM):
    '''
    Net -> UE
    Local
    '''
    constructorList = [ie for ie in EMMHeader(Type=97)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([ \
            Type4_TLV('NetFullName', T=0x43, V='\x80'),
            Type4_TLV('NetShortName', T=0x45, V='\x80'),
            Type3_TV('TZ', ReprName='Local Time Zone', T=0x46, \
                     V='\0', Len=1),
            Type3_TV('TZTime', ReprName='Time Zone and Time',\
                     T=0x47, V='\0\0\0\0\0\0\0', Len=7),
            Type4_TLV('DTime', ReprName='Daylight Saving Time',\
                      T=0x49, V='\0')])
        self._post_init(with_options, **kwargs)

# section 8.2.12, encapsulates SMS to UE
class DOWNLINK_NAS_TRANSPORT(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=98)] + [
        Type4_LV('NASContainer', V='\0\0')]

# section 8.2.30, encapsulates SMS from UE
class UPLINK_NAS_TRANSPORT(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=99)] + [
        Type4_LV('NASContainer', V='\0\0')]

# section 8.2.9
class CS_SERVICE_NOTIFICATION(Layer3NASEMM):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in EMMHeader(Type=100)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('PagingID', Pt=0, Type='uint8', Dict=PagingID_dict),
            Type4_TLV('CLI', ReprName='Calling Line', T=0x60, V='\0'),
            Type3_TV('SSCode', ReprName='Supplementary Service Transaction',
                     T=0x61, V='\0', Len=1),
            Type3_TV('LCSInd', ReprName='Location Service Indicator', T=0x62,
                     V='\0', Len=1),
            Type4_TLV('LCSCliID', ReprName='Location Service Client Identity',
                      T=0x63, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2., encapsulates any application (e.g. position / location) to UE
class DOWNLINK_GENERIC_NAS_TRANSPORT(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=104)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('ContType', ReprName='Generic Container Type', Pt=1,
                Type='uint8', Dict=GeneContType_dict),
            Type6_LVE('GenericContainer', V='\0'),
            Type4_TLV('AddInfo', T=0x65, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.2., encapsulates any application (e.g. position / location) from UE
class UPLINK_GENERIC_NAS_TRANSPORT(Layer3NASEMM):
    constructorList = [ie for ie in EMMHeader(Type=105)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NASEMM.__init__(self, with_security)
        self.extend([
            Int('ContType', ReprName='Generic Container Type', Pt=1,
                Type='uint8', Dict=GeneContType_dict),
            Type6_LVE('GenericContainer', V='\0'),
            Type4_TLV('AddInfo', T=0x65, V='\0')
            ])
        self._post_init(with_options, **kwargs)

#
