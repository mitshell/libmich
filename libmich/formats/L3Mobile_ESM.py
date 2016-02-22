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
# * File Name : formats/L3Mobile_ESM.py
# * Created : 2013-10-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# exporting
__all__ = ['ACTIVATE_DEFAULT_EPS_BEARER_CTX_REQUEST',
           'ACTIVATE_DEFAULT_EPS_BEARER_CTX_ACCEPT',
           'ACTIVATE_DEFAULT_EPS_BEARER_CTX_REJECT',
           'ACTIVATE_DEDI_EPS_BEARER_CTX_REQUEST',
           'ACTIVATE_DEDI_EPS_BEARER_CTX_ACCEPT',
           'ACTIVATE_DEDI_EPS_BEARER_CTX_REJECT',
           'MODIFY_EPS_BEARER_CTX_REQUEST',
           'MODIFY_EPS_BEARER_CTX_ACCEPT',
           'MODIFY_EPS_BEARER_CTX_REJECT',
           'DEACTIVATE_EPS_BEARER_CTX_REQUEST',
           'DEACTIVATE_EPS_BEARER_CTX_ACCEPT',
           'PDN_CONNECTIVITY_REQUEST', 'PDN_CONNECTIVITY_REJECT',
           'PDN_DISCONNECT_REQUEST', 'PDN_DISCONNECT_REJECT',
           'BEARER_RESOURCE_ALLOC_REQUEST', 'BEARER_RESOURCE_ALLOC_REJECT',
           'BEARER_RESOURCE_MODIF_REQUEST', 'BEARER_RESOURCE_MODIF_REJECT',
           'ESM_INFORMATION_REQUEST', 'ESM_INFORMATION_RESPONSE',
           'ESM_NOTIFICATION', 'ESM_STATUS',
           'ESM_dict', 'ESMCause_dict',
            ]

from libmich.core.element import Element, Str, Int, Bit, Layer, RawLayer

# these are the libraries for the handling of L3 NAS msg
from .L3Mobile_24007 import Type1_TV, Type2, Type3_V, Type3_TV, Type4_LV, \
     Type4_TLV, Type6_LVE, Type6_TLVE, PD_dict, Layer3
from .L3Mobile_NAS import Layer3NAS
#
# these are the libraries for IE interpretation
from .L3Mobile_IE import QoS, PDPAddr, ProtConfig
from .L3Mobile_IEdict import RequestType_dict, PDNType_dict, ESMTransFlag_dict

###
# TS 24.301, 11.5.0 specification
# NAS protocol for Evolved Packet System
# EMM procedures in section 5
# ESM procedures in section 6
# message function in section 8
# message format in section 9
###

ESM_dict = {
    #
    193 : "Activate default EPS bearer context request",
    194 : "Activate default EPS bearer context accept",
    195 : "Activate default EPS bearer context reject",
    #
    197 : "Activate dedicated EPS bearer context request",
    198 : "Activate dedicated EPS bearer context accept",
    199 : "Activate dedicated EPS bearer context reject",
    #
    201 : "Modify EPS bearer context request",
    202 : "Modify EPS bearer context accept",
    203 : "Modify EPS bearer context reject",
    #
    205 : "Deactivate EPS bearer context request",
    206 : "Deactivate EPS bearer context accept",
    #
    208 : "PDN connectivity request",
    209 : "PDN connectivity reject",
    #
    210 : "PDN disconnect request",
    211 : "PDN disconnect reject",
    #
    212 : "Bearer resource allocation request",
    213 : "Bearer resource allocation reject",
    #
    214 : "Bearer resource modification request",
    215 : "Bearer resource modification reject",
    #
    217 : "ESM information request",
    218 : "ESM information response",
    #
    219 : "Notification",
    #
    232 : "ESM status",
    }

# section 9.9.4.4
ESMCause_dict = {
    8 : "Operator Determined Barring",
    26 : "Insufficient resources",
    27 : "Missing or unknown APN",
    28 : "Unknown PDN type",
    29 : "User authentication failed",
    30 : "Request rejected by Serving GW or PDN GW",
    31 : "Request rejected, unspecified",
    32 : "Service option not supported",
    33 : "Requested service option not subscribed",
    34 : "Service option temporarily out of order",
    35 : "PTI already in use",
    36 : "Regular deactivation",
    37 : "EPS QoS not accepted",
    38 : "Network failure",
    39 : "Reactivation requested",
    41 : "Semantic error in the TFT operation",
    42 : "Syntactical error in the TFT operation",
    43 : "Invalid EPS bearer identity",
    44 : "Semantic errors in packet filter(s)",
    45 : "Syntactical errors in packet filter(s)",
    46 : "Unused (see NOTE 2)",
    47 : "PTI mismatch",
    49 : "Last PDN disconnection not allowed",
    50 : "PDN type IPv4 only allowed",
    51 : "PDN type IPv6 only allowed",
    52 : "Single address bearers only allowed",
    53 : "ESM information not received",
    54 : "PDN connection does not exist",
    55 : "Multiple PDN connections for a given APN not allowed",
    56 : "Collision with network initiated request",
    59 : "Unsupported QCI value",
    60 : "Bearer handling not supported",
    65 : "Maximum number of EPS bearers reached",
    66 : "Requested APN not supported in current RAT and PLMN combination",
    81 : "Invalid PTI value",
    95 : "Semantically incorrect message",
    96 : "Invalid mandatory information",
    97 : "Message type non-existent or not implemented",
    98 : "Message type not compatible with the protocol state",
    99 : "Information element non-existent or not implemented",
    100 : "Conditional IE error",
    101 : "Message not compatible with the protocol state",
    111 : "Protocol error, unspecified",
    112 : "APN restriction value incompatible with active EPS bearer context",
    }


###
# NAS protocol headers
# section 9.2
###

class ESMHeader(Layer):
    constructorList = [
        Bit('EBT', ReprName='EPS Bearer Type', Pt=0, BitLen=4, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=2, BitLen=4,
            Dict=PD_dict, Repr='hum'),
        Int('TI', ReprName='Procedure Transaction ID', Pt=0, Type='uint8'),
        Int('Type', Type='uint8', Dict=ESM_dict, Repr='hum'),
        ]


###
# NAS ESM messages
###

# section 8.3.6
class ACTIVATE_DEFAULT_EPS_BEARER_CTX_REQUEST(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=193)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_LV('EQoS', ReprName='EPS QoS', V='\0'),
            Type4_LV('APN', ReprName='Access Point Name', V='\0'),
            Type4_LV('PDNAddr', ReprName='PDN Address', V=5*'\0'),
            Type4_TLV('LTI', ReprName='Linked Transaction Identifier', T=0x5D, V='\0'),
            Type4_TLV('QoS', ReprName='Negotiated QoS', T=0x30, V=12*'\0'),
            Type3_TV('LLC_SAPI', ReprName='Negotiated LLC Service Access ' \
                      'Point ID', T=0x32, V='\0', Len=1),
            Type1_TV('RadioPrio', ReprName='Radio Priority', T=0x8, V=1),
            Type4_TLV('PFlowID', ReprName='Packet Flow ID', T=0x34, V='\0'),
            Type4_TLV('APN_AMBR', ReprName='APN Aggregate Maximum Bitrate', 
                      T=0x5E, V='\0\0'),
            Type3_TV('ESMCause', T=0x58, V='\0', Len=1),
            Type4_TLV('ProtConfig', ReprName='Protocol Configuration options',
                      T=0x27, V='\x80'),
            Type1_TV('ConType', ReprName='Connectivity Type', T=0xB, V=0)
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.4
class ACTIVATE_DEFAULT_EPS_BEARER_CTX_ACCEPT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=194)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.5
class ACTIVATE_DEFAULT_EPS_BEARER_CTX_REJECT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=195)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.3
class ACTIVATE_DEDI_EPS_BEARER_CTX_REQUEST(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=197)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('Bearer', ReprName='Linked EPS Bearer ID', Pt=5, BitLen=4,
                Repr='hum'),
            Type4_LV('EQoS', ReprName='EPS QoS', V='\0'),
            Type4_LV('TFT', ReprName='Traffic Flow Template', V='\0'),
            Type4_TLV('TI', ReprName='Transaction Identifier', T=0x5D, V='\0'),
            Type4_TLV('QoS', ReprName='Negotiated QoS', T=0x30, V=12*'\0'),
            Type3_TV('LLC_SAPI', ReprName='Negotiated LLC Service Access ' \
                      'Point ID', T=0x32, V='\0', Len=1),
            Type1_TV('RadioPrio', ReprName='Radio Priority', T=0x8, V=1),
            Type4_TLV('PFlowID', ReprName='Packet Flow ID', T=0x34, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.1
class ACTIVATE_DEDI_EPS_BEARER_CTX_ACCEPT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=198)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.2
class ACTIVATE_DEDI_EPS_BEARER_CTX_REJECT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=199)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)


# section 8.3.18
class MODIFY_EPS_BEARER_CTX_REQUEST(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=201)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('EQoS', ReprName='New EPS QoS', T=0x5B, 
                      V='\0'),
            Type4_TLV('TFT', ReprName='Traffic Flow Template', T=0x36, V='\0'),
            Type4_TLV('QoS', ReprName='New QoS', T=0x30, V=12*'\0'),
            Type3_TV('LLC_SAPI', ReprName='Negotiated LLC Service Access ' \
                      'Point ID', T=0x32, V='\0', Len=1),
            Type1_TV('RadioPrio', ReprName='Radio Priority', T=0x8, V=1),
            Type4_TLV('PFlowID', ReprName='Packet Flow ID', T=0x34, V='\0'),
            Type4_TLV('APN_AMBR', ReprName='APN Aggregate Maximum Bitrate', 
                      T=0x5E, V='\0\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.16
class MODIFY_EPS_BEARER_CTX_ACCEPT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=202)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.17
class MODIFY_EPS_BEARER_CTX_REJECT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=203)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.12
class DEACTIVATE_EPS_BEARER_CTX_REQUEST(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=205)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('T3396', T=0x37, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.11
class DEACTIVATE_EPS_BEARER_CTX_ACCEPT(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=206)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.20
class PDN_CONNECTIVITY_REQUEST(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=208)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Bit('PDNType', Pt=0, BitLen=4, Dict=PDNType_dict, Repr='hum'),
            Bit('ReqType', ReprName='Request Type', Pt=0, BitLen=4,
                Dict=RequestType_dict, Repr='hum'),
            Type1_TV('ESMTransFlag', ReprName='ESM Information Transfer Flag',
                     T=0xD, V=0, Dict=ESMTransFlag_dict),
            Type4_TLV('APN', ReprName='Access Point Name', T=0x28, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xC, V=0)
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.19
class PDN_CONNECTIVITY_REJECT(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=209)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('T3396', T=0x37, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.22
class PDN_DISCONNECT_REQUEST(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=210)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('Bearer', ReprName='Linked EPS Bearer ID', Pt=5, BitLen=4,
                Repr='hum'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.21
class PDN_DISCONNECT_REJECT(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=211)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.8
class BEARER_RESOURCE_ALLOC_REQUEST(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=212)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('Bearer', ReprName='Linked EPS Bearer ID', Pt=5, BitLen=4,
                Repr='hum'),
            Type4_LV('TFA', ReprName='Traffic Flow Aggregate', V='\0'),
            Type4_LV('EQoS', ReprName='Required Traffic Flow QoS', V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xC, V=0)
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.7
class BEARER_RESOURCE_ALLOC_REJECT(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=213)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('T3396', T=0x37, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.10
class BEARER_RESOURCE_MODIF_REQUEST(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=214)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Bit('spare', Pt=0, BitLen=4),
            Bit('Bearer', ReprName='Linked EPS Bearer ID', Pt=5, BitLen=4,
                Repr='hum'),
                
            Type4_LV('TFA', ReprName='Traffic Flow Aggregate', V='\0'),
            Type4_LV('EQoS', ReprName='Required Traffic Flow QoS', V='\0'),
            Type3_TV('ESMCause', T=0x58, V='\0', Len=1),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type1_TV('DevProp', ReprName='Device Properties', T=0xC, V=0)
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.9
class BEARER_RESOURCE_MODIF_REJECT(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=215)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('T3396', T=0x37, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.13
class ESM_INFORMATION_REQUEST(Layer3NAS):
    '''
    Net -> UE
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=217)]

# section 8.3.14
class ESM_INFORMATION_RESPONSE(Layer3NAS):
    '''
    UE -> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=218)]
    def __init__(self, with_options=False, with_security=False, **kwargs):
        Layer3NAS.__init__(self, with_security)
        self.extend([
            Type4_TLV('APN', ReprName='Access Point Name', T=0x28, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 8.3.18A
class ESM_NOTIFICATION(Layer3NAS):
    '''
    Net -> UE
    Local
    '''
    constructorList = [ie for ie in ESMHeader(Type=219)] + [ \
        Type4_LV('NotifInd', V='\0')]

# section 8.3.15
class ESM_STATUS(Layer3NAS):
    '''
    UE <-> Net
    Dual
    '''
    constructorList = [ie for ie in ESMHeader(Type=232)] + [ \
        Int('ESMCause', Pt=0, Type='uint8', Dict=ESMCause_dict)]

#
