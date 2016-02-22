# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau. ANSSI.
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
# * File Name : formats/L3Mobile_SM.py
# * Created : 2012-08-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer
from libmich.core.IANA_dict import IANA_dict

from .L3Mobile_24007 import Type1_TV, Type2, Type3_V, Type3_TV, Type4_LV, \
     Type4_TLV, PD_dict, Layer3
#
# these are the libraries for IE interpretation
from .L3Mobile_IE import QoS, PDPAddr, ProtConfig
from .L3Mobile_IEdict import *

# TS 24.008 defines L3 signalling for mobile networks
#
# section 9: 
# Message definition
#
# describes mobile L3 signalling messages
# each message composed of Information Element (IE)
# each IE is coded on a TypeX (T, TV, LV, TLV...) from 24.007
# each IE is mandatory, conditional, or optional in the message
#
# Messages are coded as Layer
# containing Bit, Int, Str or Layer for each IE
# ...
# It's going to rock!

# 24008, section 10.4
# Packet Service Session Management procedures dict
PS_SM_dict = {
    65:"GPRS - Activate PDP context request",
    66:"GPRS - Activate PDP context accept",
    67:"GPRS - Activate PDP context reject",
    68:"GPRS - Request PDP context activation",
    69:"GPRS - Request PDP context activation rejection",
    70:"GPRS - Deactivate PDP context request",
    71:"GPRS - Deactivate PDP context accept",
    72:"GPRS - Modify PDP context request(Network to MS direction)",
    73:"GPRS - Modify PDP context accept (MS to network direction)",
    74:"GPRS - Modify PDP context request(MS to network direction)",
    75:"GPRS - Modify PDP context accept (Network to MS direction)",
    76:"GPRS - Modify PDP context reject",
    77:"GPRS - Activate secondary PDP context request",
    78:"GPRS - Activate secondary PDP context accept",
    79:"GPRS - Activate secondary PDP context reject",
    80:"GPRS - Reserved",
    81:"GPRS - Reserved",
    82:"GPRS - Reserved",
    83:"GPRS - Reserved",
    84:"GPRS - Reserved",
    85:"GPRS - SM Status",
    86:"GPRS - Activate MBMS Context Request",
    87:"GPRS - Activate MBMS Context Accept",
    88:"GPRS - Activate MBMS Context Reject",
    89:"GPRS - Request MBMS Context Activation",
    90:"GPRS - Request MBMS Context Activation Reject",
    91:"GPRS - Request Secondary PDP Context Activation",
    92:"GPRS - Request Secondary PDP Context Activation Reject",
    93:"GPRS - Notification",
    }

#
# 24008, 10.5.6.6
SMCause_dict = {
    8 : 'Operator Determined Barring',
    24 : 'MBMS bearer capabilities insufficient for the service',
    25 : 'LLC or SNDCP failure(A/Gb mode only)',
    26 : 'Insufficient resources',
    27 : 'Missing or unknown APN',
    28 : 'Unknown PDP address or PDP type',
    29 : 'User authentication failed',
    30 : 'Activation rejected by GGSN, Serving GW or PDN GW',
    31 : 'Activation rejected, unspecified',
    32 : 'Service option not supported',
    33 : 'Requested service option not subscribed',
    34 : 'Service option temporarily out of order',
    35 : 'NSAPI already used (not sent)',
    36 : 'Regular deactivation',
    37 : 'QoS not accepted',
    38 : 'Network failure',
    39 : 'Reactivation required',
    40 : 'Feature not supported',
    41 : 'Semantic error in the TFT operation',
    42 : 'Syntactical error in the TFT operation',
    43 : 'Unknown PDP context',
    44 : 'Semantic errors in packet filter(s)',
    45 : 'Syntactical errors in packet filter(s)',
    46 : 'PDP context without TFT already activated',
    47 : 'Multicast group membership time-out',
    48 : 'Activation rejected, BCM violation',
    50 : 'PDP type IPv4 only allowed',
    51 : 'PDP type IPv6 only allowed',
    52 : 'Single address bearers only allowed',
    56 : 'Collision with network initiated request',
    81 : 'Invalid transaction identifier value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100 : 'Conditional IE error',
    101 : 'Message not compatible with the protocol state',
    111 : 'Protocol error, unspecified',
    112 : 'APN restriction value incompatible with active PDP context',
    }

###################
# message formats #
###################
# TS 24.008, section 9
class Header(Layer):
    constructorList = [
        Bit('TI', ReprName='Transaction Identifier', Pt=0, BitLen=4,
            Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=10, BitLen=4,
            Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=PS_SM_dict, Repr='hum')
        ]
    def __init__(self, prot=10, type=85):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type


###########################
# TS 24.008, section 9.5  #
# GPRS Session Management #
###########################

# section 9.5.1
class ACTIVATE_PDP_CONTEXT_REQUEST(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 65)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('NSAPI', ReprName='Requested Network Access Point ID',
                Pt=5, Type='uint8'),
            Int('LLC_SAPI', ReprName='Requested LLC Service Access Point ID',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('QoS', ReprName='Requested QoS', V=QoS()),
            Type4_LV('PDPAddr', ReprName='Requested PDP Address', V='\0\x01'),
            Type4_TLV('APN', ReprName='Access Point Name', T=0x28, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type1_TV('ReqType', ReprName='Request type', T=0xA, V=1, 
                     Dict=RequestType_dict)
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.2
class ACTIVATE_PDP_CONTEXT_ACCEPT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 66)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('LLC_SAPI', ReprName='Negociated LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('QoS', ReprName='Negociated QoS', V=QoS()),
            Bit('spare', Pt=0, BitLen=4),
            Bit('RadioPrio', ReprName='Radio priority', Pt=1, BitLen=4),
            Type4_TLV('PDPAddr', ReprName='Requested PDP address',
                      T=0x2B, V='\0\x01'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('PFlowID', ReprName='Packet flow id', T=0x34, V='\0'),
            Type4_TLV('SMCause', T=0x39, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.3
class ACTIVATE_PDP_CONTEXT_REJECT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 67)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.4
class ACTIVATE_SECONDARY_PDP_CONTEXT_REQUEST(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 77)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('NSAPI', ReprName='Requested network access point id',
                Pt=5, Type='uint8'),
            Int('LLC_SAPI', ReprName='Requested LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('QoS', ReprName='Requested QoS', V=QoS()),
            Type4_LV('LinkedTI', V='\0'),
            Type4_TLV('TFT', ReprName='Traffic flow template', T=0x36, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.5
class ACTIVATE_SECONDARY_PDP_CONTEXT_ACCEPT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 78)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('LLC_SAPI', ReprName='Negociated LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('QoS', ReprName='Negociated QoS', V=QoS()),
            Bit('spare', Pt=0, BitLen=4),
            Bit('RadioPrio', ReprName='Radio priority', Pt=1, BitLen=4),
            Type4_TLV('PFlowID', ReprName='Packet flow id', T=0x34, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.6
class ACTIVATE_SECONDARY_PDP_CONTEXT_REJECT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 79)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.7
class REQUEST_PDP_CONTEXT_ACTIVATION(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 68)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('PDPAddr', ReprName='Offered PDP address', V='\0\x01'),
            Type4_TLV('APN', ReprName='Access point name', T=0x28, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.8
class REQUEST_PDP_CONTEXT_ACTIVATION_REJECT(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 69)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.9
class MODIFY_PDP_CONTEXT_REQUEST_NETTOMS(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 72)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4),
            Bit('RadioPrio', ReprName='Radio priority', Pt=1, BitLen=4),
            Int('LLC_SAPI', ReprName='Requested LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('QoS', ReprName='New QoS', V=QoS()),
            Type4_TLV('PDPAddr', ReprName='PDP address', T=0x2B, V='\0\x01'),
            Type4_TLV('PFlowID', ReprName='Packet flow id', T=0x34, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('TFT', ReprName='Traffic flow template', T=0x36, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.10
class MODIFY_PDP_CONTEXT_REQUEST_MSTONET(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 74)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type3_TV('LLC_SAPI', ReprName='Requested LLC service access point id',
                     T=0x32, V='\0', Len=1),
            Type4_TLV('QoS', ReprName='New QoS', T=0x30, V=QoS()),
            Type4_TLV('TFT', ReprName='New traffic flow template', T=0x31, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.11
class MODIFY_PDP_CONTEXT_ACCEPT_MSTONET(Layer3):
    '''
    Net <-> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 73)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.12
class MODIFY_PDP_CONTEXT_ACCEPT_NETTOMS(Layer3):
    '''
    Net <-> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 75)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('QoS', ReprName='Negociated QoS', T=0x30, V=QoS()),
            Type3_TV('LLC_SAPI', ReprName='Negociated LLC service access point id',
                     T=0x32, V='\0', Len=1),
            Type1_TV('RadioPrio', ReprName='New padio priority', T=0x8, V=1),
            Type4_TLV('PFlowID', ReprName='Packet flow id', T=0x34, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.13
class MODIFY_PDP_CONTEXT_REJECT(Layer3):
    '''
    Net <-> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 76)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.14
class DEACTIVATE_PDP_CONTEXT_REQUEST(Layer3):
    '''
    Net <-> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 70)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type1_TV('TearDownInd', ReprName='TI tear down requested',
                     T=0x9, V=0),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.15
class DEACTIVATE_PDP_CONTEXT_ACCEPT(Layer3):
    '''
    Net <-> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 71)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80'),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.15a
class REQUEST_SECONDARY_PDP_CONTEXT_ACTIVATION(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 91)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('QoS', ReprName='Requested QoS', V=QoS()),
            Type4_LV('LinkedTI', V='\0'),
            Type4_TLV('TFT', ReprName='Traffic flow template', T=0x36, V='\0'),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.15b
class REQUEST_SECONDARY_PDP_CONTEXT_ACTIVATION_REJECT(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 92)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('ProtConfig', ReprName='Protocol Config Options',
                      T=0x27, V='\x80')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.16a
class GPRS_NOTIFICATION(Layer3):
    '''
    Net -> MS
    Local
    '''
    constructorList = [ie for ie in Header(10, 93)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('NotifInd', ReprName='SRVCC notification', V='\x01')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.21
class SM_STATUS(Layer3):
    '''
    Net <-> MS
    Local
    '''
    constructorList = [ie for ie in Header(10, 85)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ Int('SMCause', Pt=40, Type='uint8', Dict=SMCause_dict) ])
        self._post_init(with_options, **kwargs)

# section 9.5.22
class ACTIVATE_MBMS_CONTEXT_REQUEST(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 86)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('MBMS_NSAPI', ReprName='Requested enhanced network access point id',
                Pt=128, Type='uint8'),
            Int('LLC_SAPI', ReprName='Requested LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_LV('MBMSCap', ReprName='Supported MBMS bearer capbilities',
                     V='\0'),
            Type4_LV('PDPAddr', ReprName='Requested multicast address', 
                     V='\0\x01'),
            Type4_LV('APN', ReprName='Access point name', V='\0'),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.23
class ACTIVATE_MBMS_CONTEXT_ACCEPT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 87)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('TMGI', ReprName='Temporary mobile group id', V='\0\0\0'),
            Int('LLC_SAPI', ReprName='Negociated LLC service access point id',
                Pt=0, Type='uint8', Dict=LLCSAPI_dict),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.24
class ACTIVATE_MBMS_CONTEXT_REJECT(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 88)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.25
class REQUEST_MBMS_CONTEXT_ACTIVATION(Layer3):
    '''
    Net -> MS
    Global
    '''
    constructorList = [ie for ie in Header(10, 89)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('NSAPI', ReprName='Linked network access point id',
                Pt=128, Type='uint8'),
            Type4_LV('PDPAddr', ReprName='Offered multicast address', V='\0\x01'),
            Type4_LV('APN', ReprName='Access point name', V='\0'),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0') 
            ])
        self._post_init(with_options, **kwargs)

# section 9.5.26
class REQUEST_MBMS_CONTEXT_ACTIVATION_REJECT(Layer3):
    '''
    MS -> Net
    Global
    '''
    constructorList = [ie for ie in Header(10, 90)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('SMCause', Pt=111, Type='uint8', Dict=SMCause_dict),
            Type4_TLV('MBMSProtConfig', ReprName='MBMS Protocol Config Options',
                      T=0x35, V='\0')
            ])
        self._post_init(with_options, **kwargs)
#
