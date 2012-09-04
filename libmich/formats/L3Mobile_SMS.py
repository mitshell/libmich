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
# * File Name : formats/L3Mobile_SMS.py
# * Created : 2012-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer, \
    show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.L3Mobile_24007 import Type1_TV, Type2, \
    Type3_V, Type3_TV, Type4_LV, Type4_TLV, PD_dict, \
    Layer3
from libmich.formats.L3Mobile_IE import BCDnum

# TS 24.011 defines SMS signalling for mobile networks
#
# section 7 and 8: message format and IE coding
#
# describes mobile L3 signalling messages for SMS-PP
# each message composed of Information Element (IE)
# SM-CP : Short Message Control Protocol
# SM-RP : Short Message Relay Protocol, on top of SM-CP
#

# 24011, section 8.1: SM-CP
# CS Mobility Management procedures dict
SMSCP_dict = IANA_dict({
    1:("SMS CP-DATA", "DATA"),
    4:("SMS CP-ACK", "ACK"),
    16:("SMS CP-ERROR", "ERR"),
    })

# section 8.1.4.2
CPCause_dict = {
    17 : 'Network failure',
    22 : 'Congestion',
    81 : 'Invalid Transaction Identifier value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non existent or not implemented',
    98 : 'Message not compatible with the short message protocol state',
    99 : 'Information element non existent or not implemented',
    111 : 'Protocol error, unspecified',
    }

# section 8.2.2
RPType_dict = {
    0 : 'MS -> Net : RP-DATA',
    1 : 'Net -> MS : RP-DATA',
    2 : 'MS -> Net : RP-ACK',
    3 : 'Net -> MS : RP-ACK',
    4 : 'MS -> Net : RP-ERROR',
    5 : 'Net -> MS : RP-ERROR',
    6 : 'MS -> Net : RP-SMMA',
    }

# section 8.2.5.4
RPCause_dict = {
    1 : 'Unassigned (unallocated) number',
    8 : 'Operator determined barring',
    10 : 'Call barred',
    11 : 'Reserved',
    21 : 'Short message transfer rejected',
    22 : 'Memory capacity exceeded',
    27 : 'Destination out of order',
    28 : 'Unidentified subscriber',
    29 : 'Facility rejected',
    30 : 'Unknown subscriber',
    38 : 'Network out of order',
    41 : 'Temporary failure',
    42 : 'Congestion',
    47 : 'Resources unavailable, unspecified',
    50 : 'Requested facility not subscribed',
    69 : 'Requested facility not implemented',
    81 : 'Invalid short message transfer reference value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non existent or not implemented',
    98 : 'Message not compatible with short message protocol state',
    99 : 'Information element non existent or not implemented',
    111 : 'Protocol error, unspecified',
    127 : 'Interworking, unspecified',
    }

###################
# message formats #
###################
### Control Protocol ###
class Header(Layer):
    constructorList = [
        Bit('TI', ReprName='Transaction Identifier', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=SMSCP_dict),
        ]
    def __init__(self, prot=9, type=1):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type

# 24011, 7.2.1 and 8.1.4.1
class CP_DATA(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(9, 1)]
    def __init__(self, **kwargs):
        Layer3.__init__(self)
        self.append( Type4_LV('Data', V='') )
        self._post_init(**kwargs)
    
    def map(self, s=''):
        Layer.map(self, s)
        rpt = ord(self.Data.V()[0])&0b111

# 24011, 7.2.2
class CP_ACK(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(9, 4)]

 # 24011, 7.2.3 and 8.1.4.2
class CP_ERROR(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(9, 16)]
    def __init__(self, **kwargs):
        Layer3.__init__(self)
        self.append( Int('CPCause', Pt=17, Type='uint8', Dict=CPCause_dict) )
        self._post_init(**kwargs)

### Relay Protocol ###
# 24011, 7.3.1, 8.2.2-3 and 8.2.5.1-3
class RP_DATA_MSTONET(Layer):
    '''
    MS -> Net
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'), # reference to be used in ACKed
        Type4_LV('OrigAddrNull', V=''), # null address
        Type4_LV('BCDnum', ReprName='RP destination address', V=BCDnum()), # length 1-12
        Type4_LV('Data', V=''), # length <= 233
        ]

class RP_DATA_NETTOMS(Layer):
    '''
    Net -> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'), # reference to be used in ACKed
        Type4_LV('BCDnum', ReprName='RP originator address', V=BCDnum()), # length 1-12
        Type4_LV('DestAddrNull', V=''), # null address
        Type4_LV('Data', V=''), # length <= 233
        ]

# 24011, 7.3.2 and 8.2.2-3
class RP_SMMA(Layer):
    '''
    MS -> Net
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'),
        ]

class RP_ACK(Layer):
    '''
    Net -> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'),
        Type4_TLV('Data', T=0x41, V=''), # length <= 234
        ]

class RP_ERROR(Layer):
    '''
    Net <-> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'),
        Int('L', Type='uint8'),
        Int('RPCause', Pt=111, Type='uint8'),
        Str('RPDiag', Pt='', Repr='hex'),
        Type4_TLV('Data', T=0x41, V=''), # length <= 234
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.L.Pt = self.RPDiag
        self.L.PtFunc = lambda d: len(d)+1
        self.RPDiag.Len = self.L
        self.RPDiag.LenFunc = lambda l: int(l)-1

# to map RP struct directly onto CP_DATA struct
RPCall = {
    0 : RP_DATA_MSTONET,
    1 : RP_DATA_NETTOMS,
    2 : RP_ACK,
    3 : RP_ACK,
    4 : RP_ERROR,
    5 : RP_ERROR,
    6 : RP_SMMA,
    }