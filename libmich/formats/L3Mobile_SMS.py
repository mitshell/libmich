# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau. ANSSI / FlUxIuS
# * Many thanks to FlUxIuS for its submission (greatly appreciated)
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

from libmich.core.element import Bit, Int, Str, Layer, show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.core.shtr import shtr
from libmich.formats.L3Mobile_24007 import Type1_TV, Type2, \
    Type3_V, Type3_TV, Type4_LV, Type4_TLV, PD_dict, \
    Layer3
from libmich.formats.L3Mobile_IE import BCDNumber, StrBCD, BCDType_dict, \
    NumPlan_dict
#
from math import ceil
from binascii import unhexlify as unh


# export filter
__all__ = ['CP_DATA', 'CP_ACK', 'CP_ERROR', \
           'RP_DATA_MSToNET', 'RP_DATA_NETToMS', 'RP_SMMA', 'RP_ACK', \
           'RP_ERROR', 'RP_Originator_Address', 'RP_Destination_Address', \
           'TP_Address', 'TP_Originating_Address', 'TP_Destination_Address', \
           'TP_Recipient_Address', 'TP_PID', 'TP_DCS', 'TP_SCTS', 'TP_VP_rel', \
           'TP_VP_abs', 'TP_DT', 'TP_PI', 'Str7b', 'TP_UDH_TLV', 'SMS_DELIVER', \
           'SMS_DELIVER_REPORT_RP_ERROR', 'SMS_DELIVER_REPORT_RP_ACK', \
           'SMS_SUBMIT', 'SMS_SUBMIT_REPORT_RP_ERROR', 'SMS_SUBMIT_REPORT_RP_ACK', \
           'SMS_STATUS_REPORT', 'SMS_COMMAND', \
          ]

# TS 24.011 defines SMS lower layer signalling for mobile networks
# section 7 and 8: message format and IE coding.
# It defines the control and relay layers for SMS-PP
# SM-CP : Short Message Control Protocol
# SM-RP : Short Message Relay Protocol, on top of SM-CP

# TS 23.040 defines SMS transport and application layers
# section 9: message format and IE coding.
# It defines the highest layers of the SMS protocol signalling for SMS-PP
# and how the content of the message itself is encoded
# SM-TL : Short Message Transport Protocol
# SM-AL : Short Message Application Layer


# 24007, section 11.2.3.1.2
TI_dict = {
    0:'allocated by sender',
    1:'allocated by receiver',
    }

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
        Bit('TI', ReprName='Transaction Identifier Flag', Pt=0, BitLen=1, \
            Dict=TI_dict, Repr='hum'),
        Bit('TIO', ReprName='Transaction Identifier', Pt=0, BitLen=3, \
            Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=9, BitLen=4, \
            Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=SMSCP_dict),
        ]

# 24011, 7.2.1 and 8.1.4.1
class CP_DATA(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(Type=1)]
    def __init__(self, **kwargs):
        Layer3.__init__(self)
        self.append( Type4_LV('Data', V='') )
        self._post_init(**kwargs)
    
    def map(self, s=''):
        Layer.map(self, s)
        data = self.Data.V()
        if data:
            mti = ord(data[0])&0b111
            if mti in RP_selector:
                rp = RP_selector[mti]()
                rp.map(data)
                self.Data.L > rp
                self.Data.V > rp
                self.Data.V < None

# 24011, 7.2.2
class CP_ACK(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(Type=4)]

 # 24011, 7.2.3 and 8.1.4.2
class CP_ERROR(Layer3):
    '''
    Net <-> MS
    '''
    constructorList = [ie for ie in Header(Type=16)]
    def __init__(self, **kwargs):
        Layer3.__init__(self)
        self.append( Int('CPCause', Pt=17, Type='uint8', Dict=CPCause_dict) )
        self._post_init(**kwargs)

### Relay Protocol ###
# 24011, 7.3.1, 8.2.2-3 and 8.2.5.1-3
#
# originator / destination addresses and BCD phone number
class RP_Originator_Address(BCDNumber):
    constructorList = [
        Int('Length', Type='uint8')] + \
        BCDNumber.constructorList
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Num
        self.Length.PtFunc = lambda n: len(n)+1
        self.Num.Len = self.Length
        self.Num.LenFunc = lambda l: int(l)-1

class RP_Destination_Address(BCDNumber):
    constructorList = [
        Int('Length', Type='uint8')] + \
        BCDNumber.constructorList
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Num
        self.Length.PtFunc = lambda n: len(n)+1
        self.Num.Len = self.Length
        self.Num.LenFunc = lambda l: int(l)-1

class RP_DATA_MSToNET(Layer):
    '''
    MS -> Net
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', Pt=0, BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'), # reference to be used in ACKed
        Type4_LV('OrigAddrNull', V=''), # null address
        RP_Destination_Address(), # length 1-12
        Type4_LV('Data', V=''), # length <= 233
        ]
    
    def map(self, s=''):
        Layer.map(self, s)
        addr = self.DestAddr.V()
        if self.DestAddr.L():
            da = RP_Destination_Address()
            da.map(addr)
            self.DestAddr.L > da
            self.DestAddr.V > da
            self.DestAddr.V < None

class RP_DATA_NETToMS(Layer):
    '''
    Net -> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', Pt=1, BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'), # reference to be used in ACKed
        RP_Originator_Address(), # length 1-12
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
        Bit('Type', Pt=6, BitLen=3, Repr='hum', Dict=RPType_dict),
        Int('Ref', Type='uint8'),
        ]

class RP_ACK(Layer):
    '''
    Net -> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict), # Pt = 2 or 3
        Int('Ref', Type='uint8'),
        Type4_TLV('Data', T=0x41, V=''), # length <= 234
        ]

class RP_ERROR(Layer):
    '''
    Net <-> MS
    '''
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='hex'),
        Bit('Type', BitLen=3, Repr='hum', Dict=RPType_dict), # Pt = 4 or 5
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
RP_selector = {
    0 : RP_DATA_MSToNET,
    1 : RP_DATA_NETToMS,
    2 : RP_ACK,
    3 : RP_ACK,
    4 : RP_ERROR,
    5 : RP_ERROR,
    6 : RP_SMMA,
    }

### Transport Protocol ###
# TS 23.040, section 9.2
# SMS-DELIVER (Net -> MS), SMS-DELIVER-REPORT (MS -> Net)
# SMS-SUBMIT (MS -> Net), SMS-SUBMIT-REPORT (Net -> MS)
# SMS-STATUS-REPORT (Net -> MS)
# SMS-COMMAND (MS > Net)

# 23.040, 9.2.3.1
TP_MTI_SCtoMS_dict = {
    0 : 'SMS-DELIVER',
    1 : 'SMS-SUBMIT-REPORT',
    2 : 'SMS-STATUS-REPORT',
    3 : 'Reserved',
    }
TP_MTI_MStoSC_dict = {
    0 : 'SMS-DELIVER-REPORT',
    1 : 'SMS-SUBMIT',
    2 : 'SMS-COMMAND',
    3 : 'Reserved',
    }

# 23.040, 9.2.3.2
TP_MMS_dict = {
    0 : 'More messages are waiting for the MS in this SC',
    1 : 'No more messages are waiting for the MS in this SC',
    }

# 23.040, 9.2.3.3
# linked to TP_VP (Validity Period)
TP_VPF_dict = {
    0 : 'TP VP field not present',
    1 : 'TP VP field present - relative format',
    2 : 'TP-VP field present - enhanced format',
    3 : 'TP VP field present - absolute format',
    }

# 23.040, 9.2.3.4
TP_SRI_dict = {
    0 : 'A status report shall not be returned',
    1 : 'A status report shall be returned',
    }

# 23.040, 9.2.3.5
TP_SRR_dict = {
    0 : 'A status report is not requested',
    1 : 'A status report is requested',
    }

# 23.040, 9.2.3.7, 9.2.3.8 and 9.2.3.14
# originator / destination addresses and BCD number
class TP_Address(BCDNumber):
    constructorList = [
        Int('Length', ReprName='length of digits', Type='uint8')] + \
        BCDNumber.constructorList
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Num
        self.Length.PtFunc = lambda n: len(repr(n))
        self.Num.Len = self.Length
        self.Num.LenFunc = lambda l: (l()+1)//2 if l()%2 else l()//2

class TP_Originating_Address(TP_Address):
    pass

class TP_Destination_Address(TP_Address):
    pass

class TP_Recipient_Address(TP_Address):
    pass

# OK, this is where is starts to get crappy ! (let's telex through SMS :)
# TS 23.040, section 9.2.3.9
TP_PID_format_dict = {
    0 : 'telematic indication',
    1 : 'no telematic indication',
    2 : 'Reserved',
    3 : 'protocol for SC specific use',
    }
TP_PID_telematic_dict = {
    0 : 'no telematic interworking, but SME-to-SME protocol',
    1 : 'telematic interworking',
    }
TP_PID_teleserv_dict = IANA_dict({
    0 : 'implicit - device type is specific to this SC, '\
        'or can be concluded on the basis of the address',
    1 : 'telex (or teletex reduced to telex format)',
    2 : 'group 3 telefax',
    3 : 'group 4 telefax',
    4 : 'voice telephone (i.e. conversion to speech)',
    5 : 'ERMES (European Radio Messaging System)',
    6 : 'National Paging system (known to the SC)',
    7 : 'Videotex (T.100 [20] /T.101 [21])',
    8 : 'teletex, carrier unspecified',
    9 : 'teletex, in PSPDN',
    10 : 'teletex, in CSPDN',
    11 : 'teletex, in analog PSTN',
    12 : 'teletex, in digital ISDN',
    13 : 'UCI (Universal Computer Interface, ETSI DE/PS 3 01 3)',
    14 : '(reserved, 2 combinations)',
    16 : 'a message handling facility (known to the SC)',
    17 : 'any public X.400 based message handling system',
    18 : 'Internet Electronic Mail',
    19 : '(reserved, 5 combinations)',
    24 : 'values specific to each SC, usage based on mutual agreement '\
         'between the SME and the SC (7 combinations available for each SC)',
    31 : 'A GSM/UMTS mobile station. The SC converts the SM from the received '\
         'TP Data Coding Scheme to any data coding scheme supported by that MS',
    })
TP_PID_serv_dict = IANA_dict({
    0 : 'Short Message Type 0',
    1 : 'Replace Short Message Type 1',
    2 : 'Replace Short Message Type 2',
    3 : 'Replace Short Message Type 3',
    4 : 'Replace Short Message Type 4',
    5 : 'Replace Short Message Type 5',
    6 : 'Replace Short Message Type 6',
    7 : 'Replace Short Message Type 7',
    8 : 'Reserved',
    30 : 'Enhanced Message Service (Obsolete)',
    31 : 'Return Call Message',
    32 : 'Reserved',
    60 : 'ANSI-136 R-DATA',
    61 : 'ME Data download',
    62 : 'ME De personalization Short Message',
    63 : '(U)SIM Data download', # for USAT, TS 51.011
    })
class TP_PID(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('Format', Pt=0, BitLen=2, Repr='hum', Dict=TP_PID_format_dict),
        Bit('Telematic', Pt=0, BitLen=1, Repr='hum', Dict=TP_PID_telematic_dict),
        Bit('Protocol', Pt=0, Repr='hum')
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # telematic and protocol field length
        self.Telematic.Trans = self.Format
        self.Telematic.TransFunc = lambda f: True if f() else False
        self.Protocol.BitLen = self.Format
        self.Protocol.BitLenFunc = lambda f: 5 if f() else 4
        # dictionnary selection
        self.Protocol.Dict = self.Format
        self.Protocol.DictFunc = self._get_dict
    
    def _get_dict(self, f):
        if f() == 0:
            if self.Telematic() == 1:
                return TP_PID_teleserv_dict
            else:
                return TP_PID_serv_dict
        elif f() == 1:
            return TP_PID_serv_dict
        else:
            return {}

# 23.040, 9.2.3.10
# DCS : Data Coding Scheme, see actually TS 23.038
TP_DCS_group_dict = {
    0 : 'General Data Coding',
    1 : 'Message Marked for Automatic Deletion Group',
    2 : 'Reserved coding groups',
    3 : 'Message Waiting Indication Group',
    }
TP_DCS_general_ext_dict = {
    0 : 'uncompressed - no class meaning',
    1 : 'uncompressed - class meaning',
    2 : 'compressed - no class meaning',
    3 : 'compressed - class meaning',
    }
TP_DCS_wait_ext_dict = {
    0 : 'Discard Message',
    1 : 'Store Message', # stored in the (U)SIM
    2 : 'Store Message', # stored in the (U)SIM
    3 : 'charset and class',
    }
TP_DCS_charset_dict = {
    0 : 'GSM 7 bit default alphabet',
    1 : '8 bit data',
    2 : 'UCS2 (16 bit)',
    3 : 'Reserved',
    }
TP_DCS_class_dict = {
    0 : 'Class 0',
    1 : 'Class 1 - Default meaning: ME-specific',
    2 : 'Class 2 - (U)SIM specific message',
    3 : 'Class 3 - Default meaning: TE specific',
    }
TP_DCS_indtype_dict = {
    0 : 'Voicemail Message Waiting',
    1 : 'Fax Message Waiting',
    2 : 'Electronic Mail Message Waiting',
    3 : 'Other Message Waiting',
    }
class TP_DCS(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('Group', Pt=0, BitLen=2, Repr='hum', Dict=TP_DCS_group_dict),
        Bit('GroupExt', Pt=0, BitLen=2, Repr='hum'),
        Bit('Charset', Pt=0, BitLen=2, Repr='hum', Dict=TP_DCS_charset_dict),
        Bit('Class', Pt=0, BitLen=2, Repr='hum'),
        Bit('IndActive', Pt=0, BitLen=1, Repr='hum'),
        Bit('Reserved', Pt=0, BitLen=1, Repr='hum'),
        Bit('IndType', Pt=0, BitLen=2, Repr='hum', Dict=TP_DCS_indtype_dict),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # 23.038, section 4
        # for group 0b11, without groupext 0b11, 
        # IndActive/Reserved/IndType are there
        self.IndActive.Trans = self.Group
        self.IndActive.TransFunc = self._lsb_type
        self.Reserved.Trans = self.Group
        self.Reserved.TransFunc = self._lsb_type
        self.IndType.Trans = self.Group
        self.IndType.TransFunc = self._lsb_type
        # otherwise, Class/Charset are there 
        #self.GroupExt.Trans = self.Group
        #self.GroupExt.TransFunc = lambda g: not self._lsb_type(g)
        self.Class.Trans = self.Group
        self.Class.TransFunc = lambda g: not self._lsb_type(g)
        self.Charset.Trans = self.Group
        self.Charset.TransFunc = lambda g: not self._lsb_type(g)
        # for group 0b00, 0b01 and group-groupext 0b1111
        self.GroupExt.Dict = self.Group
        self.GroupExt.DictFunc = lambda g: TP_DCS_general_ext_dict \
                                           if g() in (0, 1) else {}
        self.Class.Dict = self.Group
        self.Class.DictFunc = self._cl_1111
        self.Charset.Dict = self.Group
        self.Charset.DictFunc = self._cs_1111
    
    def _lsb_type(self, g):
        if g() == 0b11 and self.GroupExt() in (0, 1, 2):
            return False
        else:
            return True
        
    def _cl_1111(self, g):
        if g() in (0, 1) and self.GroupExt() in (1, 3):
            return TP_DCS_class_dict
        elif g() == 3 and self.GroupExt() == 3:
            return TP_DCS_class_dict
        else:
            return {}
     
    def _cs_1111(self, g):
        if g() in (0, 1):
            return TP_DCS_charset_dict
        elif g() == 3 and self.GroupExt() == 3:
            return TP_DCS_charset_dict
        else:
            return {}

# timestamp and time representation
# 23.040, 9.2.3.12

# 7 bytes, bcd-style timestamp representation
class TP_SCTS(Layer):
    constructorList = [
        StrBCD('Year', Len=1),
        StrBCD('Month', Len=1),
        StrBCD('Day', Len=1),
        StrBCD('Hour', Len=1),
        StrBCD('Minutes', Len=1),
        StrBCD('Seconds', Len=1),
        Bit('TimeZone', Pt=0x80, BitLen=8),
        ]
    _bcd_fields = ('Year', 'Month', 'Day', 'Hour', 'Minutes', 'Seconds')
    
    def __init__(self, **kwargs):
        # safely initialize the layer
        Layer.__init__(self, **kwargs)
        # re-encode StrBCD fields properly
        self.encode(**kwargs)
    
    def encode(self, **kwargs):
        for arg in kwargs:
            if arg in self._bcd_fields:
                getattr(self, arg).encode(self._conv_num(kwargs[arg]))
    
    def _conv_num(self, num=0):
        # if num is a string, ensure it has a length of 2, or insert a '0'
        if isinstance(num, str):
            if len(num) == 0 or not num.isdigit():
                return '00'
            if len(num) >= 2:
                return num[:2]
            else:
                return '0%s' % num
        elif isinstance(num, int):
            if 0 <= num <= 9:
                return '0%i' % num
            elif 10 <= num <= 99:
                return str(num)
            elif num >= 100:
                return str(num)[-2:]
        return '00'

# 23.040, 9.2.3.12.1
class TP_VP_rel(Int):
    def __repr__(self):
        if self.Repr == 'hum' \
        and (self.Pt is not None or self.Val is not None):
            return self.interpret()
        else:
            return Int.__repr__(self)
    
    def interpret(self):
        val = self()
        if 0 <= val <= 143:
            return '%i minutes' % (val+1)*5
        elif 144 <= val <= 167:
            return '%.1f hours' % 12+((val-143)*0.5)
        elif 168 <= val <= 196:
            return '%i days' % val-166
        else:
            return '%i weeks' % val-192

# 23.040, 9.2.3.12.2
class TP_VP_abs(TP_SCTS):
    pass

# 23.040, 9.2.3.12.3
#class TP_VP_enh(Layer):
#    constructorList = [
#        ]
# actually, that's a crappy 7-bytes string...

# 23.040, 9.2.3.13
class TP_DT(TP_SCTS):
    pass


# TP-STATUS info
TP_status_dict = {
    0 : 'Short message transaction completed - Short message received '\
        'by the SME',
    1 : 'Short message transaction completed - Short message forwarded '\
        'by the SC to the SME but the SC is unable to confirm delivery',
    2 : 'Short message transaction completed - Short message replaced '\
        'by the SC',
    3 : 'Short message transaction completed - reserved',
    16 : 'Short message transaction completed - SC specific',
    32 : 'Temporary error, SC still trying to transfer SM - Congestion',
    33 : 'Temporary error, SC still trying to transfer SM - SME busy',
    34 : 'Temporary error, SC still trying to transfer SM - No response '\
         'from SME',
    35 : 'Temporary error, SC still trying to transfer SM - Service rejected',
    36 : 'Temporary error, SC still trying to transfer SM - '\
         'Quality of service not available',
    37 : 'Temporary error, SC still trying to transfer SM - Error in SME',
    38 : 'Temporary error, SC still trying to transfer SM - reserved',
    48 : 'Temporary error, SC still trying to transfer SM - SC specific',
    64 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Remote procedure error',
    65 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Incompatible destination',
    66 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Connection rejected by SME',
    67 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Not obtainable',
    68 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Quality of service not available',
    69 : 'Permanent error, SC is not making any more transfer attempts - '\
         'No interworking available',
    70 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Validity Period Expired',
    71 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Deleted by originating SME',
    72 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Deleted by SC Administration',
    73 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM does not exist',
    74 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Reserved',
    80 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SC specific',
    96 : 'Temporary error, SC is not making any more transfer attempts - '\
         'Congestion',
    97 : 'Temporary error, SC is not making any more transfer attempts - '\
         'SME busy',
    98 : 'Temporary error, SC is not making any more transfer attempts - '\
         'No response from SME',
    99 : 'Temporary error, SC is not making any more transfer attempts - '\
         'Service rejected',
    100 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Quality of service not available',
    101 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Error in SME',
    102 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Reserved',
    112 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Values specific to each SC',
    }

# TP-RP flag
TP_RP_dict = {
    0 : 'TP Reply Path parameter is not set in this SMS SUBMIT/DELIVER',
    1 : 'TP Reply Path parameter is set in this SMS SUBMIT/DELIVER',
    }

# TP-Command-Type
TP_CT_dict = IANA_dict({
    0 : 'Enquiry relating to previously submitted short message',
    1 : 'Cancel Status Report Request relating to previously '\
        'submitted short message',
    2 : 'Delete previously submitted Short Message', 
    3 : 'Enable Status Report Request relating to previously '\
        'submitted Short Message',
    4 : 'Reserved',
    224 : 'SC specific',
    })

# TP-Failure-Cause
TP_FCS_dict = IANA_dict({
    0 : 'Reserved',
	0x80 : 'TP-PID error : telematic interworking not supported',
    0x81 : 'TP-PID error : short message Type 0 not supported',
    0x82 : 'TP-PID error : cannot replace short message',
    0x83 : 'TP-PID error : reserved',
    0x8F : 'Unspecified TP-PID error',
	0x90 : 'TP-DCS error : data coding scheme (alphabet) not supported',
    0x91 : 'TP-DCS error : message class not supported',
    0x92 : 'TP-DCS error : reserved',
    0x9F : 'Unspecified TP-DCS error',
    0xA0 : 'TP-Command Error : command cannot be actioned',
    0xA1 : 'TP-Command Error : Command unsupported',
    0xA2 : 'TP-Command Error : reserved',
    0xAF : 'Unspecified TP-Command error',
    0xB0 : 'TPDU not supported',
    0xB1 : 'TPDU not supported : reserved',
    0xC0 : 'SC busy',
    0xC1 : 'No SC subscription',
    0xC2 : 'SC system failure',
    0xC3 : 'Invalid SME address',
    0xC4 : 'Destination SME barred',
    0xC5 : 'SM Rejected-Duplicate SM',
    0xC6 : 'TP-VPF not supported',
    0xC7 : 'TP-VP not supported',
    0xC8 : 'Reserved',
    0xD0 : '(U)SIM SMS storage full',
    0xD1 : 'No SMS storage capability in (U)SIM',
    0xD2 : 'Error in MS',
    0xD3 : 'Memory Capacity Exceeded',
    0xD4 : '(U)SIM Application Toolkit Busy',
    0xD5 : '(U)SIM data download error',
    0xD6 : 'Reserved',
    0xE0 : 'Values specific to an application',
    0xFF : 'Unspecified error cause',
    })

# TP-User-Data-Header-Indicator
TP_UDHI_dict = {
    0 : 'The TP UD field contains only the short message',
    1 : 'The beginning of the TP UD field contains a Header '\
        'in addition to the short message',
    }

# User Data Header parameters in TP-User-Data:
# ... lot of fun, here !
TP_UDHType_dict = IANA_dict({
    0x0 : 'Concatenated short messages, 8-bit reference number',
    0x1 : 'Special SMS Message Indication',
    0x2 : 'Reserved',
    0x3 : 'Value not used to avoid misinterpretation as <LF> character',
    0x4 : 'Application port addressing scheme, 8 bit address',
    0x5 : 'Application port addressing scheme, 16 bit address',
    0x6 : 'SMSC Control Parameters',
    0x7 : 'UDH Source Indicator',
    0x8 : 'Concatenated short message, 16-bit reference number',
    0x9 : 'Wireless Control Message Protocol',
    0x0A : 'Text Formatting',
    0x0B : 'Predefined Sound',
    0x0C : 'User Defined Sound (iMelody max 128 bytes)',
    0x0D : 'Predefined Animation',
    0x0E : 'Large Animation (16*16 times 4 = 32*4 =128 bytes)',
    0x0F : 'Small Animation (8*8 times 4 = 8*4 =32 bytes)',
    0x10 : 'Large Picture (32*32 = 128 bytes)',
    0x11 : 'Small Picture (16*16 = 32 bytes)',
    0x12 : 'Variable Picture',
    0x13 : 'User prompt indicator',
    0x14 : 'Extended Object',
    0x15 : 'Reused Extended Object',
    0x16 : 'Compression Control',
    0x17 : 'Object Distribution Indicator',
    0x18 : 'Standard WVG object',
    0x19 : 'Character Size WVG object',
    0x1A : 'Extended Object Data Request Command',
    0x1B : 'Reserved for future EMS features (see subclause 3.10)',
    0x20 : 'RFC 822 E-Mail Header',
    0x21 : 'Hyperlink format element',
    0x22 : 'Reply Address Element',
    0x23 : 'Enhanced Voice Mail Information',
    0x24 : 'National Language Single Shift',
    0x25 : 'National Language Locking Shift',
    0x26 : 'Reserved for future use',
    0x70 : '(U)SIM Toolkit Security Headers',
    0x80 : 'SME to SME specific use',
    0xA0 : 'Reserved for future use',
    0xC0 : 'SC specific use',
    0xE0 : 'Reserved for future use',
    })

class TP_UDH_TLV(Layer):
    constructorList = [
        Int('Type', Type='uint8', Dict=TP_UDHType_dict),
        Int('Length', Type='uint8'),
        Str('Value', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Value
        self.Length.PtFunc = lambda v: len(v)
        self.Value.Len = self.Length
        self.Value.LenFunc = lambda l: l()


# TP-Status-Report-Qualifier
TP_SRQ_dict = {
    0 : 'The SMS STATUS REPORT is the result of a SMS SUBMIT',
    1 : 'The SMS STATUS REPORT is the result of an SMS COMMAND',
    }

# TP-Parameter-Indicator
class TP_PI(Layer):
    constructorList = [
        Bit('Ext', Pt=0, BitLen=1),
        Bit('Res', Pt=0, BitLen=4),
        Bit('TP-UDL', Pt=0, BitLen=1),
        Bit('TP-DCS', Pt=0, BitLen=1),
        Bit('TP-PID', Pt=0, BitLen=1),
        ]

# GSM septet encoding: see TS 23.038
class Str7b(Str):
    
    def decode(self):
        if len(self) == 0:
            return ''
        # get the string buffer and reverse its bytes
        buf = ''.join([c for c in reversed(self())])
        buflen = len(buf)*8
        # use shtr to shift the string buffer
        buf = shtr(buf)
        # count number of chars and remove padding bits
        chars_num = buflen//7
        buf = buf << buflen - (7*chars_num)
        # consume 7 bit by 7 bit
        chars = []
        for i in range(chars_num):
            chars.append(buf.left_val(7))
            buf = buf << 7
        # revert back the list of decoded character and return it
        chars.reverse()
        return ''.join(map(chr, chars))
    
    def encode(self, text=''):
        # FlUxIuS encoding
        new=''
        bit=0
        for i in range(len(text)):
            if bit > 7:
                bit=0
            mask = (0Xff >> (7-bit))
            if i < len(text)-1:
                group=(ord(text[i+1]) & mask)
            else:
                group=0
            add = (group << 7-bit)
            if bit != 7:
                new+=chr((ord(text[i]) >> bit) | add)
            bit+=1
        self < None
        self > new
    
    def __repr__(self):
        if self.Repr == 'hum' \
        and (self.Pt is not None or self.Val is not None):
            return self.decode()
        else:
            return Str.__repr__(self)
    

# 23.040, section 9.2.2.1
class SMS_DELIVER(Layer):
    constructorList = [
        Bit('TP_SRI', ReprName='TP Status Report Indication', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_SRI_dict),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('TP_RP', ReprName='TP Reply Path', Pt=0, BitLen=1, Repr='hum', \
            Dict=TP_RP_dict),
        Bit('TP_LP', ReprName='TP Loop Prevention', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_MMS', ReprName='TP More Messages to Send', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_MMS_dict),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_SCtoMS_dict),
        TP_Originating_Address(), # length 2-12
        TP_PID(),
        TP_DCS(),
        TP_SCTS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))

# 23.040, section 9.2.2.1a
class SMS_DELIVER_REPORT_RP_ERROR(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=4),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_MStoSC_dict),
        Int('TP_FCS', ReprName='Failure Cause', Pt=0, Type='uint8', \
            Dict=TP_FCS_dict), # only on RP-ERROR
        TP_PI(),
        TP_PID(),
        TP_DCS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        if not with_options:
            self.TP_PID.Trans = True
            self.TP_DCS.Trans = True
            self.TP_UDL.Trans = True
            self.TP_UD.Trans = True
    
    def map(self, s=''):
        s_len = len(s)
        if s_len < 7:
            self.TP_UD.Trans = True
        if s_len < 6:
            self.TP_UDL.Trans = True
        if s_len < 5:
            self.TP_DCS.Trans = True
        if s_len < 4:
            self.TP_PID.Trans = True
        Layer.map(self, s)

class SMS_DELIVER_REPORT_RP_ACK(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=4),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_MStoSC_dict),
        TP_PI(),
        TP_PID(),
        TP_DCS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        if not with_options:
            self.TP_PID.Trans = True
            self.TP_DCS.Trans = True
            self.TP_UDL.Trans = True
            self.TP_UD.Trans = True
    
    def map(self, s=''):
        s_len = len(s)
        if s_len < 6:
            self.TP_UD.Trans = True
        if s_len < 5:
            self.TP_UDL.Trans = True
        if s_len < 4:
            self.TP_DCS.Trans = True
        if s_len < 3:
            self.TP_PID.Trans = True
        Layer.map(self, s)

# 23.040, section 9.2.2.2
class SMS_SUBMIT(Layer):
    constructorList = [
        Bit('TP_SRR', ReprName='TP Status Report Request', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_SRR_dict),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('TP_RP', ReprName='TP Reply Path', Pt=0, BitLen=1, Repr='hum', \
            Dict=TP_RP_dict),
        Bit('TP_VPF', ReprName='TP Validity Period Format', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_VPF_dict),
        Bit('TP_RD', ReprName='TP Reject Duplicates', Pt=0, BitLen=1),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=1, BitLen=2, \
            Repr='hum', Dict=TP_MTI_MStoSC_dict),
        Int('TP_MR', ReprName='TP Message Reference', Pt=0, Type='uint8'),
        TP_Destination_Address(), # length 2-12
        TP_PID(),
        TP_DCS(),
        Str('TP_VP', Pt='', Len=0), # optional, 0, 1 or 7 bytes...
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        # Validity Period automation
        self.TP_VP.Len = self.TP_VPF
        self.TP_VP.LenFunc = self._vp_len
    
    def _vp_len(self, vpf):
        val = vpf()
        if not val:
            return 0
        elif val == 1:
            return 1
        elif val in (2, 3):
            return 7
    
    def map(self, s=''):
        Layer.map(self, s)
        # additional VP interpretation
        val = self.TP_VPF()
        if val == 1:
            vp = TP_VP_rel()
            vp.map( self.TP_VP() )
            self.replace( self.TP_VP, vp )
        elif val == 3:
            vp = TP_VP_abs()
            vp.map( self.TP_VP() )
            self.replace( self.TP_VP, vp )

# 23.040, 9.2.2.2a
class SMS_SUBMIT_REPORT_RP_ERROR(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=4),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_SCtoMS_dict),
        Int('TP_FCS', ReprName='Failure Cause', Pt=0, Type='uint8', \
            Dict=TP_FCS_dict), # only on RP-ERROR
        TP_PI(),
        TP_SCTS(),
        TP_PID(),
        TP_DCS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        if not with_options:
            self.TP_PID.Trans = True
            self.TP_DCS.Trans = True
            self.TP_UDL.Trans = True
            self.TP_UD.Trans = True
    
    def map(self, s=''):
        s_len = len(s)
        if s_len < 14:
            self.TP_UD.Trans = True
        if s_len < 13:
            self.TP_UDL.Trans = True
        if s_len < 12:
            self.TP_DCS.Trans = True
        if s_len < 11:
            self.TP_PID.Trans = True
        Layer.map(self, s)

class SMS_SUBMIT_REPORT_RP_ACK(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=4),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_SCtoMS_dict),
        TP_PI(),
        TP_SCTS(),
        TP_PID(),
        TP_DCS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        if not with_options:
            self.TP_PID.Trans = True
            self.TP_DCS.Trans = True
            self.TP_UDL.Trans = True
            self.TP_UD.Trans = True
    
    def map(self, s=''):
        s_len = len(s)
        if s_len < 13:
            self.TP_UD.Trans = True
        if s_len < 12:
            self.TP_UDL.Trans = True
        if s_len < 11:
            self.TP_DCS.Trans = True
        if s_len < 10:
            self.TP_PID.Trans = True
        Layer.map(self, s)

# 23.040, 9.2.2.3
class SMS_STATUS_REPORT(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('TP_SRQ', ReprName='TP Status Report Qualifier', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_SRI_dict),
        Bit('TP_LP', ReprName='TP Loop Prevention', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_MMS', ReprName='TP More Messages to Send', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_MMS_dict),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_SCtoMS_dict),
        Int('TP_MR', ReprName='TP Message Reference', Pt=0, Type='uint8'),
        TP_Recipient_Address(), # length 2-12
        TP_SCTS(),
        TP_DT(),
        Int('TP_ST', ReprName='TP Status', Pt=0, Type='uint8', \
            Dict=TP_status_dict),
        TP_PI(),
        TP_PID(),
        TP_DCS(),
        Int('TP_UDL', ReprName='User Data Length (in character)', Pt=0, \
            Type='uint8'),
        Str7b('TP_UD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_UDL.Pt = self.TP_UD
        self.TP_UDL.PtFunc = lambda d: len(d.decode())
        self.TP_UD.Len = self.TP_UDL
        self.TP_UD.LenFunc = lambda l: int(ceil(l()*7.0/8))
        if not with_options:
            self.TP_PI.Trans = True
            self.TP_PID.Trans = True
            self.TP_DCS.Trans = True
            self.TP_UDL.Trans = True
            self.TP_UD.Trans = True
    
    def map(self, s=''):
        s_len = len(s)
        Layer.map(self, s)
        addr_len = len(self.TP_Recipient_Address)
        if s_len < 22+addr_len:
            self.TP_UD.Trans = True
        if s_len < 21+addr_len:
            self.TP_UDL.Trans = True
        if s_len < 20+addr_len:
            self.TP_DCS.Trans = True
        if s_len < 19+addr_len:
            self.TP_PID.Trans = True
        if s_len < 18+addr_len:
            self.TP_PI.Trans = True
    
# 23.040, 9.2.2.4
class SMS_COMMAND(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('TP_UDHI', ReprName='TP User Data Header Indicator', Pt=0, BitLen=1),
        Bit('TP_SRR', ReprName='TP Status Report Request', Pt=0, BitLen=1, \
            Repr='hum', Dict=TP_SRR_dict),
        Bit('spare', Pt=0, BitLen=3),
        Bit('TP_MTI', ReprName='TP Message Type Indicator', Pt=0, BitLen=2, \
            Repr='hum', Dict=TP_MTI_MStoSC_dict),
        Int('TP_MR', ReprName='TP Message Reference', Pt=0, Type='uint8'),
        TP_PID(),
        Int('TP_CT', ReprName='TP Command Type', Pt=0, Type='uint8', \
            Dict=TP_CT_dict),
        Int('TP_MN', ReprName='TP Message Number', Pt=0, Type='uint8'),
        TP_Destination_Address(), # length 2-12
        Int('TP_CDL', ReprName='TP Command Data Length', Type='uint8'),
        Str('TP_CD', Pt=''),
        ]
    def __init__(self, with_options=False, **kwargs):
        Layer.__init__(self, **kwargs)
        self.TP_CDL.Pt = self.TP_CD
        self.TP_CDL.PtFunc = lambda d: len(d)
        self.TP_CD.Len = self.TP_CDL
        self.TP_CD.LenFunc = lambda l: l()
