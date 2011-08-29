#/**
# * Software Name : libmich 
# * Version : 0.2.1 
# *
# * Copyright © 2011. Benoit Michau. France Telecom.
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
# * File Name : formats/L3GSM_RR.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer, show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.L3Mobile_24007 import Type1_TV, Type2, Type3_V, Type3_TV, \
     Type4_LV, Type4_TLV, PD_dict, Layer3


# TS 44.006 defines data link format
# which carry signalling for 2G mobile networks
#
# section 5: 
# Frame structure for p2p communication
#
# It's going to rock! (again...)
#
# 44006, section 5.1
# frame Bbis, for BCCH, PCH, NCH, AGCH
# this is what gsm-receiver gets by default
#
# TS 44.018 defines Radio Ressource Control protocol
# which is carried over the data-link
#
# section 8: basic structures
# section 9: messages stuctures (pffff...)
# section 10: general aspect and IE coding

# Defining a Str class that will handle '2b' padding
class StrRR(Str):
    _padding_bye = '\x2b'
    
    # building basic methods for manipulating easily the Element from its attributes
    def __call__(self):
        # when Len has fixed value:
        if self.LenFunc is not None:
            if self.safe: assert(type(self.LenFunc(self.Len)) is int)
            l = self.LenFunc(self.Len)
        elif type(self.Len) is int: 
            l = self.Len
        else: 
            l = None
        # when no values are defined at all:
        if self.Val is None and self.Pt is None: 
            if l: return l * self._padding_byte
            else: return ''
        # returning the right string:
        # if defined, self.Val overrides self.Pt capabilities
        elif self.Val is not None: 
            return str(self.Val)[:l]
        # else: use self.Pt capabilities to get the string
        elif self.PtFunc is not None: 
            if self.safe: 
                assert( type(self.PtFunc(self.Pt)) is str )
            return self.PtFunc(self.Pt)[:l]
        else:
            if self.safe: 
                assert( type(self.Pt) is str )
            return str(self.Pt)[:l]


# Actually, this is not truly part of L3, but from the 
# data link layer
#
# 44006, section 6.2
# Address field
class AddressRR(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('LPD', Pt=0, BitLen=2),
        Bit('SAPI', Pt=0, BitLen=4),
        Bit('CR', ReprName='Command / Response', Pt=0, BitLen=1),
        Bit('EA', ReprName='No extension', Pt=1, BitLen=1)]

# 44006, section 6.6
# Length indicator field
class LengthRR(Layer):
    constructorList = [
        Bit('len', Pt=0, BitLen=6),
        Bit('M', ReprName='More data bit', Pt=0, BitLen=1),
        Bit('EL', ReprName='Length field not extended', Pt=1, BitLen=1)]



##################
# This is truly L3
# 44018, section 10.1
# Header field
#
# 44018, section 9.1
# RRC procedures dictionnary
GSM_RR_dict = {
    0:'SYSTEM INFORMATION TYPE 13',
    1:'SYSTEM INFORMATION TYPE 14',
    2:'SYSTEM INFORMATION TYPE 2bis',
    3:'SYSTEM INFORMATION TYPE 2ter',
    4:'SYSTEM INFORMATION TYPE 9',
    5:'SYSTEM INFORMATION TYPE 5bis',
    6:'SYSTEM INFORMATION TYPE 5ter',
    7:'SYSTEM INFORMATION TYPE 2quater',
    9:'VGCS UPLINK GRANT',
    10:'PARTIAL RELEASE',
    13:'CHANNEL RELEASE',
    14:'UPLINK RELEASE',
    15:'PARTIAL RELEASE COMPLETE',
    16:'CHANNEL MODE MODIFY',
    17:'TALKER INDICATION',
    18:'RR STATUS',
    19:'CLASSMARK ENQUIRY',
    20:'FREQUENCY REDEFINITION',
    21:'MEASUREMENT REPORT',
    22:'CLASSMARK CHANGE',
    22:'MBMS ANNOUNCEMENT',
    23:'CHANNEL MODE MODIFY ACKNOWLEDGE',
    24:'SYSTEM INFORMATION TYPE 8',
    25:'SYSTEM INFORMATION TYPE 1',
    26:'SYSTEM INFORMATION TYPE 2',
    27:'SYSTEM INFORMATION TYPE 3',
    28:'SYSTEM INFORMATION TYPE 4',
    29:'SYSTEM INFORMATION TYPE 5',
    30:'SYSTEM INFORMATION TYPE 6',
    31:'SYSTEM INFORMATION TYPE 7',
    32:'NOTIFICATION/NCH',
    33:'PAGING REQUEST TYPE 1',
    34:'PAGING REQUEST TYPE 2',
    36:'PAGING REQUEST TYPE 3',
    38:'NOTIFICATION/RESPONSE',
    39:'PAGING RESPONSE',
    40:'HANDOVER FAILURE',
    41:'ASSIGNMENT COMPLETE',
    42:'UPLINK BUSY',
    43:'HANDOVER COMMAND',
    44:'HANDOVER COMPLETE',
    45:'PHYSICAL INFORMATION',
    46:'ASSIGNMENT COMMAND',
    47:'ASSIGNMENT FAILURE',
    48:'CONFIGURATION CHANGE COMMAND',
    49:'CONFIGURATION CHANGE ACK',
    50:'CIPHERING MODE COMPLETE',
    51:'CONFIGURATION CHANGE REJECT',
    52:'GPRS SUSPENSION REQUEST',
    53:'CIPHERING MODE COMMAND',
    54:'EXTENDED MEASUREMENT REPORT',
    54:'SERVICE INFORMATION',
    55:'EXTENDED MEASUREMENT ORDER',
    56:'APPLICATION INFORMATION',
    57:'IMMEDIATE ASSIGNMENT EXTENDED',
    58:'IMMEDIATE ASSIGNMENT REJECT',
    59:'ADDITIONAL ASSIGNMENT',
    61:'SYSTEM INFORMATION TYPE 16',
    62:'SYSTEM INFORMATION TYPE 17',
    63:'IMMEDIATE ASSIGNMENT',
    64:'SYSTEM INFORMATION TYPE 18',
    65:'SYSTEM INFORMATION TYPE 19',
    66:'SYSTEM INFORMATION TYPE 20',
    67:'SYSTEM INFORMATION TYPE 15',
    68:'SYSTEM INFORMATION TYPE 13alt',
    69:'SYSTEM INFORMATION TYPE 2n',
    70:'SYSTEM INFORMATION TYPE 21',
    72:'DTM ASSIGNMENT FAILURE',
    73:'DTM REJECT',
    74:'DTM REQUEST',
    75:'PACKET ASSIGNMENT',
    76:'DTM ASSIGNMENT COMMAND',
    77:'DTM INFORMATION',
    78:'PACKET NOTIFICATION',
    96:'UTRAN CLASSMARK CHANGE',
    98:'CDMA 2000 CLASSMARK CHANGE',
    99:'INTER SYSTEM TO UTRAN HANDOVER COMMAND',
    100:'INTER SYSTEM TO CDMA2000 HANDOVER COMMAND',
    101:'GERAN IU MODE CLASSMARK CHANGE',
    102:'PRIORITY UPLINK REQUEST',
    103:'DATA INDICATION',
    104:'DATA INDICATION 2'}

Cause_dict = {
    0:'Normal event',
    1:'Abnormal release, unspecified',
    2:'Abnormal release, channel unacceptable',
    3:'Abnormal release, timer expired',
    4:'Abnormal release, no activity on the radio path',
    5:'Preemptive release',
    6:'UTRAN configuration unknown',
    8:'Handover impossible, timing advance out of range',
    9:'Channel mode unacceptable',
    10:'Frequency not implemented',
    11:'Originator or talker leaving group call area',
    12:'Lower layer failure',
    65:'Call already cleared',
    95:'Semantically incorrect message',
    96:'Invalid mandatory information',
    97:'Message type non-existent or not implemented',
    98:'Message type not compatible with protocol state',
    100:'Conditional IE error',
    101:'No cell allocation available',
    111:'Protocol error unspecified'}

# 44018, section 10.1
# standard RRC header
class Header(Layer):
    constructorList = [
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=GSM_RR_dict),
        ]
    def __init__(self, prot=6, type=18):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type


##################
# 44018, section 9
# RRC messages
##################

# 44018, section 9.1.2
class ASSIGNMENT_COMMAND(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    ChanDesc2: description of the 1st channel, after time, 3 bytes
    PowCmd: power command, 1 byte
    ... too much options ...
    '''
    constructorList = [ie for ie in Header(6, 46)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Str('ChanDesc2', ReprName='Chann Description 2', Pt='\0\0\0', \
                 Len=3),
             Str('PowCmd', ReprName='Power Command', Pt='\0', Len=1),
             Type4_TLV('FreqList', ReprName='Frequency list, after time', \
                       T=0x05, V='\0\0'),
             Type3_TV('CellChanDesc', ReprName='Cell Channel description', \
                      T=0x62, V=16*'\0', len=16),
             Type4_TLV('MultAlloc', ReprName='Multi-slot allocation', \
                       T=0x10, V='\0'),
             Type3_TV('ChanSet1', ReprName='Channel Set 1', T=0x63, \
                      V='\0', len=1),
             Type3_TV('ChanSet2', ReprName='Channel Set 2', T=0x11, \
                      V='\0', len=1),
             Type3_TV('ChanSet3', ReprName='Channel Set 3', T=0x13, \
                      V='\0', len=1),
             Type3_TV('ChanSet4', ReprName='Channel Set 4', T=0x14, \
                      V='\0', len=1),
             Type3_TV('ChanSet5', ReprName='Channel Set 5', T=0x15, \
                      V='\0', len=1),
             Type3_TV('ChanSet6', ReprName='Channel Set 6', T=0x16, \
                      V='\0', len=1),
             Type3_TV('ChanSet7', ReprName='Channel Set 7', T=0x17, \
                      V='\0', len=1),
             Type3_TV('ChanSet8', ReprName='Channel Set 8', T=0x18, \
                      V='\0', len=1),
             Type3_TV('ChanDesc2', ReprName='2nd channel description, after time', \
                      T=0x64, V='\0\0\0', len=3),
             Type3_TV('ChanMod2', ReprName='Channel Mode 2', T=0x64, \
                      V='\0', len=1),
             Type4_TLV('MobAlloc', ReprName='Mobile allocation', T=0x72, \
                       V='\0'),
             Type3_TV('Start', ReprName='Starting time', T=0x7C, \
                      V='\0\0', len=2),
             Type4_TLV('FreqListB', ReprName='Frequency list, before time', \
                       T=0x19, V='\0\0'),
             Type3_TV('ChanDescB', ReprName='1st channel description, before time', \
                      T=0x1C, V='\0\0\0', len=3),
             Type3_TV('ChanDesc2B', ReprName='2nd channel description, before time', \
                      T=0x1D, V='\0\0\0', len=3),
             Type3_TV('FreqChanSeq', ReprName='Frequency channel sequence', \
                      T=0x1E, V=9*'\0', len=9),
             Type4_TLV('MobAllocB', ReprName='Mobile allocation, before time', \
                       T=0x21, V='\0'),
             Type2('CiphMod', ReprName='Cipher mode setting', T=0x09),
             Type4_TLV('VGCSind', ReprName='VGCS target mode indication', \
                       T=0x01, V='\0'),
             Type4_TLV('MRconf', ReprName='Multi-rate config', T=0x03, V='\0\0'),
             Type4_TLV('VGCSciph', ReprName='VGCS ciphering parameters', \
                       T=0x04, V='\0')])
        self._post_init(with_options)

# 44018, section 9.1.3
class ASSIGNMENT_COMPLETE(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    RR Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(6, 41)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])
 
# 44018, section 9.1.4
class ASSIGNMENT_FAILURE(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    RR Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(6, 47)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])

# 44018, section 9.1.7
class CHANNEL_RELEASE(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    
    '''
    constructorList = [ie for ie in Header(6, 13)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])
#


# 44018, section 9.1.18
class IMMEDIATE_ASSIGNMENT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Page mode: 4 bits
    Dedicated mode: 4 bits, can be ignore by ME
    Channel description: 3 bytes, conditional to Dedicated mode
    Packet channel description: 3 bytes, conditional to Dedicated mode
    ... options ...
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 63)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Bit('Page', ReprName='Page mode', Pt=0, BitLen=4),
             Bit('Dedi', ReprName='Dedicated mode or TBF', Pt=0, BitLen=4),
             Str('ChanDesc', ReprName='Channel description', \
                 Pt='\0\0\0', Len=3),
             Str('pChanDesc', ReprName='Packet channel description', \
                Pt='\0\0\0', Len=3),
             Str('ReqRef', ReprName='Request reference', Pt='\0\0\0', \
                 Len=3),
             Str('TimeAdv', ReprName='Timing advance', Pt='\0', Len=1),
             Type4_LV('MobAlloc', ReprName='Mobile allocation', V=''),
             Type3_TV('Start', ReprName='Starting time', T=0x7C, \
                      V='\0\0', ),
             StrRR('IArest', ReprName='IA rest octets')])
        self._post_init(with_options)
        # Now, automatic fields
        # L2 pseudo header
        self.len.Pt = (self.MobAlloc, self.Start)
        self.len.PtFunc = lambda L: sum(map(len, L))+14
        self.IArest.Len = self.len
        self.IArest.LenFunc = lambda l: 22-l()-len(l)
        # TODO: handle correctly dedicated chan assignment and IE
        self.ChanDesc.Trans = self.Dedi
        self.ChanDesc.TransFunc = lambda dedi: False
        self.pChanDesc.Trans = self.Dedi
        self.pChanDesc.TransFunc = lambda dedi: False

# 44018, section 9.1.22
class PAGING_REQUEST_1(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Page mode: 4 bits
    
    ... options ...
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 33)]
    def __init__(self, with_options=True):
        Layer3.__init__(self)
        self.extend( \
            [Bit('Page', ReprName='Page mode', Pt=0, BitLen=4),
             Bit('ChanNeed', ReprName='Channel needed', Pt=0, BitLen=4),
             Type4_LV('ID', V=ID()),
             Type4_TLV('ID2', T=0x17, V=ID()),
             StrRR('IArest', ReprName='IA rest octets')])
        self._post_init(with_options)
        # Now, automatic fields
        # L2 pseudo header
        self.len.Pt = (self.ID, self.ID2)
        self.len.PtFunc = lambda L: sum(map(len, L))+3
        self.IArest.Len = self.len
        self.IArest.LenFunc = lambda l: 22-l()-len(l)

# 44018, section 9.1.25
class PAGING_RESPONSE(Layer3):
    pass
    
# 44018, section 9.1.23
class PAGING_REQUEST_2(Layer3):
    pass

# 44018, section 9.1.24
class PAGING_REQUEST_3(Layer3):
    pass

# 44018, section 9.1.31
class SYSTEM_INFO_1(Layer3):
    pass

# 44018, section 9.1.32
class SYSTEM_INFO_2(Layer3):
    pass

# 44018, section 9.1.33
class SYSTEM_INFO_2BIS(Layer3):
    pass

# 44018, section 9.1.34
class SYSTEM_INFO_2TER(Layer3):
    pass

# 44018, section 9.1.34a
class SYSTEM_INFO_2QUATER(Layer3):
    pass

# 44018, section 9.1.34b
class SYSTEM_INFO_2N(Layer3):
    pass

# 44018, section 9.1.35
class SYSTEM_INFO_3(Layer3):
    pass

# 44018, section 9.1.36
class SYSTEM_INFO_4(Layer3):
    pass

# 44018, section 9.1.43a
class SYSTEM_INFO_13(Layer3):
    pass




