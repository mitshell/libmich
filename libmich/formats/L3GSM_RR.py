# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2011. Benoit Michau. France Telecom. ANSSI.
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

__all__ = ['ASSIGNMENT_COMMAND', 'ASSIGNMENT_COMPLETE', 'ASSIGNMENT_FAILURE',
           'CHANNEL_RELEASE', 'MEASUREMENT_REPORT',
           'CLASSMARK_ENQUIRY', 'CLASSMARK_CHANGE',
           'CIPHERING_MODE_COMMAND', 'CIPHERING_MODE_COMPLETE',
           'IMMEDIATE_ASSIGNMENT', 'PAGING_REQUEST_1', 'PAGING_REQUEST_2',
           'PAGING_REQUEST_3', 'PAGING_RESPONSE',
           'SI_1', 'SI_2', 'SI_2bis', 'SI_2ter', 'SI_2quater', 'SI_3',
           'SI_4', 'SI_5', 'SI_5bis', 'SI_5ter', 'SI_6', 'SI_13',
           'RestOctets', 'GSM_RR_dict']

# convinience
#from binascii import unhexlify as unh
#
from libmich.core.element import Bit, Int, Str, Layer, show, showattr, log, \
    ERR, WNG, DBG
from libmich.core.IANA_dict import IANA_dict
from .L3Mobile_24007 import *
from .L2GSM import LengthRR
from .L3Mobile_MM import CKSN_dict
from .L3Mobile_IE import ID, LAI, MSCm2, MSCm3
from .L3GSM_IE import *
from .L3GSM_rest import *


######
# TS 44.018 defines Radio Ressource Control protocol
# which is carried over the data-link
#
# section 8: basic structures
# section 9: messages stuctures (pffff...)
# section 10: general aspect and IE coding
##################
# 44018, section 10.1
# Header field
#
# 44018, section 9.1
# RRC procedures dictionnary
GSM_RR_dict = {
    0:'SYSTEM INFORMATION TYPE 13',
    1:'SYSTEM INFORMATION TYPE 14',
    2:'SYSTEM INFORMATION TYPE 2 bis',
    3:'SYSTEM INFORMATION TYPE 2 ter',
    4:'SYSTEM INFORMATION TYPE 9',
    5:'SYSTEM INFORMATION TYPE 5 bis',
    6:'SYSTEM INFORMATION TYPE 5 ter',
    7:'SYSTEM INFORMATION TYPE 2 quater',
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
    #22:'MBMS ANNOUNCEMENT',
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
    68:'SYSTEM INFORMATION TYPE 13 alt',
    69:'SYSTEM INFORMATION TYPE 2 n',
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
    Net -> ME (in DCCH)
    Dual
    # content #
    ChanDesc2: description of the 1st channel, after time, 3 bytes
    PowCmd: power command, 1 byte
    ... too much options ...
    '''
    constructorList = [ie for ie in Header(6, 46)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('ChanDesc', ReprName='Channel Description 2', Pt=ChanDesc(), \
                Len=3), # TODO: check 10.5.2.5a, with diff TDMAoff_dict
            Str('PowCmd', ReprName='Power Command', Pt='\0', Len=1),
            Type4_TLV('FreqList', ReprName='Frequency list, after time', \
                      T=0x05, V='\0\0'),
            Type3_TV('CellChan', ReprName='Cell Channel description', \
                     T=0x62, V=CellChan(), Len=16),
            Type4_TLV('MultAlloc', ReprName='Multi-slot allocation', \
                      T=0x10, V='\0'),
            Type3_TV('ChanSet1', ReprName='Channel Set 1', T=0x63, \
                     V='\0', Len=1),
            Type3_TV('ChanSet2', ReprName='Channel Set 2', T=0x11, \
                     V='\0', Len=1),
            Type3_TV('ChanSet3', ReprName='Channel Set 3', T=0x13, \
                     V='\0', Len=1),
            Type3_TV('ChanSet4', ReprName='Channel Set 4', T=0x14, \
                     V='\0', Len=1),
            Type3_TV('ChanSet5', ReprName='Channel Set 5', T=0x15, \
                     V='\0', Len=1),
            Type3_TV('ChanSet6', ReprName='Channel Set 6', T=0x16, \
                     V='\0', Len=1),
            Type3_TV('ChanSet7', ReprName='Channel Set 7', T=0x17, \
                     V='\0', Len=1),
            Type3_TV('ChanSet8', ReprName='Channel Set 8', T=0x18, \
                     V='\0', Len=1),
            Type3_TV('ChanDesc_2', ReprName='2nd channel description, ' \
                     'after time', T=0x64, V=ChanDesc(), Len=3),
            Type3_TV('ChanMod2', ReprName='Channel Mode 2', T=0x66, \
                     V='\0', Len=1),
            Type4_TLV('MobAlloc', ReprName='Mobile allocation', T=0x72, \
                      V=MobAlloc()),
            Type3_TV('Start', ReprName='Starting time', T=0x7C, \
                     V='\0\0', Len=2),
            Type4_TLV('FreqListB', ReprName='Frequency list, before time', \
                      T=0x19, V='\0\0'),
            Type3_TV('ChanDesc_3', ReprName='1st channel description, ' 
                     'before time', T=0x1C, V=ChanDesc(), Len=3),
            Type3_TV('ChanDesc2B', ReprName='2nd channel description, ' \
                     'before time', T=0x1D, V='\0\0\0', Len=3),
            Type3_TV('FreqChanSeq', ReprName='Frequency channel sequence', \
                     T=0x1E, V=9*'\0', Len=9),
            Type4_TLV('MobAlloc', ReprName='Mobile allocation, before time', \
                      T=0x21, V=MobAlloc()),
            Type2('CiphMod', ReprName='Cipher mode setting', T=0x09),
            Type4_TLV('VGCSind', ReprName='VGCS target mode indication', \
                      T=0x01, V='\0'),
            Type4_TLV('MRconf', ReprName='Multi-rate config', \
                      T=0x03, V='\0\0'),
            Type4_TLV('VGCSciph', ReprName='VGCS ciphering parameters', \
                      T=0x04, V='\0')])
        self._post_init(with_options, **kwargs)

# 44018, section 9.1.3
class ASSIGNMENT_COMPLETE(Layer3):
    '''
    ME -> Net (in DCCH)
    Dual
    # content #
    RR Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(6, 41)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])
        self._post_init(with_options, **kwargs)
 
# 44018, section 9.1.4
class ASSIGNMENT_FAILURE(Layer3):
    '''
    ME -> Net (in DCCH)
    Dual
    # content #
    RR Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(6, 47)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])
        self._post_init(with_options, **kwargs)

# 44018, section 9.1.7
class CHANNEL_RELEASE(Layer3):
    '''
    Net -> ME (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 13)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=0, Type='uint8', Dict=Cause_dict, Repr='hum')])
        # TODO: add optional IE during __init__()
        self._post_init(with_options, **kwargs)

# 44.018, section 9.1.12
class CLASSMARK_ENQUIRY(Layer3):
    '''
    Net -> ME (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 19)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('CmEnq', ReprName='Classmark Enquiry mask', T=0x10, \
                       V=CmEnq())])
        self._post_init(with_options, **kwargs)

# 44.018, section 9.1.
class CLASSMARK_CHANGE(Layer3):
    '''
    ME -> Net (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 22)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('MSCm2', V=MSCm2()), # in L3Mobile_IE.py
            Type4_TLV('MSCm3', T=0x20, V='\0\0\0\0\0\0\0')]) # in L3Mobile_IE.py, CSN1 field
        self._post_init(with_options, **kwargs)

# 44018, section 9.1.9
AlgId_dict = {
    0 : 'A5/1',
    1 : 'A5/2',
    2 : 'A5/3',
    3 : 'A5/4',
    4 : 'A5/5',
    5 : 'A5/6',
    6 : 'A5/7',
    7 : 'reserved',
    }
StCiph_dict = {
    0 : 'No ciphering',
    1 : 'Start ciphering',
    }
CiphRes_dict = {
    0 : 'IMEISV shall not be included',
    1 : 'IMEISV shall be included',
    }
class CIPHERING_MODE_COMMAND(Layer3):
    '''
    Net -> ME (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 53)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=3, Repr='hex'),
            Bit('CMRes', ReprName='Cipher Mode Response', Pt=0, BitLen=1, \
                Repr='hum', Dict=CiphRes_dict),
            Bit('AlgId', ReprName='Algorithm Identifier', Pt=0, BitLen=3, \
                Repr='hum', Dict=AlgId_dict),
            Bit('SC', ReprName='Start Ciphering', Pt=0, BitLen=1, \
                Repr='hum', Dict=StCiph_dict)])
        self._post_init(with_options, **kwargs)

# 44018, section 9.1.10
class CIPHERING_MODE_COMPLETE(Layer3):
    '''
    ME -> Net (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 50)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_TLV('ID', T=0x17, V=ID())])
        self._post_init(with_options, **kwargs)

# 44.018, section 9.1.8
# establishment cause can be 3 to 6 bits length
# depending if NECI bit is set by he network: 4 or 6 bits length
# or not set: 3 or 4 bits length
#ChanReqNoNECI_dict = {
#    5 : 'Emergency call',
#    6 : 'Call re-establishment; TCH/F or TCH/H was in use',
#    4 : 'Answer to paging',
#    3 : 'Answer to paging (dual rate)',
#    2 : 'Answer to paging (dual rate)',
#    1 : 'Answer to paging (SDCCH)', 
#    7 : 'Originating call, or procedures that can be completed with a SDCCH',
#    0 : 'Location updating',
#    }
#ChanReqNECI_dict = {
#    5 : 'Emergency call',
#    6 : 'Call re-establishment; TCH/F was in use',
#    26 : 'Call re-establishment; TCH/H was in use',
#    27 : 'Call re-establishment; TCH/H + TCH/H was in use',
#    4 : 'Answer to paging',
#    3 : 'Answer to paging (dual rate)',
#    2 : 'Answer to paging (dual rate)',
#    1 : 'Answer to paging (SDCCH)',
#    7 : 'Originating call and TCH/F is needed',
#    #4: 'Originating speech call from dual rate mobile station when TCH/H is sufficient and supported by the MS for speech calls',
#    #5: 'Originating data call from dual rate mobile station when TCH/H	is sufficient and supported by the MS for data calls',
#    0 : 'Location updating',
#    #1: '',
#    }
#class CHANNEL_REQUEST(Layer3):
#    '''
#    ME -> Net (in RACH)
#    '''
#    constructorList = [
#        Bit('estab', ReprName='Establishment cause', Pt=7, BitLen=3, \
#            Repr='hum'),
#        Bit('ra', ReprName='Random reference', BitLen=5, Repr='hum')
#        ]
#    # TODO: check how to deal with this mess of a bit-length...
#    # we need stateful (NECI from SI_3 or SI_4)
#    # anyway, we dont need to implement that crap into this lib !

# 44018, section 9.1.21
class MEASUREMENT_REPORT(Layer3):
    '''
    ME -> Net (in SACCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 21)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Str('MeasRes', ReprName='Measurement Results',
                     Pt=MeasRes(build_auto=True), Len=16)])
        self._post_init(with_options, **kwargs)
    
# 44.018, section 10.5.2.26
Page_dict = {
    0 : 'Normal paging',
    1 : 'Extended paging',
    2 : 'Paging reorganization',
    3 : 'Same as before',
    }
# 44.018, section 10.5.2.25b: dedicated chan assignment (for voice ?), 
# or TBF (for GPRS)
Dedic_dict = {
    0 : 'dedicated mode resource assignment',
    1 : 'uplink TBF assignment or second message of two in a two-message ' \
        'assignment of an uplink or downlink TBF',
    3 : 'downlink TBF assignment to the mobile station identified in ' \
        'the IA Rest Octets IE',
    5 : 'first message of two in a two-message assignment of an uplink TBF',
    7 : 'first message of two in a two-message assignment of a downlink TBF ' \
        'to the mobile station identified in the IA Rest Octets IE',
    }

# 44018, section 9.1.18
class IMMEDIATE_ASSIGNMENT(Layer3):
    '''
    Net -> ME (in CCCH)
    Dual
    # content #
    Page mode: 4 bits
    Dedicated mode: 4 bits,
    Channel description: 3 bytes, conditional to Dedicated mode
    Packet channel description: 3 bytes, conditional to Dedicated mode
    ... options ...
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 63)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('Dedicated', ReprName='Dedicated mode or TBF', Pt=0, \
                BitLen=4, Repr='hum', Dict=Dedic_dict),
            Bit('Page', ReprName='Page mode', Pt=0, BitLen=4, Repr='hum', \
                Dict=Page_dict),
            Str('ChanDesc', ReprName='Channel description', \
                Pt=ChanDesc(), Len=3), # 44018, 10.5.2.5, in L3GSM_IE.py
            Str('PChanDesc', ReprName='Packet channel description', \
                Pt=PChanDesc(build_auto=True), Len=3), # TODO: 44018, 10.5.2.25a
            Str('ReqRef', ReprName='Request reference', Pt=ReqRef(), \
                Len=3), # TODO: 44018, 10.5.2.30
            Int('TimeAdv', ReprName='Timing Advance', Pt=0, Type='uint8'),
            Type4_LV('MobAlloc', ReprName='Mobile allocation', \
                     V=MobAlloc()), # 44018, 10.5.2.21, in L3GSM_IE.py
            Type3_TV('Start', ReprName='Starting time', T=0x7C, \
                     V='\0\0', Len=2), # 44018, 10.5.2.38
            StrRR('IARestOctets', Repr='hex')]) # 44018, 10.5.2.16
        self._post_init(with_options, **kwargs)
        # L2 pseudo header automation
        self.len.Pt = (self.ChanDesc, self.PChanDesc, self.MobAlloc, self.Start)
        self.len.PtFunc = lambda x: sum(map(len, x))+7
        self.IARestOctets.Len = self.len
        self.IARestOctets.LenFunc = lambda l: 22-l()
        # Handling of packet / CS dedicated chan assignment
        self.ChanDesc.Trans = self.Dedicated
        self.ChanDesc.TransFunc = lambda dedi: False if dedi() == 0 else True
        self.PChanDesc.Trans = self.Dedicated
        self.PChanDesc.TransFunc = lambda dedi: False if dedi() in (1,3,5,7) \
                                                else True

# 44018, section 9.1.22
ChanNeed_dict = {
    0 : 'Any channel',
    1 : 'SDCCH',
    2 : 'TCH/F (Full rate)',
    3 : 'TCH/H or TCH/F (Dual rate)'
    }
class PAGING_REQUEST_1(Layer3):
    '''
    Net -> ME (in CCCH)
    Dual
    # content #
    Page mode: 4 bits
    ... options ...
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 33)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ChanNeedID2', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('ChanNeedID1', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('Page', ReprName='Page mode', Pt=0, BitLen=4, \
               Dict= Page_dict, Repr='hum'), # 10.5.2.26
            Type4_LV('ID', V=ID()), # never IMEI, in L3Mobile_IE.py
            Type4_TLV('ID_2', T=0x17, V=ID()), # never IMEI, in L3Mobile_IE.py
            StrRR('P1RestOctets', Repr='hex')])
        self._post_init(with_options, **kwargs)
        # L2 pseudo header automation
        self.len.Pt = (self.ID, self.ID_2)
        self.len.PtFunc = lambda x: sum(map(len, x))+3
        self.P1RestOctets.Len = self.len
        self.P1RestOctets.LenFunc = lambda l: 22-l()

# 44018, section 9.1.23
class PAGING_REQUEST_2(Layer3):
    '''
    Net -> ME (in CCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 34)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ChanNeedID2', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('ChanNeedID1', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('Page', ReprName='Page mode', Pt=0, BitLen=4, \
               Dict=Page_dict, Repr='hum'), # 10.5.2.26
            # only TMSI / P-TMSI, 10.5.2.42, for the 2 mandatory IDs
            Str('TMSI_1', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Str('TMSI_2', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Type4_TLV('ID', T=0x17, V=ID()), # can be MBMS, but never IMEI
            StrRR('P2RestOctets', Repr='hex')])
        self._post_init(with_options, **kwargs)
        # Now, automatic fields
        # L2 pseudo header
        self.len.Pt = self.ID
        self.len.PtFunc = lambda i:  len(i)+11
        self.P2RestOctets.Len = self.len
        self.P2RestOctets.LenFunc = lambda l: 22-l()

# 44018, section 9.1.24
class PAGING_REQUEST_3(Layer3):
    '''
    Net -> ME (in CCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 36)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ChanNeedID2', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('ChanNeedID1', ReprName='Channel needed', Pt=1, BitLen=2, \
               Dict=ChanNeed_dict, Repr='hum'), # 10.5.2.8
            Bit('Page', ReprName='Page mode', Pt=0, BitLen=4, \
               Dict=Page_dict, Repr='hum'), # 10.5.2.26
            # only TMSI / P-TMSI, 10.5.2.42, for the 4 mandatory IDs
            Str('TMSI_1', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Str('TMSI_2', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Str('TMSI_3', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Str('TMSI_4', Pt='\0\0\0\0', Len=4, Repr='hex'),
            StrRR('P3RestOctets', Len=3, Repr='hex')]) # 10.5.2.25
        self._post_init(with_options, **kwargs)
        self.len.Pt = 19

# 44018, section 9.1.25
class PAGING_RESPONSE(Layer3):
    '''
    ME -> Net (in DCCH)
    Dual
    '''
    constructorList = [ie for ie in Header(6, 39)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4),
            Bit('CKSN', ReprName='Ciphering Key Sequence Number', \
                Pt=0, BitLen=4, Dict=CKSN_dict), # 10.5.1.2, see L3Mobile_MM.py
            Type4_LV('MSCm2', V=MSCm2()), # in L3Mobile_IE.py
            Type4_LV('ID', V=ID())]) # in L3Mobile_IE.py
        self._post_init(with_options, **kwargs)

# 44018, section 9.1.31
class SI_1(Layer3):
    '''
    Net -> ME (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 25)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('CellChan', ReprName='Cell Channel Description', \
                Pt=CellChan(), Len=16), # 44018, 10.5.2.1b, in L3Mobile_RR.py
            Str('RACHCtrl', ReprName='RACH Control Parameters', Pt=RACHCtrl(),\
                Len=3), # 44018, 10.5.2.29, in L3Mobile_RR.py
            # rest octet is purely padding: 2b
            StrRR('SI1RestOctets', Repr='hex')])
            #StrRR('SI1RestOctets', Len=1, Repr='hex')]) # 10.5.2.32
        self._post_init(with_options, **kwargs)
        #self.len.Pt = 21
        # standard rest octet is 1 byte for SI1
        # L2 pseudo header automation
        self.len.Pt = (self.CellChan, self.RACHCtrl)
        self.len.PtFunc = lambda (c, r): len(c)+len(r)+2
        self.SI1RestOctets.Len = self.len
        self.SI1RestOctets.LenFunc = lambda l: 22-l()
        

# 44018, section 9.1.32
class SI_2(Layer3):
    '''
    Net -> ME (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 26)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('BCCHFreq', ReprName='Neighbour Cell Description', \
                Pt=BCCHFreq(), Len=16), # 44018, 10.5.2.22, in L3GSM_IE.py
            Bit('NCCPerm', ReprName='NCC Permitted', Pt=255, BitLen=8, \
                Repr='bin'), # 44018, 10.5.2.27
            Str('RACHCtrl', ReprName='RACH Control Parameters', Pt=RACHCtrl(),\
                Len=3)]) # 44018, 10.5.2.29, in L3GSM_IE.py
        self._post_init(with_options, **kwargs)
        self.len.Pt = 22

# 44018, section 9.1.33
# message to be ignored by P-GSM 900 band only mobiles
class SI_2bis(Layer3):
    '''
    Net -> ME (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 2)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('ExtBCCHFreq', ReprName='Neighbour Cell Description', \
                Pt=ExtBCCHFreq(), Len=16), # 44018, 10.5.2.22, in L3GSM_IE.py
            Str('RACHCtrl', ReprName='RACH Control Parameters', Pt=RACHCtrl(),\
                Len=3), # 44018, 10.5.2.29, in L3GSM_IE.py
            StrRR('SI2bisRestOctets', Len=1, Repr='hex')]) # 10.5.2.33
        self._post_init(with_options, **kwargs)
        #self.len.Pt = 21
        # standard rest octet is 1 byte for SI2bis
        # L2 pseudo header automation
        self.len.Pt = (self.ExtBCCHFreq, self.RACHCtrl)
        self.len.PtFunc = lambda (e, r): len(e)+len(r)+2
        self.SI2bisRestOctets.Len = self.len
        self.SI2bisRestOctets.LenFunc = lambda l: 22-l()

# 44018, section 9.1.34
# message to be ignored by P-GSM 900 band or DCS 1800 band only mobiles
class SI_2ter(Layer3):
    '''
    Net -> ME (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 3)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('ExtBCCHFreq', ReprName='Neighbour Cell Description', \
                Pt=ExtBCCHFreq(), Len=16), # 44018, 10.5.2.22, in L3GSM_IE.py
            #StrRR('SI2terRestOctets', Len=4, Repr='hex')]) # 10.5.2.33a
            StrRR('SI2terRestOctets', Repr='hex')])
        self._post_init(with_options, **kwargs)
        #self.len.Pt = 18
        # standard rest octet is 4 bytes for SI2ter
        # L2 pseudo header automation
        self.len.Pt = self.ExtBCCHFreq
        self.len.PtFunc = lambda e: len(e)+2
        self.SI2terRestOctets.Len = self.len
        self.SI2terRestOctets.LenFunc = lambda l: 22-l()

# 44018, section 9.1.34a
# info on UTRAN, E-UTRAN and 3G/4G CSG cells
class SI_2quater(Layer3):
    '''
    Net -> ME (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 7)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            StrRR('SI2quaterRestOctets', Len=20, Repr='hex')]) # 10.5.2.33b
        self._post_init(with_options, **kwargs)
        self.len.Pt = 1

# 44018, section 9.1.35
class SI_3(Layer3):
    '''
    Net -> ME  (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 27)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('CellID', Pt='\0\0', ReprName='Cell identity', Len=2, \
                Repr='hex'), # 44018, 10.5.1.1
            Str('LAI', ReprName='Location Area Identity', Pt=LAI(), \
                Len=5), # 44018, 10.5.1.3, in L3Mobile_IE.py
            Str('CChanDesc', ReprName='Control Channel Description', \
                Pt=CChanDesc(), Len=3), # 44018, 10.5.2.11, in L3GSM_IE.py
            Str('CellOpt', ReprName='Cell Options (BCCH)', Pt=CellOpt(), \
                Len=1), # 44018, 10.5.2.3, in L3GSM_IE.py
            Str('CellSel', ReprName='Cell Selection Parameters', \
                Pt=CellSel(), Len=2), # 44018, 10.5.2.4
            Str('RACHCtrl', ReprName='RACH Control Parameters', Pt=RACHCtrl(),\
                Len=3), # 44018, 10.5.2.29
            StrRR('SI3RestOctets', Len=4, Repr='hex')]) # 44018, 10.5.2.33a
        self._post_init(with_options, **kwargs)
        self.len.Pt = 18
        if hasattr(self.CellSel, 'ACS'):
            self.CellSel.ACS.Dict = ACS_SI3_dict
            

# 44018, section 9.1.36
class SI_4(Layer3):
    '''
    Net -> ME  (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 28)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('LAI', ReprName='Location Area Identity', Pt=LAI(), Len=5, \
                Repr='hex'), # 44018, 10.5.1.3, in L3Mobile_IE.py
            Str('CellSel', ReprName='Cell Selection Parameters', \
                Pt=CellSel(), Len=2), # 44018, 10.5.2.4
            Str('RACHCtrl', ReprName='RACH Control Parameters', Pt=RACHCtrl(),\
                Len=3), # 44018, 10.5.2.29, in L3GSM_IE.py
            Type3_TV('ChanDesc', ReprName='CBCH Channel Description', T=0x7C, \
                V=ChanDesc(), Len=3), # 44018, 10.5.2.5, in L3GSM_IE.py
            Type4_TLV('MobAlloc', ReprName='CBCH Mobile Allocation', T=0x72, \
                V=MobAlloc()), # 44018, 10.5.2.21, in L3GSM_IE.py
            StrRR('SI4RestOctets', Repr='hex')]) # 44018, 10.5.2.35
        self._post_init(with_options, **kwargs)
        if hasattr(self.CellSel, 'ACS'): self.CellSel.ACS.Dict = ACS_SI4_dict
        # L2 pseudo header automation
        self.len.Pt = self.MobAlloc
        self.len.PtFunc = lambda m: len(m)+16
        self.SI4RestOctets.Len = self.len
        self.SI4RestOctets.LenFunc = lambda l: 22-l()

class SI_5(Layer3):
    '''
    Net -> ME (in SACCH)
    Dual
    '''
    # no LengthRR as it will come from LAPDm (see L2GSM)
    constructorList = [ie for ie in Header(6, 29)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('BCCHFreq', ReprName='Neighbour Cell Description', \
                Pt=BCCHFreq(), Len=16)]) # 44018, 10.5.2.22a, in L3GSM_IE.py
        self._post_init(with_options, **kwargs)

class SI_5bis(Layer3):
    '''
    Net -> ME (in SACCH)
    Dual
    '''
    # no LengthRR as it will come from LAPDm (see L2GSM)
    constructorList = [ie for ie in Header(6, 5)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('BCCHFreq', ReprName='Neighbour Cell Description', \
                Pt=BCCHFreq(), Len=16)]) # 44018, 10.5.2.22, in L3GSM_IE.py
        self._post_init(with_options, **kwargs)

class SI_5ter(Layer3):
    '''
    Net -> ME (in SACCH)
    Dual
    '''
    # no LengthRR as it will come from LAPDm (see L2GSM)
    constructorList = [ie for ie in Header(6, 6)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([\
            Str('ExtBCCHFreq', ReprName='Extended Neighbour Cell Description', \
                Pt=ExtBCCHFreq(), Len=16)]) # 44018, 10.5.2.22a, in L3GSM_IE.py
        self._post_init(with_options, **kwargs)

class SI_6(Layer3): 
    '''
    Net -> ME (in SACCH)
    Dual
    '''
    # no LengthRR as it will come from LAPDm (see L2GSM)
    constructorList = [ie for ie in Header(6, 30)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('CellID', Pt='\0\0', ReprName='Cell identity', Len=2, \
                Repr='hex'), # 44018, 10.5.1.1
            Str('LAI', ReprName='Location Area Identity', Pt=LAI(), \
                Len=5), # 44018, 10.5.1.3, in L3Mobile_IE.py
            Str('CellOpt', ReprName='Cell Options (BCCH)', Pt=CellOpt(), \
                Len=1), # 44018, 10.5.2.3, in L3GSM_IE.py
            Bit('NCCPerm', ReprName='NCC Permitted', Pt=255, BitLen=8, \
                Repr='bin'), # 44018, 10.5.2.27
            StrRR('SI6RestOctets', Len=7, Repr='hex')]) # 44018, 10.5.2.35a
        #self.len.Pt = 11 # WTF ! RestOctets are 7 and length should be 11 ?
        # anyway, length is in LAPDm, not directly into L3...
        self._post_init(with_options, **kwargs)

class SI_13(Layer3):
    '''
    Net -> ME  (in BCCH)
    Dual
    '''
    constructorList = [ie for ie in LengthRR()] + [ie for ie in Header(6, 0)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            StrRR('SI13RestOctets', Len=20, Repr='hex')]) # 44018, 10.5.2.33a
        self._post_init(with_options, **kwargs)
        self.len.Pt = 0
#
