# -*- coding: UTF-8 -*-
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
# * File Name : formats/L3GSM_rest.py
# * Created : 2012-04-10 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# exporting
__all__ = ['RestOctets', 'P1RestOctets', 'IARestOctets',
           'SI1RestOctets', 'SI2terRestOctets', 'SI2quaterRestOctets',
           'SI3RestOctets', 'SI4RestOctets', 'SI13RestOctets' ]
           #'u']

# for convinience
from binascii import unhexlify as u
#
from libmich.core.element import Bit, Layer, show, log, DBG, WNG, ERR
from libmich.core.shtr import decomposer, shtr
from libmich.core.CSN1 import CSN1, LHFlag, BREAK, BREAK_LOOP
from libmich.formats.L3Mobile_IE import AccessTechnoType_dict

# Decoder joker
class _Paf_(Bit):
    def map(self, s):
        raise(Exception)

# In order to map correctly the rest bits at the end of the RestOctets
class RestOctets(CSN1):
    # name for padding at the end
    rest_name = 'Rest_padding'
    # GSM padding: 0x2b (for CSN1)
    L = [0,0,1,0,1,0,1,1]
    # default has empty CSN1
    csn1List = []
    #
    def map(self, string='', byte_offset=0):
        # map according to the CSN1 struct
        CSN1.map(self, string, byte_offset)
        # check how many bits already mapped, and how many remaining
        done = self.bit_len()
        rem = len(string)*8 - done
        s = shtr(string) << done
        # append the padding element
        self.append(Bit('%s' % self.rest_name, BitLen=rem, Repr='hex'))
        self[-1].map(s)

#
# TS 44.018, section 9.1.21a: Group Call information (see TS 44.608 too)
class MobAlloc(CSN1):
    csn1List = [
        Bit('len', Pt=1, BitLen=8),
        Bit('MA_RFchan', ReprName='Mobile Allocation RF channel mask', \
            Pt=0, Repr='bin')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        #self.csn1List[0].Pt = self.csn1List[1]
        #self.csn1List[0].PtFunc = lambda m: len(m)
        self.csn1List[1].BitLen = self.csn1List[0]
        self.csn1List[1].BitLenFunc = lambda l: l()*8

class GroupChannelDescription(CSN1):
#    max_bitlen = 36
    csn1List = [
        Bit('ChannelDescription', BitLen=24),
        {'0':BREAK, 
         '1':{'0':MobAlloc(), '1':Bit('FrequencyShortList', BitLen=64)}}
        ]
GroupService_dict = {
    0 : 'VBS (broadcast call reference)',
    1 : 'VGCS (group call reference)'}
class GroupCallInformation(CSN1):
    # from 44.018, CSN1 @ 9.1.21a, group call reference looks like 36 bits
    # however, from the description above and info in 44.068 @ 9.4.1,
    # a reference is 27 bits + 1 bit service flag
    # the group call reference is a 'token' delivered by the MNO 
    # as an identifier for the group / broadcast call
    csn1List = [
        Bit('GroupCallReference', BitLen=27, Repr='hum'),
        Bit('ServiceFlag', BitLen=1, Repr='hum', Dict=GroupService_dict),
        {'0':BREAK, '1':GroupChannelDescription()}
        ]

# TS 44.060, section 12.10a
class RFLNumberList(CSN1):
    csn1List = [
        Bit('RFL_NUMBER', BitLen=4),
        Bit('more', BitLen=1),
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
    def map(self, string='', byte_offset=0):
        # work with shtr
        s, l = shtr(string), len(string)*8
        # initialize values
        CSN1.map(self, s, byte_offset)
        s, l = s<<5, l-5
        # while we got more==1, stack new structure
        while self[-1]() and l>0:
            num = Bit('RFL_NUMBER', BitLen=4)
            num.map(s)
            self.append(num)
            s = s<<4
            m = Bit('more', BitLen=1)
            m.map(s)
            self.append(m)
            s, l = s<<1, l-5

class ARFCNIndexList(CSN1):
    csn1List = [
        Bit('ARFCN_INDEX', BitLen=6),
        Bit('more', BitLen=1),
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
    def map(self, string='', byte_offset=0):
        # work with shtr
        s, l = shtr(string), len(string)*8
        # initialize values
        CSN1.map(self, s, byte_offset)
        s, l = s<<7, l-7
        # while we got more==1, stack new structure
        while self[-1]() and l>0:
            ind = Bit('ARFCN_INDEX', BitLen=6)
            ind.map(s)
            self.append(ind)
            s = s<<6
            m = Bit('more', BitLen=1)
            m.map(s)
            self.append(m)
            s, l = s<<1, l-7
class GPRSMobileAllocation(CSN1):
    csn1List = [
        Bit('HSN', BitLen=6, Repr='hum'),
        {'0':BREAK, '1':RFLNumberList()},
        {'0':(Bit('MA_LENGTH', Pt=7, BitLen=6, Repr='hum'), Bit('MA_BITMAP')), \
         '1':{'0':BREAK, '1':ARFCNIndexList()}}
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        #self.csn1List[2]['0'][0].Pt = self.csn1List[2]['0'][1]
        #self.csn1List[2]['0'][0].PtFunc = lambda b: b.bit_len()-1
        self.csn1List[2]['0'][1].BitLen = self.csn1List[2]['0'][0]
        self.csn1List[2]['0'][1].BitLenFunc = lambda l: l()+1

# TS 44.060, section 12.8
class IndirectEncoding(CSN1):
    csn1List = [
        Bit('MAIO', BitLen=6, Repr='hum'), 
        Bit('MA_NUMBER', BitLen=4),
        {'0':BREAK, '1':(Bit('CHANGE_MARK_1', BitLen=2), \
                        {'0':BREAK, '1':Bit('CHANGE_MARK_2', BitLen=2)})}
        ]
class DirectEncoding1(CSN1):
    csn1List = [
        Bit('MAIO', BitLen=6, Repr='hum'),
        GPRSMobileAllocation()
        ]
class DirectEncoding2(CSN1):
    csn1List = [
        Bit('MAIO', BitLen=6, Repr='hum'), 
        Bit('HSN', BitLen=6),
        Bit('LengthOfMAFrequencyListContents', Pt=8, BitLen=4),
        Bit('MAFrequencyListContents')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # MAFrequencyListContents length automation
        #self.csn1List[2].Pt = self.csn1List[3]
        #self.csn1List[2].PtFunc = lambda ma: ma.bit_len()
        self.csn1List[3].BitLen = self.csn1List[2]
        self.csn1List[3].BitLenFunc = lambda l: l()
class FrequencyParameters(CSN1):
    csn1List = [
        Bit('TSC', BitLen=3),
        {'00':Bit('ARFCN', BitLen=10),
         '01':IndirectEncoding(),
         '10':DirectEncoding1(),
         '11':DirectEncoding2()}
        ]

# TS 44.060, section 12.37
class MBMSptmChannelDescription(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':FrequencyParameters()},
        Bit('DL_TIMESLOT_ALLOCATION', BitLen=8)
        ]

# TS 44.060, section 12.5.2
#class EGPRSWindowSize(CSN1):
#    csn1List = [
#        ]

# TS 44.060, section 12.40
# EGPRS window size: section 12.5.2
class MBMSSessionParametersList(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':(Bit('LengthOfMBMSBearerIdentity', BitLen=3), \
              Bit('MBMSBearerIdentity'), \
              Bit('EstimatedSessionDuration', BitLen=8), \
              {'0':BREAK, '1':Bit('MBMSRadioBearerStartingTime', BitLen=16)},
              {'0':BREAK, '1':Bit('EGPRSWindowSize', BitLen=5)}, \
              {'0':BREAK, '1':Bit('NPMTransferTime', BitLen=5)})}
        ]

# TS 44.060, section 12.41
class MPRACHControlParameters(CSN1):
    csn1List = [
        {'0':BREAK, '1':Bit('ACC_CONTR_CLASS', BitLen=16)},
        {'0':BREAK, '1':Bit('MAX_RETRANS', BitLen=2)},
        Bit('S', BitLen=4),
        {'0':BREAK, '1':Bit('TX_INT', BitLen=4)},
        {'0':BREAK, '1':Bit('PERSISTENCE_LEVEL', BitLen=4)}
        ]

# TS 44.060, section 12.38
class MPRACHDescription(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':FrequencyParameters()},
        Bit('MPRACH_TIMESLOT_NUMBER', BitLen=3),
        Bit('USF', BitLen=3, Repr='hum'),
        {'0':BREAK,
         '1':MPRACHControlParameters()}
        ]

# TS 44.060, section 12.36
class MBMSChannelParameters(CSN1):
    csn1List = [
        {'0':{'0':BREAK,
              '1':(MBMSptmChannelDescription(), MBMSSessionParametersList())},
         '1':{'0':BREAK,
              '1':MPRACHDescription()}}
        ]

# TS 44.060, section 12.33
class TMGI(CSN1):
    csn1List = [
        {'0':Bit('MBMSServiceID', BitLen=24), 
         '1':(Bit('MBMSServiceID', BitLen=24), 
              Bit('MCC', BitLen=12),
              Bit('MNC', BitLen=12))}
        ]

# TS 44.060, section 12.39
class MBMSSessionsList(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':(TMGI(), {'0':BREAK, 
                       '1':Bit('MBMSSessionIdentity', BitLen=8)})}
        ]

class MBMSInformation(CSN1):
    csn1List = [
        MBMSSessionsList(),
        {'0':BREAK,
         '1':({'0':BREAK, '1':BREAK}, MBMSSessionsList())},
        {'1':(MBMSChannelParameters(), MBMSSessionsList())}
        ]

class ETWSPrimaryNotificationStatus(CSN1):
    csn1List = [
        {'0':Bit('TotalNoOfSegmentsForETWSPrimaryNotification', BitLen=4),
         '1':Bit('SegmentNumber', BitLen=4)},
        Bit('PNI', BitLen=1),
        Bit('LengthOfSegment', Pt=8, BitLen=7),
        Bit('ETWSPrimaryNotificationData')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # ETWSPrimaryNotificationData length automation
        #self.csn1List[2].Pt = self.csn1List[3]
        #self.csn1List[2].PtFunc = lambda dat: dat.bit_len()
        self.csn1List[3].BitLen = self.csn1List[2]
        self.csn1List[3].BitLenFunc = lambda l: l()

PacketPageInd_dict = {
    'L' : 'paging procedure for RR connection establishment',
    'H' : 'packet paging procedure'}
Priority_dict = {
	0 : 'no priority applied',
	1 : 'call priority level 4',
	2 : 'call priority level 3',
	3 : 'call priority level 2',
	4 : 'call priority level 1',
	5 : 'call priority level 0',
	6 : 'call priority level B',
	7 : 'call priority level A',
    }
class P1RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 'H':(Bit('NLN', BitLen=2), Bit('NLNstatus', BitLen=1))},
        {'L':BREAK, 'H':Bit('Priority1', BitLen=3, Dict=Priority_dict, Repr='hum')},
        {'L':BREAK, 'H':Bit('Priority2', BitLen=3, Dict=Priority_dict, Repr='hum')},
        {'L':BREAK, 'H':GroupCallInformation()},
        LHFlag('PacketPageInd1', Dict=PacketPageInd_dict),
        LHFlag('PacketPageInd2', Dict=PacketPageInd_dict),
        # Rel.6 additions
        {'L':BREAK,
         'H':({'0':BREAK,
               '1':{'00':Bit('CELL_GLOBAL_COUNT', BitLen=2),
                    '01':(Bit('CELL_GLOBAL_COUNT', BitLen=2), Bit('VSTK_RAND', BitLen=36)),
                    '10':(Bit('Reduced_GCR', BitLen=2), Bit('VSTK_RAND', BitLen=36)),
                    '11':(Bit('CELL_GLOBAL_COUNT', BitLen=2), Bit('VSTK_RAND', BitLen=36))}},
              # MBMS parameters
              {'0':BREAK,
               '1':({'0':BREAK, '1':MBMSChannelParameters('MBMSNotification1')},
                    {'0':BREAK, '1':{'0':BREAK, '1':MBMSChannelParameters('MBMSNotification2')}},
                    {'0':BREAK, '1':MBMSInformation()})})},
        # Rel.7 additions
        {'L':BREAK, 'H':{'0':BREAK, '1':Bit('AMRConfig', BitLen=4)}},
        # Rel.8 additions
        {'L':BREAK, 'H':(Bit('PriorityUplinkAccess', BitLen=1),
                        {'0':BREAK, '1':ETWSPrimaryNotificationStatus()})},
        ]

###
# 44.018, section 10.5.2.16 Immediate Assignment rest octets, 
#/mode complete_nightmare
Polling_dict = {
    0 : 'No action required from MS',
    1 : 'MS shall send a PACKET CONTROL ACKNOWLEDGEMENT message in the ' \
        'uplink block specified by TBF Starting Time, on the assigned PDCH'}
USFGran_dict = {
    0 : 'MS shall transmit one RLC/MAC block',
    1 : 'MS shall transmit four consecutive RLC/MAC blocks'}
RLCMode_dict = {
    0 : 'RLC acknowledged mode',
    1 : 'RLC unacknowledged mode'}
TAValid_dict = {
    0 : 'the timing advance value is not valid',
    1 : 'the timing advance value is valid'}
CompIRATINFO_dict = {
    'L': 'Compressed version of the INTER RAT HANDOVER INFO message ' \
         'shall not be used',
    'H': 'Compressed version of the INTER RAT HANDOVER INFO message ' \
         'shall be used'}
EGPRSLevel_dict = {
    0 : 'EGPRS',
    1 : 'EGPRS2-A',
    2 : 'EGPRS2-B',
    3 : 'EGPRS2-B',
    4 : 'reserved'
    }
    
class AccessTechnologiesRequest(CSN1):
    # Need a recursive
    csn1List = [
        Bit('AccessTechnologyType', BitLen=4, \
            Dict=AccessTechnoType_dict, Repr='hum'),
        Bit('more', BitLen=1)
        ]
    def map(self, string='', byte_offset=0):
        # work with shtr
        s, l = shtr(string), len(string)*8
        # initialize values
        CSN1.map(self, s, byte_offset)
        s, l = s<<5, l-5
        # while we got more==1, stack new structure to decode
        while self[-1]() and l>0:
            att = Bit('AccessTechnologyType', BitLen=4, \
                      Dict=AccessTechnoType_dict, Repr='hum')
            att.map(s)
            self.append(att)
            s = s << 4
            m = Bit('more', BitLen=1)
            m.map(s)
            self.append(m)
            s, l = s<<1, l-5

# TS 44.060, section 12.10d
class EGPRSPacketUplinkAssignment(CSN1):
    csn1List = [
        Bit('ExtendedRA', BitLen=5),
        {'0':BREAK, '1':AccessTechnologiesRequest()},
        {'1':(Bit('TFI_ASSIGNMENT', BitLen=5),
              Bit('POLLING', BitLen=1, Dict=Polling_dict, Repr='hum'),
              Bit('_unused', Pt=0, BitLen=1),
              Bit('USF', BitLen=3, Repr='hum'),
              Bit('USF_GRANULARITY', BitLen=1, Dict=USFGran_dict, Repr='hum'),
              {'0':BREAK, '1':(Bit('P0', BitLen=4), Bit('PR_MODE', BitLen=1))},
              Bit('EGPRSModulationAndCoding', BitLen=4),
              Bit('TLLI_BLOCK_CHANNEL_CODING', BitLen=1),
              {'0':BREAK, '1':Bit('BEP_PERIOD2', BitLen=4)},
              Bit('RESEGMENT', BitLen=1),
              Bit('EGPRSWindowSize', BitLen=5),
              {'0':BREAK, 
               '1':(Bit('ALPHA', BitLen=4), 
                    Bit('GAMMA', BitLen=5, Repr='hum'))},
              {'0':BREAK, '1':Bit('TIMING_ADVANCE_INDEX', BitLen=4, Repr='hum')},
              {'0':BREAK, '1':Bit('TBF_STARTING_TIME', BitLen=16)},
              # starting Rel.7 stuff
              {'L':BREAK,
               'H':{'0':{'0':BREAK, # FANR is not activated
                         '1':{'0':BREAK, # SSN-based encoding
                              '1':(Bit('ReportedTimeslots', BitLen=8),
                                   Bit('TSH', BitLen=2))}},
                    '1':(Bit('RTTIUSFMode', Pt=0, BitLen=1),
                         Bit('PDCHPairIndication', BitLen=3),
                         Bit('AdditionalUSF', BitLen=3, Repr='hum'),
                         {'0':BREAK,
                          '1':(Bit('USF2', BitLen=2),
                               Bit('AdditionalUSF2', BitLen=2))},
                         {'0':BREAK,
                          '1':(Bit('ReportedTimeslots', BitLen=8),
                               Bit('TSH', BitLen=2))})}}),
         '0':({'0':BREAK,
               '1':(Bit('ALPHA', BitLen=4), Bit('GAMMA', BitLen=5, Repr='hum'),
                    Bit('TBFStartingTime', BitLen=16),
                    Bit('NumberOfRadioBlocksAllocated', BitLen=2))},
              {'0':BREAK,
               '1':(Bit('P0', BitLen=4), Bit('_unused', Pt=0, BitLen=1),
                    Bit('PR_MODE', BitLen=1))},
              # starting Rel.6 stuff
              {'L':BREAK,
               'H':{'0':BREAK, '1':Bit('PFI', BitLen=7)}})}
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # TODO
        #self.csn1List[AdditionalUSF].Trans = self.csn1List[RTTIUSFMode]
        self.csn1List[2]['1'][14]['H']['1'][2].Trans = \
            self.csn1List[2]['1'][14]['H']['1'][0]
        #self.csn1List[AdditionalUSF].TransFunc = lambda r: 1-r()
        self.csn1List[2]['1'][14]['H']['1'][2].TransFunc = \
            lambda r: True if r()==1 else True
        #self.csn1List[AdditionalUSF2].Trans = self.csn1List[RTTIUSFMode]
        self.csn1List[2]['1'][14]['H']['1'][3]['1'][1].Trans = \
            self.csn1List[2]['1'][14]['H']['1'][0]
        #self.csn1List[AdditionalUSF2].TransFunc = lambda r: 1-r()
        self.csn1List[2]['1'][14]['H']['1'][3]['1'][1].TransFunc = \
            lambda r: True if r()==1 else True

# 44.060, section 12.12
class PacketTimingAdvance(CSN1):
    csn1List = [
        Bit('TIMING_ADVANCE_VALUE', BitLen=6),
        Bit('TIMING_ADVANCE_INDEX', BitLen=4, Repr='hum'),
        Bit('TIMING_ADVANCE_TIMESLOT_NUMBER', BitLen=3, Repr='hum')]

class MultipleBlocksPacketDownlinkAssignment(CSN1):
    csn1List = [
        Bit('TBF_STARTING_TIME', BitLen=16),
        Bit('NumberOfAllocatedBlocks', BitLen=4, Repr='hum'),
        {'0':{'1':{'0':(TMGI(), Bit('MBMSSessionIdentity', BitLen=8)),
                   '1':(Bit('TLLI/G-RNTI', BitLen=2),
                        {'0':BREAK,
                         '1':(Bit('LengthOfMS_ID', BitLen=2),
                              Bit('MS_ID'),
                              PacketTimingAdvance(),
                              {'0':BREAK, 
                               '1':(Bit('ALPHA', BitLen=4),
                                    {'0':BREAK,
                                     '1':Bit('GAMMA', BitLen=5, Repr='hum')})})})},
              '0':BREAK},
         '1':BREAK}
        ]

class PacketUplinkAssignment(CSN1):
    csn1List = [
        {'1':(Bit('TFI_ASSIGNMENT', BitLen=5),
              Bit('POLLING', BitLen=1, Dict=Polling_dict, Repr='hum'),
              Bit('_unused', Pt=0, BitLen=1),
              Bit('USF', BitLen=3, Repr='hum'),
              Bit('USF_GRANULARITY', BitLen=1, Dict=USFGran_dict, Repr='hum'),
              {'0':BREAK, '1':(Bit('P0', BitLen=4), Bit('PR_MODE', BitLen=1))},
              Bit('TLLI_BLOCK_CHANNEL_CODING', BitLen=1),
              {'0':BREAK, '1':Bit('ALPHA', BitLen=4)},
              Bit('GAMMA', BitLen=5, Repr='hum'),
              {'0':BREAK, '1':Bit('TIMING_ADVANCE_INDEX', BitLen=4, Repr='hum')},
              {'0':BREAK, '1':Bit('TBF_STARTING_TIME', BitLen=16)}),
         '0':({'0':BREAK, '1':Bit('ALPHA', BitLen=4)},
              Bit('GAMMA', BitLen=5, Repr='hum'),
              Bit('_unused', Pt=0, BitLen=1),
              Bit('TBF_STARTING_TIME', BitLen=16),
              {'L':BREAK, 'H':(Bit('P0', BitLen=4), 
                              Bit('_unused', Pt=1, BitLen=1), 
                              Bit('PR_MODE', BitLen=1))})},
        {'L':BREAK, # from R99
         'H':{'0':BREAK, '1':Bit('ExtendedRA', BitLen=5)}},
        {'L':BREAK, # from Rel.6
         'H':{'0':BREAK, '1':Bit('PFI', BitLen=7)}},
        ]

class PacketDownlinkAssignment(CSN1):
    csn1List = [
        Bit('TLLI', BitLen=32, Repr='hex'),
        {'0':BREAK, 
         '1':(Bit('TFI_ASSIGNMENT', BitLen=5, Repr='hum'),
              Bit('RLC_MODE', BitLen=1, Dict=RLCMode_dict, Repr='hum'),
              {'0':BREAK, '1':Bit('ALPHA', BitLen=4)},
              Bit('GAMMA', BitLen=5, Repr='hum'),
              Bit('POLLING', BitLen=1, Dict=Polling_dict, Repr='hum'),
              Bit('TA_VALID', BitLen=1, Dict=TAValid_dict, Repr='hum'))},
        {'0':BREAK, '1':Bit('TIMING_ADVANCE_INDEX', BitLen=4, Repr='hum')},
        {'0':BREAK, '1':Bit('TBF_STARTING_TIME', BitLen=4)},
        {'0':BREAK, 
         '1':(Bit('P0', BitLen=4),
              Bit('_unused', Pt=1, BitLen=1),
              Bit('PR_MODE', BitLen=1),
              {'L':BREAK, # from R99
               'H':(Bit('EGPRSWindowSize', BitLen=5),
                    Bit('LINK_QUALITY_MEASUREMENT_MODE', BitLen=2),
                    {'0':BREAK, '1':Bit('BEP_PERIOD2', BitLen=4)})},
              {'L':BREAK, # from Rel.6
               'H':{'0':BREAK, '1':Bit('PFI', BitLen=7)}},
              {'L':BREAK, # from Rel.7
               'H':({'0':BREAK, '1':Bit('NPMTransferTime', BitLen=5)},
                    {'0':{'0':BREAK, '1':Bit('EVENT_BASED_FANR', BitLen=1)},
                     '1':(Bit('EVENT_BASED_FANR', BitLen=1),
                          Bit('PDCH_PAIR_INDICATION', BitLen=3))},
                    Bit('DownlinkEGPRSLevel', BitLen=2, Dict=EGPRSLevel_dict))})}
    ]

class SecondPartPacketAssignment(CSN1):
    csn1List = [
        {'L':BREAK,
         'H':{'0':BREAK,
              '1':Bit('ExtendedRA', BitLen=5)}}
        ]

# 44.018, section ?.?
class IARestOctets(RestOctets):
    csn1List = [
        {'LL':LHFlag('Compressed_Inter_RAT_HO_INFO_IND', Dict=CompIRATINFO_dict),
         #'LL':BREAK, # which is actually a flag for Compressed_Inter_RAT_HO_INFO_IND
         'LH':{'0':{'0':EGPRSPacketUplinkAssignment(),
                    '1':MultipleBlocksPacketDownlinkAssignment()},
               '1':BREAK},
         'HL':(Bit('LengthOfFrequencyParameters', Pt=7, BitLen=6),
               Bit('_unused', Pt=0, BitLen=2),
               Bit('MAIO', BitLen=6, Repr='hum'),
               Bit('MA_RFchan', ReprName='Mobile Allocation RF channel mask'),
               LHFlag('Compressed_Inter_RAT_HO_INFO_IND',Dict=CompIRATINFO_dict)),
         'HH':{'0':{'0':PacketUplinkAssignment(),
                    '1':PacketDownlinkAssignment()},
               '1':SecondPartPacketAssignment()}}
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # MA_RFchan length automation
        #self.csn1List[0]['HL'][0].Pt = self.csn1List[0]['HL'][3]
        #self.csn1List[0]['HL'][0].PtFunc = lambda m: m.bit_len()-1
        self.csn1List[0]['HL'][3].BitLen = self.csn1List[0]['HL'][0]
        self.csn1List[0]['HL'][3].BitLenFunc = lambda l: l()+1

###
# 44.018, section 10.5.2.32: System Info type 1 rest octet
#
NCHpos_dict = {
    0 : '1 block(s), 1st block is 0',
    1 : '1 block(s), 1st block is 1',
    2 : '1 block(s), 1st block is 2',
    3 : '1 block(s), 1st block is 3',
    4 : '1 block(s), 1st block is 4',
    5 : '1 block(s), 1st block is 5',
    6 : '1 block(s), 1st block is 6',
    7 : '2 block(s), 1st block is 0',
    8 : '2 block(s), 1st block is 1',
    9 : '2 block(s), 1st block is 2',
    10 : '2 block(s), 1st block is 3',
    11 : '2 block(s), 1st block is 4',
    12 : '2 block(s), 1st block is 5',
    13 : '3 block(s), 1st block is 0',
    14 : '3 block(s), 1st block is 1',
    15 : '3 block(s), 1st block is 2',
    16 : '3 block(s), 1st block is 3',
    17 : '3 block(s), 1st block is 4',
    18 : '4 block(s), 1st block is 0',
    19 : '4 block(s), 1st block is 1',
    20 : '4 block(s), 1st block is 2',
    21 : '4 block(s), 1st block is 3',
    22 : '5 block(s), 1st block is 0',
    23 : '5 block(s), 1st block is 1',
    24 : '5 block(s), 1st block is 2',
    25 : '6 block(s), 1st block is 0',
    26 : '6 block(s), 1st block is 1',
    27 : '7 block(s), 1st block is 0',
    }
class SI1RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 'H':Bit('NCHPosition', BitLen=5, Repr='hum', Dict=NCHpos_dict)},
        LHFlag('BAND_INDICATOR'),
        ]

###
# SI2 has no rest octet

###
# 44.018, section 10.5.2.33a: System Info type 2 ter rest octets
#
class SI2terRestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 
         'H':(Bit('SI2ter_MP_CHANGE_MARK', BitLen=1, Repr='hum'),
              Bit('SI2ter_3G_CHANGE_MARK', BitLen=1, Repr='hum'),
              Bit('SI2ter_INDEX', BitLen=3, Repr='hum'),
              Bit('SI2ter_COUNT', BitLen=3, Repr='hum'),
              {'0':BREAK,
               '1':{'00':BREAK, '11':BREAK, '10':BREAK,
                    '01':(Bit('FDD-ARFCN', BitLen=14, Repr='hum'),
                          {'0':BREAK,
                           '1':Bit('Bandwidth_FDD', BitLen=3)})}},
              {'0':BREAK,
               '1':{'00':BREAK, '11':BREAK, '10':BREAK,
                    '01':(Bit('TDD-ARFCN', BitLen=14, Repr='hum'),
                          {'0':BREAK,
                           '1':Bit('Bandwidth_TDD', BitLen=3)})}},
              {'0':BREAK,
               '1':(Bit('Qsearch_I', BitLen=4),
                    {'0':BREAK, 
                     '1':(Bit('FDD_Qoffset', BitLen=4),
                          Bit('FDD_Qmin', BitLen=3))},
                    {'0':BREAK, '1':Bit('TDD_Qoffset', BitLen=4)})},
              {'L':BREAK,
               'H':{'0':BREAK,
                    '1':(Bit('FDD_Qmin_Qoffset', BitLen=3),
                         Bit('FDD_RSCPmin', BitLen=4))}})}
        ]


###
# 44.018, section 10.5.2.33b: System Info type 2 quater rest octets
# aaaarrrrrgggghhhh
#
# 3G neighbour cell description: see 44.018, 3.4.1.2.1.1
FDD3GCellInfoLength_dict = {
    0:0,
    1:10,
    2:19,
    3:28,
    4:36,
    5:44,
    6:52,
    7:60,
    8:67,
    9:74,
    10:81,
    11:88,
    12:95,
    13:102,
    14:109,
    15:116,
    16:122,
    }
TDD3GCellInfoLength_dict = {
    0:0,
    1:9,
    2:17,
    3:25,
    4:32,
    5:39,
    6:46,
    7:53,
    8:59,
    9:65,
    10:71,
    11:77,
    12:83,
    13:89,
    14:95,
    15:101,
    16:106,
    17:111,
    18:116,
    19:121,
    20:126
    }
class UTRANFDDNeighbourCells(CSN1):
    csn1List = [
        {'0':Bit('FDD_ARFCN', BitLen=14, Repr='hum'), '1':BREAK},
        Bit('FDD_Indic0', BitLen=1, Repr='hum'),
        Bit('NR_OF_FDD_CELLS', BitLen=5, Repr='hum'),
        Bit('FDD_CELL_INFORMATION', Repr='hex')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # FDD_CELL_INFO automation: see 9.1.51.4
        self.csn1List[3].BitLen = self.csn1List[2]
        self.csn1List[3].BitLenFunc = self._fddci_len
    def _fddci_len(self, nr):
        n = nr()
        if n in FDD3GCellInfoLength_dict.keys():
            return FDD3GCellInfoLength_dict[n]
        else:
            return 0

class UTRANTDDNeighbourCells(CSN1):
    csn1List = [
        {'0':Bit('TDD_ARFCN', BitLen=14, Repr='hum'), '1':BREAK},
        Bit('TDD_Indic0', BitLen=1),
        Bit('NR_OF_TDD_CELLS', BitLen=5, Repr='hum'),
        Bit('TDD_CELL_INFORMATION', Repr='hex')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # TDD_CELL_INFO automation: see 9.1.51.4
        self.csn1List[3].BitLen = self.csn1List[2]
        self.csn1List[3].BitLenFunc = self._tddci_len
    def _tddci_len(self, nr):
        n = nr()
        if n in TDD3GCellInfoLength_dict.keys():
            return TDD3GCellInfoLength_dict[n]
        else:
            return 0

class ThreeGNeighbourCell(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':Bit('Index_Start_3G', BitLen=7, Repr='hum')},
        {'0':BREAK,
         '1':Bit('Absolute_Index_Start_EMR', BitLen=7, Repr='hum')},
        {'0':BREAK,
         '1':({'0':BREAK,
               '1':Bit('Bandwidth_FDD', BitLen=3)},
               # RepeatedUTRANFDDNeighbourCells
              {'0':BREAK_LOOP,
               '1':UTRANFDDNeighbourCells()})},
        {'0':BREAK,
         '1':({'0':BREAK,
               '1':Bit('Bandwidth_TDD', BitLen=3)},
               # RepeatedUTRANTDDNeighbourCells
              {'0':BREAK_LOOP,
               '1':UTRANTDDNeighbourCells()})}
        ]

MeasPar_dict = {
    1 : 'The MS shall use the Measurement Report message for reporting'
    }
class MeasurementParameters(CSN1):
    csn1List = [
        Bit('REPORT_TYPE', BitLen=1, Repr='hum', Dict=MeasPar_dict),
        Bit('SERVING_BAND_REPORTING', BitLen=2, Repr='hum')
        ]

class ThreeGMeasurementParameters(CSN1):
    csn1List = [
        Bit('Qsearch_I', BitLen=4),
        Bit('Qsearch_C_Initial', BitLen=1),
        {'0':BREAK,
         '1':(Bit('FDD_Qoffset', BitLen=4), Bit('FDD_REP_QUANT', BitLen=1),
              Bit('FDD_MULTIRAT_REPORTING', BitLen=2),
              Bit('FDD_Qmin', BitLen=3))},
        {'0':BREAK,
         '1':(Bit('TDD_Qoffset', BitLen=4), 
              Bit('TDD_MULTIRAT_REPORTING', BitLen=2))}
        ]

class GPRS_RealTimeDifference(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':({'0':BREAK, '1':Bit('BA_Index_Start_RTD', BitLen=5)},
              # RTD6
              {'0':Bit('RTD', BitLen=6), '1':BREAK_LOOP},
              # RTD6 within RTD6 ...
              {'0':{'0':Bit('RTD', BitLen=6), '1':BREAK_LOOP}, '1':BREAK_LOOP})},
        {'0':BREAK,
         '1':({'0':BREAK, '1':Bit('BA_Index_Start_RTD', BitLen=5)},
              # RTD12
              {'0':Bit('RTD', BitLen=12), '1':BREAK_LOOP},
              # RTD12 within RTD12 ...
              {'0':{'0':Bit('RTD', BitLen=12), '1':BREAK_LOOP}, '1':BREAK_LOOP})},
        ]

BSICFreqScroll_dict = {
    1 : 'Next BSIC in the structure relates to the subsequent frequency in the BA list',
    }
class R_BSIC(CSN1):
    csn1List = [
        Bit('Frequency_Scrolling', BitLen=1, Repr='hum', Dict=BSICFreqScroll_dict),
        Bit('BSIC', BitLen=6, Repr='hum')
        ]
class GPRS_BSIC(CSN1):
    csn1List = [
        {'0':BREAK, '1':Bit('BA_Index_Start_BSIC', BitLen=5)},
        Bit('BSIC', BitLen=6, Repr='hum'),
        Bit('Remaining_BSIC', BitLen=7, Repr='hum'),
        ]
    def map(self, string='', byte_offset=0):
        # work with shtr
        s, l = shtr(string), len(string)*8
        CSN1.map(self, s, byte_offset)
        bitlen = self.bit_len()
        s, l = s<<bitlen, l-bitlen
        for i in range(self.Remaining_BSIC()):
            bsic = R_BSIC()
            bsic.map(s)
            self.append(bsic)
            bitlen = bsic.bit_len()
            s, l = s<<bitlen, l-bitlen

class GPRS_REPORT_PRIORITY(CSN1):
    csn1List = [
        Bit('Number_Cells', Pt=8, BitLen=7),
        Bit('REP_PRIORITY')
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # TODO: confirm length is in bit
        #self.csn1List[0].Pt = self.csn1List[1]
        #self.csn1List[0].PtFunc = lambda rp: rp.bit_len()
        self.csn1List[1].BitLen = self.csn1List[0]
        self.csn1List[1].BitLenFunc = lambda n: n()

class GPRS_MEASUREMENT_Parameters(CSN1):
    csn1List = [
        Bit('REPORT_TYPE', BitLen=1),
        Bit('REPORTING_RATE', BitLen=1),
        Bit('INVALID_BSIC_REPORTING', BitLen=1),
        {'0':BREAK, '1':Bit('MULTIBAND_REPORTING', BitLen=2)},
        {'0':BREAK, '1':Bit('SERVING_BAND_REPORTING', BitLen=2)},
        Bit('SCALE_ORD', BitLen=2),
        {'0':BREAK, '1':(Bit('900_REPORTING_OFFSET', BitLen=3), Bit('900_REPORTING_THRESHOLD', BitLen=3))},
        {'0':BREAK, '1':(Bit('1800_REPORTING_OFFSET', BitLen=3), Bit('1800_REPORTING_THRESHOLD', BitLen=3))},
        {'0':BREAK, '1':(Bit('400_REPORTING_OFFSET', BitLen=3), Bit('400_REPORTING_THRESHOLD', BitLen=3))},
        {'0':BREAK, '1':(Bit('1900_REPORTING_OFFSET', BitLen=3), Bit('1900_REPORTING_THRESHOLD', BitLen=3))},
        {'0':BREAK, '1':(Bit('850_REPORTING_OFFSET', BitLen=3), Bit('850_REPORTING_THRESHOLD', BitLen=3))},
        ]

class GPRS_ThreeG_MEASUREMENT_Parameters(CSN1):
    csn1List = [
        Bit('Qsearch_P', BitLen=4),
        Bit('_unused', BitLen=1),
        {'0':BREAK,
         '1':(Bit('FDD_REP_QUANT', BitLen=1), Bit('FDD_MULTIRAT_REPORTING', BitLen=2))},
        {'0':BREAK,
         '1':(Bit('FDD_REPORTING_OFFSET', BitLen=3), Bit('FDD_REPORTING_THRESHOLD', BitLen=3))},
        {'0':BREAK,
         '1':Bit('TDD_MULTIRAT_REPORTING', BitLen=2)},
        {'0':BREAK,
         '1':(Bit('TDD_REPORTING_OFFSET', BitLen=3), Bit('TDD_REPORTING_THRESHOLD', BitLen=3))},
        ]

class NC_MeasurementParameters(CSN1):
    csn1List = [
        Bit('NETWORK_CONTROL_ORDER', BitLen=2),
        {'0':BREAK,
         '1':(Bit('NC_ NON_DRX_PERIOD', BitLen=3), 
              Bit('NC_REPORTING_PERIOD_I', BitLen=3),
              Bit('NC_REPORTING_PERIOD_T', BitLen=3))},
        ]

class EUTRANMeasurementParameters(CSN1):
    csn1List = [
        Bit('Qsearch_C_EUTRAN_Initial', BitLen=4),
        Bit('EUTRAN_REP_QUANT', BitLen=1),
        Bit('EUTRAN_MULTIRAT_REPORTING', BitLen=2),
        {'0':({'0':BREAK,
               '1':(Bit('EUTRAN_FDD_REPORTING_THRESHOLD', BitLen=3),
                    {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_THRESHOLD_2', BitLen=6)},
                    {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_OFFSET', BitLen=3)})},
              {'0':BREAK,
               '1':(Bit('EUTRAN_TDD_REPORTING_THRESHOLD', BitLen=3),
                    {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_THRESHOLD_2', BitLen=6)},
                    {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_OFFSET', BitLen=3)})}),
         '1':({'0':BREAK,
               '1':(Bit('EUTRAN_FDD_MEASUREMENT_REPORT_OFFSET', BitLen=6),
                    {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_THRESHOLD_2', BitLen=6)},
                    {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_OFFSET', BitLen=3)})},
              {'0':BREAK,
               '1':(Bit('EUTRAN_TDD_MEASUREMENT_REPORT_OFFSET', BitLen=6),
                    {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_THRESHOLD_2', BitLen=6)},
                    {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_OFFSET', BitLen=3)})},
              Bit('REPORTING_GRANULARITY', BitLen=1))}
        ]

class GPRSEUTRANMeasurementParameters(CSN1):
    csn1List = [
        Bit('Qsearch_P_EUTRAN', BitLen=4),
        Bit('EUTRAN_REP_QUANT', BitLen=1),
        Bit('EUTRAN_MULTIRAT_REPORTING', BitLen=2),
        {'0':BREAK,
         '1':(Bit('EUTRAN_FDD_REPORTING_THRESHOLD', BitLen=3),
              {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_THRESHOLD_2', BitLen=6)},
              {'0':BREAK, '1':Bit('EUTRAN_FDD_REPORTING_OFFSET', BitLen=3)})},
        {'0':BREAK,
         '1':(Bit('EUTRAN_TDD_REPORTING_THRESHOLD', BitLen=3),
              {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_THRESHOLD_2', BitLen=6)},
              {'0':BREAK, '1':Bit('EUTRAN_TDD_REPORTING_OFFSET', BitLen=3)})}
        ]

class RepeatedEUTRANNeighbourCells(CSN1):
    csn1List = [
        {'0':BREAK_LOOP,
         '1':(Bit('EARFCN', BitLen=16, Repr='hum'),
              {'0':BREAK, '1':Bit('MeasurementBandwidth', BitLen=3)})},
        {'0':BREAK, '1':Bit('EUTRAN_PRIORITY', BitLen=3)},
        Bit('THRES_EUTRAN_high', BitLen=5),
        {'0':BREAK, '1':Bit('THRES_EUTRAN_low', BitLen=5)},
        {'0':BREAK, '1':Bit('EUTRAN_QRXLEVMIN', BitLen=5)}
        ]

class RepeatedEUTRANNotAllowedCells(CSN1):
    csn1List = [
        # TODO: PCID Group IE ???
        _Paf_('PCIDGroup'),
        {'0':BREAK_LOOP, '1':Bit('EUTRAN_FREQUENCY_INDEX', BitLen=3)}
        ]

class RepeatedEUTRANPCIDtoTAmapping(CSN1):
    csn1List = [
        # TODO: PCID Group IE ???
        {'0':BREAK_LOOP, '1':_Paf_('PCIDGroup')},
        {'0':BREAK_LOOP, '1':Bit('EUTRAN_FREQUENCY_INDEX', BitLen=3)}
        ]

class PriorityAndEUTRANParameters(CSN1):
    csn1List = [
        # serving cell prio
        {'0':BREAK,
         '1':(Bit('GERAN_PRIORITY', BitLen=3),
              Bit('THRES_Priority_Search', BitLen=4),
              Bit('THRES_GSM_low', BitLen=4), 
              Bit('H_PRIO', BitLen=2),
              Bit('T_Reselection', BitLen=2))},
        # 3G prio
        {'0':BREAK,
         '1':(Bit('UTRAN_Start', BitLen=1),
              Bit('UTRAN_Stop', BitLen=1),
              {'0':BREAK,
               '1':(Bit('DEFAULT_UTRAN_PRIORITY', BitLen=3),
                    Bit('DEFAULT_THRES_UTRAN', BitLen=5),
                    Bit('DEFAULT_UTRAN_QRXLEVMIN', BitLen=5))},
              # reapeated UTRAN priority
              {'0':BREAK_LOOP,
               '1':({'0':BREAK_LOOP, 
                     # repeated UTRAN_FREQUENCY_INDEX
                     '1':Bit('UTRAN_FREQUENCY_INDEX', BitLen=5)},
                    {'0':BREAK, '1':Bit('UTRAN_PRIORITY', BitLen=3)},
                    Bit('THRES_UTRAN_high', BitLen=5),
                    {'0':BREAK, '1':Bit('THRES_UTRAN_low', BitLen=5)},
                    {'0':BREAK, '1':Bit('UTRAN_QRXLEVMIN', BitLen=5)})})},
        # EUTRAN: TODO
        {'0':BREAK,
         '1':(Bit('EUTRAN_CCN_ACTIVE', BitLen=1),
              Bit('EUTRAN_Start', BitLen=1),
              Bit('EUTRAN_Stop', BitLen=1),
              {'0':BREAK, '1':EUTRANMeasurementParameters()},
              {'0':BREAK, '1':GPRSEUTRANMeasurementParameters()},
              {'1':RepeatedEUTRANNeighbourCells(), '0':BREAK_LOOP},
              {'1':RepeatedEUTRANNotAllowedCells(), '0':BREAK_LOOP},
              {'1':RepeatedEUTRANPCIDtoTAmapping(), '0':BREAK_LOOP})}
        ]

class ThreeG_CSG(CSN1):
    csn1List = [
        {'0':BREAK_LOOP,
         # TODO: PSC Group IE ???
         '1':(_Paf_('PSCGroup'), {'0':BREAK_LOOP, '1':Bit('UTRAN_FREQUENCY_INDEX', BitLen=5)})},
        {'0':BREAK_LOOP,
         '1':{'0':Bit('CSG_FDD_UARFCN', BitLen=14, Repr='hum'),
              '1':Bit('CSG_TDD_UARFCN', BitLen=14, Repr='hum')}}
        ]

class EUTRAN_CSG(CSN1):
    csn1List = [
        {'0':BREAK_LOOP,
        # TODO: PCID Group IE ???
         '1':(_Paf_('PCIDGroup'),
              {'0':BREAK_LOOP, '1':Bit('EUTRAN_FREQUENCY_INDEX', BitLen=3)})},
        {'0':BREAK_LOOP, '1':Bit('CSG_EARFCN', BitLen=16, Repr='hum')}
        ]

class EnhancedCellReselectionParameters(CSN1):
    csn1List = [
        # TODO: ???
        _Paf_('TODO')
        ]

class CSGCellsReporting(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':({'0':BREAK,
               '1':(Bit('UTRAN_CSG_FDD_REPORTING_THRESHOLD', BitLen=3),
                    Bit('UTRAN_CSG_FDD_REPORTING_THRESHOLD_2', BitLen=6))},
              {'0':BREAK,
               '1':Bit('UTRAN_CSG_TDD_REPORTING_THRESHOLD', BitLen=3)})},
        {'0':BREAK,
         '1':({'0':BREAK,
               '1':(Bit('EUTRAN_CSG_FDD_REPORTING_THRESHOLD', BitLen=3),
                    Bit('EUTRAN_CSG_FDD_REPORTING_THRESHOLD_2', BitLen=6))},
              {'0':BREAK,
               '1':(Bit('EUTRAN_CSG_TDD_REPORTING_THRESHOLD', BitLen=3),
                    Bit('EUTRAN_CSG_TDD_REPORTING_THRESHOLD_2', BitLen=6))})}
        ]

class SI2quaterRestOctets(RestOctets):
    csn1List = [
        Bit('BA_IND', BitLen=1, Repr='hum'),
        Bit('3G_BA_IND', BitLen=1, Repr='hum'),
        Bit('MP_CHANGE_MARK', BitLen=1, Repr='hum'),
        Bit('SI2quater_INDEX', BitLen=4, Repr='hum'),
        Bit('SI2quater_COUNT', BitLen=4, Repr='hum'),
        {'0':BREAK, '1':MeasurementParameters()},
        {'0':BREAK, '1':GPRS_RealTimeDifference()},
        {'0':BREAK, '1':GPRS_BSIC()},
        {'0':BREAK, '1':GPRS_REPORT_PRIORITY()},
        {'0':BREAK, '1':GPRS_MEASUREMENT_Parameters()},
        {'0':BREAK, '1':NC_MeasurementParameters()},
        {'0':BREAK, '1':(Bit('extension_length', Pt=7, BitLen=8, Repr='hum'), \
                         Bit('SI2q_extension_info'))},
        {'0':BREAK, '1':ThreeGNeighbourCell()},
        {'0':BREAK, '1':ThreeGMeasurementParameters()},
        {'0':BREAK, '1':GPRS_ThreeG_MEASUREMENT_Parameters()},
        # addition in Rel.5
        {'L':BREAK, 
         'H':({'0':BREAK,
               '1':(Bit('FDD_Qmin_offset', BitLen=3), Bit('FDD_RSCPmin', BitLen=4))},
              {'0':BREAK,
               '1':{'0':BREAK, '1':Bit('FDD_REPORTING_THRESHOLD_2', BitLen=2)}},
              # addition in Rel.6
              {'L':BREAK,
               'H':(Bit('ThreeG_CCN_ACTIVE', BitLen=1),
                    # addition in Rel.7
                    {'L':BREAK,
                     'H':({'0':BREAK,
                           '1':(Bit('700_REPORTING_OFFSET', BitLen=3),
                                Bit('700_REPORTING_THRESHOLD', BitLen=3))},
                          {'0':BREAK,
                           '1':(Bit('810_REPORTING_OFFSET', BitLen=3),
                                Bit('810_REPORTING_THRESHOLD', BitLen=3))},
                          # addition in Rel.8
                          {'L':BREAK,
                           'H':({'0':BREAK,
                                 '1':PriorityAndEUTRANParameters()},
                                {'0':BREAK,
                                 '1':ThreeG_CSG()},
                                {'0':BREAK,
                                 '1':EUTRAN_CSG()},
                                # addition in Rel.9
                                {'L':BREAK,
                                 'H':({'0':BREAK,
                                       '1':EnhancedCellReselectionParameters()},
                                      {'0':BREAK,
                                       '1':CSGCellsReporting()})})})})})}
    ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # TODO: confirm length is in bits
        #self.csn1List[11]['1'][0].Pt = self.csn1List[11]['1'][1]
        #self.csn1List[11]['1'][0].PtFunc = lambda ei: ei.bit_len()-1
        self.csn1List[11]['1'][1].BitLen = self.csn1List[11]['1'][0]
        self.csn1List[11]['1'][1].BitLenFunc = lambda l: l()+1


###
# 44.018, section 10.5.2.34: System Info type 3 rest octets
#
class SelectionParameters(CSN1):
    csn1List = [
        Bit('CELL_BAR_QUALIFY', BitLen=1, Repr='hum'),
        Bit('CELL_RESELECT_OFFSET', BitLen=6),
        Bit('TEMPORARY_OFFSET', BitLen=3),
        Bit('PENALTY_TIME', BitLen=5),
        ]
SI13Pos_dict = {
    0 : 'SI13 sent on BCCH Norm',
    1 : 'SI13 sent on BCCH Ext'
    }
class GPRSIndicator(CSN1):
    csn1List = [
        Bit('RA_COLOUR', BitLen=3, Repr='hum'),
        Bit('SI13_POSITION', BitLen=1, Repr='hum', Dict=SI13Pos_dict),
        ]
SI2terInd_dict = {
    'L' : 'SI2ter not available',
    'H' : 'SI2ter available'
    }
ECSCtrl_dict = {
    'L' : 'Early Classmark Sending is forbidden',
    'H' : 'Early Classmark Sending is allowed',
    }
ECSRes_dict = {
    'L' : 'No 3G or Iu mode classmark shall be sent with early classmark',
    'H' : '3G and Iu mode classmark controlled by early classmark control'
    }
SI2quater_dict = {
    0 : 'SI2 quater sent on BCCH Norm',
    1 : 'SI2 quater sent on BCCH Ext'
    }
SI13alt_dict = {
    0 : 'SI13 alt sent on BCCH Norm',
    1 : 'SI13 alt sent on BCCH Ext'
    }
class SI3RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 'H':SelectionParameters()},
        {'L':BREAK, 'H':Bit('PowerOffset', BitLen=2)},
        LHFlag('SI2terIndicator', Dict=SI2terInd_dict),
        LHFlag('EarlyClassmarkSendingControl', Dict=ECSCtrl_dict),
        {'L':BREAK, 'H':Bit('SchedulingWHERE', BitLen=3)},
        {'L':BREAK, 'H':GPRSIndicator()},
        LHFlag('3GEarlyClassmarkSendingRestriction', Dict=ECSRes_dict),
        {'L':BREAK, 
         'H':Bit('SI2quater_POSITION', BitLen=1, Repr='hum', Dict=SI2quater_dict)},
        #Bit('SI13altPOSITION', BitLen=1, Repr='hum', Dict=SI13alt_dict),
        # this bit depends of the context (Iu mode or not): damned 3GPP !
        ]

###
# 44.018, section 10.5.2.35: System Info type 4 rest octets
#
class LSAIDInfo_(CSN1):
    csn1List = [
        {'0':Bit('LSA_ID', BitLen=24, Repr='hex'),
         '1':Bit('ShortLSA_ID', BitLen=10, Repr='hex')},
        ]
class LSAIDInformation(CSN1):
    def map(self, string='', byte_offset=0):
        # work with shtr
        s, l = shtr(string), len(string)*8
        m = 1
        while m and l>0:
            inf = LSAIDInfo_()
            inf.map(s)
            self.append(inf)
            bitlen = inf.bit_len()
            s, l = s<<bitlen, l-bitlen
            mor = Bit('more', BitLen=1)
            mor.map(s)
            self.append(mor)
            s, l = s<<1, l-1
            m = mor()
class LSAParameters(CSN1):
    csn1List = [
        Bit('PRIO_THR', BitLen=3),
        Bit('LSA_OFFSET', BitLen=3),
        {'0':BREAK, '1':Bit('MCC', BitLen=12, Repr='hex')},
        Bit('MNC', BitLen=12, Repr='hex')
        ]
BreakInd_dict = {
    'L' : 'Additional parameters not sent in SYSTEM INFORMATION TYPE 7 and 8',
    'H' : 'Additional parameters sent in SYSTEM INFORMATION TYPE 7 and 8'
    }
class SI4RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 'H':SelectionParameters()},
        {'L':BREAK, 'H':Bit('PowerOffset', BitLen=2)},
        {'L':BREAK, 'H':GPRSIndicator()},
        {'L':LHFlag('BreakIndicator', Dict=BreakInd_dict),
         'H':({'L':BREAK, 'H':LSAParameters()},
              {'L':BREAK, 'H':Bit('CellIdentity', BitLen=16, Repr='hex')},
              {'L':BREAK, 'H':LSAIDInformation()},
              {'L':BREAK, 'H':Bit('CBQ3', BitLen=2)},
              {'0':BREAK,
               '1':Bit('SI13_POSITION', BitLen=1, Repr='hum', Dict=SI13Pos_dict)})}
        ]

###
# 44.018, section 10.5.2.37b: System Info type 13 rest octets
#
# 44.060, section 12.24: GPRS Cell Options
class ExtensionInformation(CSN1):
    csn1List = [
        {'0':BREAK,
         '1':(Bit('EGPRS_PACKET_CHANNEL_REQUEST', BitLen=1),
              Bit('BEP_PERIOD', BitLen=4))},
        Bit('PFC_FEATURE_MODE', BitLen=1),
        Bit('DTM_SUPPORT', BitLen=1),
        Bit('BSS_PAGING_COORDINATION', BitLen=1),
        Bit('CCN_ACTIVE', BitLen=1),
        Bit('NW_EXT_UTBF', BitLen=1),
        Bit('MULTIPLE_TBF_CAPABILITY', BitLen=1),
        Bit('EXT_UTBF_NODATA', BitLen=1),
        Bit('DTM_ENHANCEMENTS_CAPABILITY', BitLen=1),
        {'0':BREAK,
         '1':(Bit('DEDICATED_MODE_MBMS_NOTIFICATION_SUPPORT', BitLen=1),
              Bit('MNCI_SUPPORT', BitLen=1))},
        Bit('REDUCED_LATENCY_ACCESS', BitLen=1)
        ]
class GPRSCellOptions(CSN1):
    csn1List = [
        Bit('NMO', BitLen=2),
        Bit('T3168', BitLen=3),
        Bit('T3192', BitLen=3),
        Bit('DRX_TIMER_MAX', BitLen=3),
        Bit('ACCESS_BURST_TYPE', BitLen=1),
        Bit('CONTROL_ACK_TYPE', BitLen=1),
        Bit('BS_CV_MAX', BitLen=4, Repr='hum'),
        {'0':BREAK,
         '1':(Bit('PAN_DEC', BitLen=3, Repr='hum'),
              Bit('PAN_INC', BitLen=3, Repr='hum'),
              Bit('PAN_MAX', BitLen=3, Repr='hum'))},
        {'0':BREAK,
         '1':(Bit('ExtensionLength', Pt=7, BitLen=6, Repr='hum'),
              Bit('ExtensionInformation'))},
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        # extension info automation: 
        #self.csn1List[8]['1'][0].Pt = self.csn1List[8]['1'][1]
        #self.csn1List[8]['1'][0].PtFunc = lambda ei: ei.bit_len()-1
        self.csn1List[8]['1'][1].BitLen = self.csn1List[8]['1'][0]
        self.csn1List[8]['1'][1].BitLenFunc = lambda l: 1+l()
    # define a .map() that introduce ExtensionInformation() fields
    def map(self, string='', byte_offset=0):
        CSN1.map(self, string, byte_offset)
        # Try to get ExtensionInformation()
        if hasattr(self, 'ExtensionLength'):
            l = self.ExtensionLength()+1
            v = self[-1] # this is ExtensionInformation
            w = ExtensionInformation()
            w.map(str(v))
            while w.bit_len() > v.bit_len():
                w.remove(w[-1])
            if w.bit_len() == v.bit_len():
                # replace v with w
                self.remove(self[-1])
                self.append(w)
                self.ExtensionLength.Pt = self[-1]
                
# TS 44.060, section 12.9a: GPRS power ctrl
class GPRSPowerControlParameters(CSN1):
    csn1List = [
        Bit('ALPHA', BitLen=4),
        Bit('T_AVG_W', BitLen=5),
        Bit('T_AVG_T', BitLen=5),
        Bit('PC_MEAS_CHAN', BitLen=1),
        Bit('N_AVG_I', BitLen=4)
        ]
class PBCCHDescription(CSN1):
    csn1List = [
        Bit('Pb', BitLen=4),
        Bit('TSC', BitLen=3),
        Bit('TN', BitLen=3),
        {'0':{'0':BREAK,
              '1':Bit('ARFCN', BitLen=10, Repr='hum')},
         '1':Bit('MAIO', BitLen=2)}
        ]
class SI13RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK,
         'H':(Bit('BCCH_CHANGE_MARK', BitLen=3, Repr='hum'),
              Bit('SI_CHANGE_FIELD', BitLen=4),
              {'0':BREAK,
               '1':(Bit('SI13_CHANGE_MARK', BitLen=2, Repr='hum'),
                    GPRSMobileAllocation())},
              {'0':(Bit('RAC', BitLen=8, Repr='hum'),
                    Bit('SPGC_CCCH_SUP', BitLen=1),
                    Bit('PRIORITY_ACCESS_THR', BitLen=3),
                    Bit('NETWORK_CONTROL_ORDER', BitLen=2),
                    GPRSCellOptions(),
                    GPRSPowerControlParameters()),
               '1':(Bit('PSI1_REPEAT_PERIOD', BitLen=4),
                    PBCCHDescription())},
              {'L':BREAK, # Rel.99
               'H':(Bit('SGSNR', BitLen=1, Repr='hum', \
                        Dict={0:'R98 or older', 1:'R99 onwards'}),
                    {'L':BREAK, # Rel.4
                     'H':(Bit('SI_STATUS_IND', BitLen=1),
                          {'L':BREAK, # Rel.6
                           'H':({'0':BREAK,
                                 '1':Bit('LB_MS_TXPWR_MAX_CCH', BitLen=5)},
                                Bit('SI2n_SUPPORT', BitLen=2))})})})}
    ]


###
# 44.018, section 10.5.2.35a
PCRFlag_dict = {
    0 : 'paging channel is not restructured',
    1 : 'paging channel is restructured'
    }
class PCHandNCHinfo(CSN1):
    csn1List = [
        Bit('paging_channel_restructuring', Dict=PCRFlag_dict, Repr='hum'),
        Bit('NLN_SACCH', BitLen=2),
        {'0':BREAK, '1':Bit('Call_priority', BitLen=3)},
        Bit('NLN_status', BitLen=1),
        ]
VBSVGCSNot_dict = {
    0 : 'network does not provide notification on FACCH, mobile should inspect NCH for notifications',
    1 : 'mobile shall be notified on incoming high priority VBS/VGCS calls through	NOTIFICATION/FACCH, mobile need not to inspect the NCH'
    }
VBSVGCSPag_dict = {
    0 : 'network does not provide paging information on FACCH, mobile should inspect PCH for pagings',
    1 : 'mobile shall be notified on incoming high priority point-to-point calls through NOTIFICATION/FACCH, mobile need not to inspect the PCH'
    }
BandInd_dict = {
    'L' : 'Band 1800',
    'H' : 'Band 1900'
    }
class SI6RestOctets(RestOctets):
    csn1List = [
        {'L':BREAK, 'H':PCHandNCHinfo()},
        {'L':BREAK, 
         'H':(Bit('VBS_VGCS_inband_notifications', BitLen=1, Dict=VBSVGCSNot_dict, Repr='hum'), \
              Bit('VBS_VGCS_inband_pagings', BitLen=1, Dict=VBSVGCSPag_dict, Repr='hum'))},
        {'L':BREAK, 
         'H':(Bit('DTM_support_RAC', BitLen=8, Repr='hum'), 
              Bit('DTM_support_MAX_LAPDm', BitLen=3))}, # DTM support
        LHFlag('BandIndicator', Dict=BandInd_dict),
        {'L':BREAK, 'H':Bit('GPRS_MS_TXPWR_MAX_CCH', BitLen=5, Repr='hum')},
        {'L':BREAK,
         'H':(Bit('DEDICATED_MODE_MBMS_NOTIFICATION_SUPPORT', BitLen=1), \
              Bit('MNCI_SUPPORT', BitLen=1))},
        {'L':BREAK,
         'H':{'0':BREAK, '1':Bit('AMR_Config', BitLen=4)}}
        ]
    # for SI6 rest octets, rest bits are random (not 2B, to avoid known plaintext
    # when attacking A5 encryption
#
