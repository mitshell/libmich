# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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
# * File Name : formats/UMA.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from struct import unpack
from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.L3Mobile_IE import LAI, ID, MSCm2
#from libmich.formats.L3Mobile import L3Mobile
from libmich.formats.L3Mobile import parse_L3, Layer3

###
# GA-RC is the basis UMA signaling layer:
# 1) GA-RC discovery request -> accept / reject <-
# 2) GA-RC register request -> accept / reject / redirect <-
# 3) GA-RC deregister <->
# 4) GA-RC keep alive ->
# 5) GA-RC synch info ->
# 6) GA-RC cell broadcast info <-
###

'''
### Implements TS 44.318 v920, section 11 ###
'''

ProtocolDiscriminator = IANA_dict({
0 : "GA-RC",
1 : "GA-CSR",
2 : "GA-PSR",
3 : "GA-RRC",
})

RCMsgType = IANA_dict({
1 : 'GA-RC DISCOVERY REQUEST',
2 : 'GA-RC DISCOVERY ACCEPT',
3 : 'GA-RC DISCOVERY REJECT',
4 : 'unassigned',
16 : 'GA-RC REGISTER REQUEST',
17 : 'GA-RC REGISTER ACCEPT',
18 : 'GA-RC REGISTER REDIRECT',
19 : 'GA-RC REGISTER REJECT',
20 : 'GA-RC DEREGISTER',
21 : 'GA-RC REGISTER UPDATE UPLINK',
22 : 'GA-RC REGISTER UPDATE DOWNLINK',
23 : 'GA-RC CELL BROADCAST INFO',
24 : 'unassigned',
32 : 'GA-CSR CIPHERING MODE COMMAND',
33 : 'GA-CSR CIPHERING MODE COMPLETE',
34 : 'unassigned',
48 : 'GA-CSR ACTIVATE CHANNEL',
49 : 'GA-CSR ACTIVATE CHANNEL ACK',
50 : 'GA-CSR ACTIVATE CHANNEL COMPLETE',
51 : 'GA-CSR ACTIVATE CHANNEL FAILURE',
52 : 'GA-CSR CHANNEL MODE MODIFY',
53 : 'GA-CSR CHANNEL MODE MODIFY ACKNOWLEDGE',
54 : 'unassigned',
64 : 'GA-CSR RELEASE',
65 : 'GA-CSR RELEASE COMPLETE',
66 : 'GA-CSR CLEAR REQUEST',
67 : 'unassigned',
80 : 'GA-CSR HANDOVER ACCESS',
81 : 'GA-CSR HANDOVER COMPLETE',
82 : 'GA-CSR UPLINK QUALITY INDICATION',
83 : 'GA-CSR HANDOVER INFORMATION',
84 : 'GA-CSR HANDOVER COMMAND',
85 : 'GA-CSR HANDOVER FAILURE',
86 : 'unassigned',
96 : 'GA-CSR PAGING REQUEST',
97 : 'GA-CSR PAGING RESPONSE',
98 : 'unassigned',
112 : 'GA-CSR UPLINK DIRECT TRANSFER',
113 : 'unassigned',
114 : 'GA-CSR DOWNLINK DIRECT TRANSFER',
115 : 'GA-CSR STATUS',
116 : 'GA-RC KEEP ALIVE',
117 : 'GA-CSR CLASSMARK ENQUIRY',
118 : 'GA-CSR CLASSMARK CHANGE',
119 : 'GA-CSR GPRS SUSPENSION REQUEST',
120 : 'GA-RC SYNCHRONIZATION INFORMATION',
121 : 'GA-CSR UTRAN CLASSMARK CHANGE',
122 : 'unassigned',
128 : 'GA-CSR REQUEST',
129 : 'GA-CSR REQUEST ACCEPT',
130 : 'GA-CSR REQUEST REJECT',
131 : 'unassigned',
})

PSRMsgType = IANA_dict({
1 : 'GA-PSR-DATA',
2 : 'GA-PSR UNITDATA',
3 : 'GA-PSR-PS-PAGE',
4 : 'unassigned',
6 : 'GA-PSR-UFC-REQ',
7 : 'GA-PSR-DFC-REQ',
8 : 'GA-PSR-ACTIVATE-UTC-REQ',
9 : 'GA-PSR-ACTIVATE-UTC-ACK',
10 : 'GA-PSR-DEACTIVATE-UTC-REQ',
11 : 'GA-PSR-DEACTIVATE-UTC-ACK',
12 : 'GA-PSR STATUS',
13 : 'GA-PSR HANDOVER COMPLETE',
14 : 'GA-PSR UPLINK QUALITY INDICATION',
15 : 'GA-PSR HANDOVER INFORMATION',
16 : 'GA-PSR HANDOVER COMMAND',
17 : 'GA-PSR HANDOVER CONTINUE',
18 : 'GA-PSR HANDOVER FAILURE',
19 : 'unassigned',
})

RRCMsgType = IANA_dict({
1 : 'GA-RRC REQUEST',
2 : 'GA-RRC REQUEST ACCEPT',
3 : 'GA-RRC REQUEST REJECT',
4 : 'GA-RRC RELEASE REQUEST',
5 : 'GA-RRC RELEASE',
6 : 'GA-RRC RELEASE COMPLETE',
7 : 'GA-RRC PAGING REQUEST',
8 : 'GA-RRC ACTIVATE CHANNEL',
9 : 'GA-RRC ACTIVATE CHANNEL ACK',
10 : 'GA-RRC ACTIVATE CHANNEL COMPLETE',
11 : 'GA-RRC MODIFY CHANNEL',
12 : 'GA-RRC MODIFY CHANNEL ACK',
13 : 'GA-RRC DEACTIVATE CHANNEL REQUEST',
14 : 'GA-RRC DEACTIVATE CHANNEL',
15 : 'GA-RRC DEACTIVATE CHANNEL COMPLETE',
16 : 'GA-RRC SECURITY MODE COMMAND',
17 : 'GA-RRC SECURITY MODE COMPLETE',
18 : 'GA-RRC INITIAL DIRECT TRANSFER',
19 : 'GA-RRC UPLINK DIRECT TRANSFER',
20 : 'GA-RRC DOWNLINK DIRECT TRANSFER',
21 : 'GA-RRC RELOCATION INFORMATION',
22 : 'GA-RRC RELOCATION COMMAND',
23 : 'GA-RRC RELOCATION ACCESS',
24 : 'GA-RRC RELOCATION COMPLETE',
25 : 'GA-RRC RELOCATION FAILURE',
26 : 'GA-RRC RELOCATION REQUEST',
27 : 'GA-RRC RELOCATION REQUEST ACK',
28 : 'GA-RRC UPLINK QUALITY INDICATION',
29 : 'GA-RRC STATUS',
30 : 'unassigned',
255 : 'GA-RRC PDU',
})

IEType = IANA_dict({
1 : 'Mobile Identity',
2 : 'GAN Release Indicator',
3 : 'Radio Identity',
4 : 'GERAN Cell Identity',
5 : ('Location Area Identification', 'LAI'),
6 : 'GERAN/UTRAN coverage Indicator',
7 : 'GAN Classmark',
8 : 'Geographical Location',
9 : 'GANC-SEGW IP Address',
10 : 'GANC-SEGW Fully Qualified Domain/Host Name',
11 : 'Redirection Counter',
12 : 'Discovery Reject Cause',
13 : 'GAN Cell Description',
14 : 'GAN Control Channel Description',
15 : 'Cell Identifier List',
16 : ('TU3907 Timer', 'TU3907'),
17 : 'GSM RR/UTRAN RRC State',
18 : 'Routing Area Identification',
19 : 'GAN Band',
20 : 'GA-RC/GA-CSR/GA-PSR State',
21 : 'Register Reject Cause',
22 : ('TU3906 Timer', 'TU3906'),
23 : ('TU3910 Timer', 'TU3910'),
24 : ('TU3902 Timer', 'TU3902'),
26 : 'L3 Message',
27 : 'Channel Mode',
28 : ('Mobile Station Classmark 2', 'MSCm2'),
29 : 'RR Cause',
30 : 'Cipher Mode Setting',
31 : 'GPRS Resumption',
32 : 'Handover From GAN Command',
33 : 'UL Quality Indication',
34 : 'TLLI',
35 : 'Packet Flow Identifier',
36 : 'Suspension Cause',
37 : ('TU3920 Timer', 'TU3920'),
38 : 'QoS',
39 : 'GA-PSR Cause',
40 : 'User Data Rate',
41 : 'Routing Area Code',
42 : 'AP Location',
43 : ('TU4001 Timer', 'TU4001'),
44 : 'Location Status',
45 : 'Cipher Response',
46 : 'Ciphering Command RAND',
47 : 'Ciphering Command MAC',
48 : 'Ciphering Key Sequence Number',
49 : 'SAPI ID',
50 : 'Establishment Cause',
51 : 'Channel Needed',
52 : 'PDU in Error',
53 : 'Sample Size',
54 : 'Payload Type',
55 : 'Multi-rate Configuration',
56 : 'Mobile Station Classmark 3',
57 : 'LLC-PDU',
58 : 'Location Black List indicator',
59 : 'Reset Indicator',
60 : ('TU4003 Timer', 'TU4003'),
61 : 'AP Service Name',
62 : 'GAN Service Zone Information',
63 : 'RTP Redundancy Configuration',
64 : 'UTRAN Classmark',
65 : 'Classmark Enquiry Mask',
66 : 'UTRAN Cell Identifier List',
67 : 'Serving GANC table indicator',
68 : 'Registration indicators',
69 : 'GAN PLMN List',
71 : 'Required GAN Services',
72 : 'Broadcast Container',
73 : ('3G Cell Identity', '3GCellID'),
74 : '3G Security Capability',
75 : 'NAS Synchronisation Indicator',
76 : 'GANC TEID',
77 : 'MS TEID',
78 : 'UTRAN RRC Message',
79 : 'GAN Mode Indicator',
80 : 'CN Domain Identity',
81 : 'GAN Iu Mode Cell Description',
82 : '3G UARFCN',
83 : 'RAB ID',
84 : 'RAB ID List',
85 : 'GA-RRC Establishment Cause',
86 : 'GA-RRC Cause',
87 : 'GA-RRC Paging Cause',
88 : 'Intra Domain NAS Node Selector',
89 : 'CTC Activation List',
90 : 'CTC Description',
91 : 'CTC Activation Ack List',
92 : 'CTC Activation Ack Description',
93 : 'CTC Modification List',
94 : 'CTC Modification Ack List',
95 : 'CTC Modification Ack Description',
96 : 'MS Radio Identity',
97 : 'GANC IP Address',
98 : 'GANC FQDN',
99 : 'IP address for GPRS user data transport',
100 : 'UDP Port for GPRS user data transport',
103 : 'GANC TCP port',
104 : 'RTP UDP port',
105 : 'RTCP UDP port',
106 : 'GERAN Received Signal Level List',
107 : 'UTRAN Received Signal Level List',
108 : 'PS Handover to GERAN Command',
109 : 'PS Handover to UTRAN Command',
110 : 'PS Handover to GERAN PSI',
111 : 'PS Handover to GERAN SI',
112 : 'TU4004 Timer',
115 : 'PTC Activation List',
116 : 'PTC Description',
117 : 'PTC Activation Ack List',
118 : 'PTC Activation Ack Description',
119 : 'PTC Modification List',
120 : 'PTC Modification Ack List',
121 : 'PTC Modification Ack Description',
122 : 'RAB Configuration',
123 : 'Multi-rate Configuration 2',
124 : 'Selected Integrity Protection Algorithm',
125 : 'Selected Encryption Algorithm',
126 : 'CN Domains to Handover',
127 : 'SRNS Relocation Info',
128 : 'MS Radio Access Capability',
129 : 'Handover Reporting Control',
130 : 'unassigned',
})



class UMA(Block):
	# selector for type of IE to use
	# 'new' supports extended Length and Tag
	# not 'old'
	#_IE_type = 'new'
    _IE_type = 'old'
	
    def __init__(self, mode='control', protocol='GA_RC', 
                       type=RCMsgType['GA-RC DISCOVERY REQUEST']):
        
        Block.__init__(self, Name='UMA')
        
        if mode == 'user':
            if protocol == 'GA_PSR':
                self.append( GA_PSR_UP_hdr(type=type) )
            elif protocol == 'GA_RRC':
                self.append( GA_RRC_UP_hdr(type=type) )
        
        elif mode == 'control':
            if protocol == 'GA_RC':
                self.append( GA_RC_hdr(type=type) )
            elif protocol == 'GA_CSR':
                self.append( GA_CSR_hdr(type=type) )
            elif protocol == 'GA_PSR':
                self.append( GA_PSR_hdr(type=type) )
            elif protocol == 'GA_RRC':
                self.append( GA_RRC_hdr(type=type) )
    
    def __lt__(self, newLayer):
        # to use when appending a payload with hierarchy 1, typical for TLV over GA header
        self.append(newLayer)
        self[-1].hierarchy = self[0].hierarchy + 1
    
    def parse(self, s='', mode='control', process_L3=True):
        # map GA header, after checking the protocol discriminator value
        pd = ord(s[2]) & 0x0F
        Block.__init__(self, Name='UMA')
        if pd in hdrCall.keys():
            # now easy way to distinguish CP from UP at the UMA layer
            # (may depend if its carried over TCP or UDP?)
            self.append( hdrCall[pd]() )
        else: 
            self.append( GA_RC_hdr() )
        self[0].map(s)
        s = s[ len(self[0]) : ]
        
        # map iteratively the TLV Information Element
        while len(s) > 0:
            if self._IE_type == 'old':
                self < UMA_IE_old()
            else:
                self < UMA_IE()
            self[-1].map(s)
            s = s[ len(self[-1]) : ]
            # check if can also handle V with L3Mobile_IE:
            if self[-1].T() == IEType['Location Area Identification']:
                self.map_last_to_IE(LAI)
            elif self[-1].T() == IEType['Mobile Identity']:
                self.map_last_to_IE(ID)
            elif self[-1].T() == IEType['Mobile Station Classmark 2']:
                self.map_last_to_IE(MSCm2)
            elif self[-1].T() == IEType['GAN PLMN List']:
                self.map_last_to_IE(PLMNlist)
            elif process_L3 and self[-1].T() == IEType['L3 Message']:
                l3 = parse_L3(self[-1].V())
                if isinstance(l3, Layer3):
                # otherwise, cill get a RawLayer()
                    self[-1].V < None
                    self[-1].V > l3
    
    def map_last_to_IE(self, IE):
        # get string buffer from last Value (V)
        buf = self[-1].V()
        # empty V
        self[-1].V < None
        # make V point to a L3Mobile_IE Layer
        self[-1].V > IE()
        # make the IE parse the string buffer
        # in case we have a Block (no specific cases in mind, but who knows...)
        if hasattr(self[-1].V.Pt, 'parse'):
            self[-1].V.Pt.parse(buf)
        # in case we only have a Layer (e.g. ID())
        else:
            self[-1].V.Pt.map(buf)

class GA_RC_hdr(Layer):
    constructorList = [
        Int(CallName='len', ReprName='Message Length', Type='uint16'),
        Bit(CallName='si', ReprName='Skip Indicator', Pt=0, BitLen=4, Repr='hex'),
        Bit(CallName='pd', ReprName='Protocol Discriminator', Pt=0, BitLen=4, 
            Repr='hum', Dict=ProtocolDiscriminator),
        Int(CallName='type', ReprName='Message Type', Type='uint8', Dict=RCMsgType)
        ]
    
    def __init__(self, type=0):
        Layer.__init__(self, CallName='hdr')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay()) + 2
        self.type.Pt = type

class GA_CSR_hdr(Layer):
    constructorList = [
        Int(CallName='len', ReprName='Message Length', Type='uint16'),
        Bit(CallName='si', ReprName='Skip Indicator', Pt=0, BitLen=4, Repr='hex'),
        Bit(CallName='pd', ReprName='Protocol Discriminator', Pt=1, BitLen=4, 
            Repr='hum', Dict=ProtocolDiscriminator),
        Int(CallName='type', ReprName='Message Type', Type='uint8', Dict=RCMsgType)
        ]
    
    def __init__(self, type=0):
        Layer.__init__(self, CallName='hdr')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay()) + 2
        self.type.Pt = type


class GA_PSR_hdr(Layer):
    constructorList = [
        Int(CallName='len', ReprName='Message Length', Type='uint16'),
        Bit(CallName='si', ReprName='Skip Indicator', Pt=0, BitLen=4, Repr='hex'),
        Bit(CallName='pd', ReprName='Protocol Discriminator', Pt=2, BitLen=4, 
            Repr='hum', Dict=ProtocolDiscriminator),
        Int(CallName='type', ReprName='Message Type', Type='uint8', Dict=PSRMsgType),
        Int(CallName='tlli', ReprName='Temporary Logical Link Identity', Type='uint32'),
        ]
    
    def __init__(self, type=0, tlli=0):
        Layer.__init__(self, CallName='hdr')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay()) + 2
        self.type.Pt = type
        self.tlli.Pt = tlli


class GA_PSR_UP_hdr(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Message Type', Type='uint8', Dict=PSRMsgType),
        Int(CallName='tlli', ReprName='Temporary Logical Link Identity', Type='uint32'),
        Int(CallName='sqn', ReprName='Sequence Number', Type='uint16'),
        ]
    
    def __init__(self, type=0, tlli=0, sqn=0):
        Layer.__init__(self, CallName='hdr')
        self.type.Pt = type
        self.tlli.Pt = tlli
        self.sqn.Pt = sqn


class GA_RRC_hdr(Layer):
    constructorList = [
        Int(CallName='len', ReprName='Message Length', Type='uint16'),
        Bit(CallName='si', ReprName='Skip Indicator', Pt=0, BitLen=4, Repr='hex'),
        Bit(CallName='pd', ReprName='Protocol Discriminator', Pt=3, BitLen=4, 
            Repr='hum', Dict=ProtocolDiscriminator),
        Int(CallName='type', ReprName='Message Type', Type='uint8', Dict=RRCMsgType)
        ]
    
    def __init__(self, type=0):
        Layer.__init__(self, CallName='hdr')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay()) + 2
        self.type.Pt = type


class GA_RRC_UP_hdr(Layer):
    # same header as for GTP-U in TS 29.merdier
    constructorList = [
        Bit(CallName='vers', ReprName='Version', Pt=1, BitLen=3),
        Bit(CallName='PT', ReprName='Payload Type', Pt=1, BitLen=1),
        Bit(CallName='spare', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Extension Header Flag', Pt=0, BitLen=1),
        Bit(CallName='S', ReprName='Sequence Number Flag', Pt=0, BitLen=1),
        Bit(CallName='PN', ReprName='N-PDU Number Flag', Pt=0, BitLen=1),
        Int(CallName='type', ReprName='Message Type', Pt=0xFF, Type='uint8', 
            Dict=RRCMsgType),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='teid', ReprName='Tunnel Endpoint ID', Type='uint32'),
        ]
    
    def __init__(self, teid=0):
        Layer.__init__(self, CallName='hdr')
        self.teid.Pt = teid
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())

class UMA_IE_old(Layer):
    constructorList = [
        Int(CallName='T', ReprName='Tag', Type='uint8', \
            Dict=IEType),
        Int(CallName='L', ReprName='Length', Type='uint8'),
        Str(CallName='V', ReprName='Value'),
        ]
    
    def __init__(self, T=1, V=''):
        Layer.__init__(self, CallName='IE_old')
        # Tag
        self.T.Pt = T
        # Length / Value business
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)


class UMA_IE(Layer):
    constructorList = [
        Bit(CallName='Text', Pt=0, BitLen=1),
        Bit(CallName='T', ReprName='Tag', BitLen=7, Repr='hum', Dict=IEType),
        Bit(CallName='Lext', Pt=0, BitLen=1),
        Bit(CallName='L', ReprName='Length', Repr='hum', BitLen=7),
        Str(CallName='V', ReprName='Value'),
        ]
    
    def __init__(self, T=1, V=''):
        Layer.__init__(self, CallName='IE')
        # trigger extension bits and adapt consequently T and L BitLen attributes
        self.Text.Pt = self.T
        self.Text.PtFunc = lambda T: self.__trig_Text(int(T))
        self.Lext.Pt = self.V
        self.Lext.PtFunc = lambda V: self.__trig_Lext(len(V))
        # Tag
        self.T.Pt = T
        self.T.BitLen = self.T
        self.T.BitLenFunc = lambda T: self.__thres(T)
        # Length / Value business
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
    
    def __thres(self, tag):
        if tag.Val: val = int(tag.Val)
        elif tag.Pt: val = int(tag.Pt)
        else: val = 0
        if val < 128: return 7
        else: return 15
    
    def __trig_Text(self, val):
        if val > 127: return 1
        else: return 0
    
    def __trig_Lext(self, val):
        if val > 127:
            self.L.BitLen = 15
            return 1
        else: 
            self.L.BitLen = 7
            return 0

    def map(self, s):
        if unpack('!B', s[0])[0] & 0x80 == 0x80:
            self.T.BitLen = 15
            self.T.BitLenFunc = None
            #BitLenFunc, self.T.BitLenFunc = self.T.BitLenFunc, None
        if unpack('!B', s[self.T.bit_len()//8+1])[0] & 0x80 == 0x80:
            self.L.BitLen = 15
        Layer.map(self, s)
        #self.BitLenFunc = BitLenFunc


hdrCall = {
    0 : GA_RC_hdr, 
    1 : GA_CSR_hdr, 
    2 : GA_PSR_hdr, 
    3 : GA_RRC_hdr,
    4 : GA_RC_hdr,
    }

