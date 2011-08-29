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
# * File Name : formats/IP.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Bit, \
     Layer, RawLayer, Block
from libmich.core.IANA_dict import IANA_dict
#from libmich.core.IANA_dict import IPv4 as IPv4_dic
from libmich.utils.inet import checksum
from socket import inet_aton
from struct import pack, unpack


IP_prot = IANA_dict({
    0 : "HOPOPT",
    1 : "ICMP",
    2 : "IGMP",
    3 : "GGP",
    4 : "IP",
    5 : "ST",
    6 : "TCP",
    7 : "CBT",
    8 : "EGP",
    9 : "IGP",
    10 : "BBN-RCC-MON",
    11 : "NVP-II",
    12 : "PUP",
    13 : "ARGUS",
    14 : "EMCON",
    15 : "XNET",
    16 : "CHAOS",
    17 : "UDP",
    18 : "MUX",
    19 : "DCN-MEAS",
    20 : "HMP",
    21 : "PRM",
    22 : "XNS-IDP",
    23 : "TRUNK-1",
    24 : "TRUNK-2",
    25 : "LEAF-1",
    26 : "LEAF-2",
    27 : "RDP",
    28 : "IRTP",
    29 : "ISO-TP4",
    30 : "NETBLT",
    31 : "MFE-NSP",
    32 : "MERIT-INP",
    33 : "DCCP",
    34 : "3PC",
    35 : "IDPR",
    36 : "XTP",
    37 : "DDP",
    38 : "IDPR-CMTP",
    39 : "TP++",
    40 : "IL",
    41 : "IPv6",
    42 : "SDRP",
    43 : "IPv6-Route",
    44 : "IPv6-Frag",
    45 : "IDRP",
    46 : "RSVP",
    47 : "GRE",
    48 : "DSR",
    49 : "BNA",
    50 : "ESP",
    51 : "AH",
    52 : "I-NLSP",
    53 : "SWIPE",
    54 : "NARP",
    55 : "MOBILE",
    56 : "TLSP",
    57 : "SKIP",
    58 : "IPv6-ICMP",
    59 : "IPv6-NoNxt",
    60 : "IPv6-Opts",
    61 : "any",
    62 : "CFTP",
    63 : "any",
    64 : "SAT-EXPAK",
    65 : "KRYPTOLAN",
    66 : "RVD",
    67 : "IPPC",
    68 : "any",
    69 : "SAT-MON",
    70 : "VISA",
    71 : "IPCV",
    72 : "CPNX",
    73 : "CPHB",
    74 : "WSN",
    75 : "PVP",
    76 : "BR-SAT-MON",
    77 : "SUN-ND",
    78 : "WB-MON",
    79 : "WB-EXPAK",
    80 : "ISO-IP",
    81 : "VMTP",
    82 : "SECURE-VMTP",
    83 : "VINES",
    84 : "TTP",
    85 : "NSFNET-IGP",
    86 : "DGP",
    87 : "TCF",
    88 : "EIGRP",
    89 : "OSPFIGP",
    90 : "Sprite-RPC",
    91 : "LARP",
    92 : "MTP",
    93 : "AX.25",
    94 : "IPIP",
    95 : "MICP",
    96 : "SCC-SP",
    97 : "ETHERIP",
    98 : "ENCAP",
    99 : "any",
    100 : "GMTP",
    101 : "IFMP",
    102 : "PNNI",
    103 : "PIM",
    104 : "ARIS",
    105 : "SCPS",
    106 : "QNX",
    107 : "A/N",
    108 : "IPComp",
    109 : "SNP",
    110 : "Compaq-Peer",
    111 : "IPX-in-IP",
    112 : "VRRP",
    113 : "PGM",
    114 : "any",
    115 : "L2TP",
    116 : "DDX",
    117 : "IATP",
    118 : "STP",
    119 : "SRP",
    120 : "UTI",
    121 : "SMP",
    122 : "SM",
    123 : "PTP",
    124 : "ISIS",
    125 : "FIRE",
    126 : "CRTP",
    127 : "CRUDP",
    128 : "SSCOPMCE",
    129 : "IPLT",
    130 : "SPS",
    131 : "PIPE",
    132 : "SCTP",
    133 : "FC",
    134 : "RSVP-E2E-IGNORE",
    135 : "Mobility",
    136 : "UDPLite",
    137 : "MPLS-in-IP",
    138 : "manet",
    139 : "HIP",
    140 : "Shim6",
    141 : "Unassigned",
    252 : "Unassigned",
    253 : "Experimentation",
    254 : "Experimentation",
    255 : "Reserved"
    })
    
IPv4_opt = IANA_dict({
    0: ("EndofOptions", "EOOL"),
    1: ("NoOperation", "NOP"),
    2: "unassigned",
    7: ("RecordRoute", "RR"),
    8: "unassigned",
    10: ("ExperimentalMeasurement", "ZSU"),
    11: ("MTUProbe", "MTUP"),
    12: ("MTUReply", "MTUR"),
    13: "unassigned",
    15: "ENCODE",
    16: "unassigned",
    25: ("Quick-Start", "QS"),
    26: "unassigned",
    30: ("RFC3692-styleExperiment", "EXP"),
    31: "unassigned",
    68: ("TimeStamp", "TS"),
    69: "unassigned",
    82: ("Traceroute", "TR"),
    83: "unassigned",
    94: ("RFC3692-styleExperiment", "EXP"),
    95: "unassigned",
    130: ("Security", "SEC"),
    131: ("LooseSourceRoute", "LSR"),
    132: "unassigned",
    133: ("ExtendedSecurity", "E-SEC"),
    134: ("CommercialSecurity", "CIPSO"),
    135: "unassigned",
    136: ("StreamID", "SID"),
    137: ("StrictSourceRoute", "SSR"),
    138: "unassigned",
    142: ("ExpermentalAccessControl", "VISA"),
    143: "unassigned",
    144: ("IMITrafficDescriptor", "IMITD"),
    145: ("ExtendedInternetProtocol", "EIP"),
    146: "unassigned",
    147: ("AddressExtension", "ADDEXT"),
    148: ("RouterAlert", "RTRALT"),
    149: ("SelectiveDirectedBroadcast", "SDB"),
    150: "unassigned",
    151: ("DynamicPacketState", "DPS"),
    152: ("UpstreamMulticastPkt", "UMP", ),
    153: "unassigned",
    158: ("RFC3692-styleExperiment", "EXP"),
    159: "unassigned",
    205: ("ExperimentalFlowControl", "FINN"),
    206: "unassigned",
    222: ("RFC3692-styleExperiment", "EXP"),
    223: "unassigned",
    255: "unassigned",
    })


class Eth(Layer):
    constructorList = [
        Str(CallName='dst', ReprName='Destination MAC', Pt='', \
            Len=6, Repr='hex'),
        Str(CallName='src', ReprName='Source MAC', Pt='', \
            Len=6, Repr='hex'),
        Int(CallName='typ', ReprName='Ethertype', Pt=0x0800, \
            Type='uint16', Repr='hex'),
        ]
    
    def __init__(self, src='\0\0\0\0\0\0', dst='\xFF\xFF\xFF\xFF\xFF\xFF'):
        Layer.__init__(self, CallName='eth', ReprName='Ethernet header')
        self.src.Pt = src
        self.dst.Pt = dst
        self.typ.Pt = self.get_payload
        self.typ.PtFunc = lambda pay: binder[type(pay()[0])]


class Vlan(Layer):
    constructorList = [
        Bit(CallName='pcp', ReprName='Priority Code Point', Pt=0, \
            BitLen=3, Repr='hum'),
        Bit(CallName='cfi', ReprName='Canonical Format Indicator', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit(CallName='vid', ReprName='VLAN Identifier', Pt=0, \
            BitLen=12, Repr='hum'),
        Int(CallName='typ', ReprName='Ethertype', Pt=0x0800, \
            Type='uint16', Repr='hex'),
        ]
    
    def __init__(self, vid=0):
        Layer.__init__(self, CallName='vlan', ReprName='IEEE 802.1Q')
        self.vid.Pt = vid
        self.typ.Pt = self.get_payload
        self.typ.PtFunc = lambda pay: binder[type(pay()[0])]


class ARP(Layer):
    constructorList = [
        Int(CallName='hw', ReprName='Hardware type', Pt=0x0001, \
            Type='uint16', Repr='hex'),
        Int(CallName='prot', ReprName='Protocol type', Pt=0x0800, \
            Type='uint16', Repr='hex'),
        Int(CallName='hw_size', ReprName='Hardware size', Pt=6, \
            Type='uint8', Repr='hum'),
        Int(CallName='prot_size', ReprName='Protocol size', Pt=4, \
            Type='uint8', Repr='hum'),
        Int(CallName='op', ReprName='Opcode', Pt=0x0001, \
            Type='uint16', Repr='hex'),
        Str(CallName='src_mac', ReprName='Source MAC', Pt='\0\0\0\0\0\0', \
            Repr='hex'),
        Str(CallName='src', ReprName='Source address', Pt='\x7f\0\0\x01', \
            Repr='hex'),
        Str(CallName='dst_mac', ReprName='Destination MAC', Pt='\0\0\0\0\0\0', \
            Repr='hex'),
        Str(CallName='dst', ReprName='Destination address', Pt='\x7f\0\0\x01', \
            Repr='hex'),
        ]
    
    def __init__(self, src_mac='\0\0\0\0\0\0', src='\x7f\0\0\x01', dst='\x7f\0\0\x01'):
        Layer.__init__(self, CallName='arp', ReprName='Address Resolution Protocol')
        # MAC addresses definition
        self.src_mac.Pt = src_mac
        self.src_mac.Len = self.hw_size
        self.src_mac.LenFunc = lambda x: int(x)
        self.dst_mac.Len = self.hw_size
        self.dst_mac.LenFunc = lambda x: int(x)
        # IP addresses definition
        self.src.Pt = src
        self.src.Len = self.prot_size
        self.src.LenFunc = lambda x: int(x)
        self.dst.Pt = dst
        self.dst.Len = self.prot_size
        self.dst.LenFunc = lambda x: int(x)
        # MAC and IP addresses tricks (enable fuzzing)
        self.hw_size.Ptfunc = lambda x: (len(self.src_mac)+len(self.dst_mac))/2 
        self.prot_size.PtFunc = lambda x: (len(self.src)+len(self.dst))/2


class IPv4(Layer):
    constructorList = [
        Bit(CallName='ver', ReprName='Version', Pt=4, BitLen=4, Repr='hum'),
        Bit(CallName='ihl', ReprName='Header length (32 bits words)', \
            BitLen=4, Repr='hum'),
        Bit(CallName='pre', ReprName='Precedence', Pt=0, BitLen=3, \
            Repr='hum', Dict={0:'Routine', 1:'Priority', 2:'Immediate', \
                              3:'Flash', 4:'Flash Override', 5:'CRITIC/ECP', \
                              6:'Internetwork Control', 7:'Network Control'}),
        Bit(CallName='delay', Pt=0, BitLen=1, Repr='hum', \
            Dict={0:'Normal', 1:'Low'}),
        Bit(CallName='thr', ReprName='Throughput', Pt=0, BitLen=1, \
            Repr='hum', Dict={0:'Normal', 1:'High'}),
        Bit(CallName='rel', ReprName='Reliability', Pt=0, BitLen=1, \
            Repr='hum', Dict={0:'Normal', 1:'High'}),
        Bit(CallName='res1', ReprName='reserved', Pt=0, BitLen=2),
        Int(CallName='len', ReprName='Datagram length', Type='uint16'),
        Int(CallName='id', ReprName='Identification', Pt=0, Type='uint16'),
        Bit(CallName='res2', ReprName='reserved', Pt=0, BitLen=1),
        Bit(CallName='DF', ReprName='Don\'t fragment', Pt=0, BitLen=1, \
            Repr='hum', Dict={0:'May Fragment', 1:'Don\'t Fragment'}),
        Bit(CallName='MF', ReprName='More fragments', Pt=0, BitLen=1, \
            Repr='hum', Dict={0:'Last Fragment', 1:'More Fragments'}),
        Bit(CallName='frag', ReprName='Fragment offset', Pt=0, BitLen=13, \
            Repr='hum'),
        Int(CallName='ttl', ReprName='Time To Live', Pt=32, Type='uint8'),
        Int(CallName='prot', ReprName='Protocol', Pt=17, Type='uint8', \
            Repr='hum', Dict=IP_prot),
        Int(CallName='cs', ReprName='Header checksum', Type='uint16', \
            Repr='hex'),
        Str(CallName='src', ReprName='Source address', Pt='\x7f\x00\x00\x01', \
            Len=4, Repr='ipv4'),
        Str(CallName='dst', ReprName='Destination address', Pt='\x7f\x00\x00\x01', \
            Len=4, Repr='ipv4'),
        Str(CallName='opt', ReprName='Options', Pt=''), #, Trans=True),
        ]
    
    def __init__(self, src='127.0.0.1', dst='127.0.0.1'):
        Layer.__init__(self, CallName='ipv4', ReprName='IPv4 header')
        self.src.Pt = inet_aton(src)
        self.dst.Pt = inet_aton(dst)
        
        # ihl is the length of the header in 32-bit words, including options:
        self.ihl.Pt = self
        self.ihl.PtFunc = lambda sel: 5 + len(sel.opt)//4
        # len is the length of the complete datagram including header:
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay()) + len(self.opt) + 20
        # protocol type
        self.prot.Pt = self.get_payload
        self.prot.PtFunc = lambda pay: binderIP[type(pay()[0])]
        # IPv4 checksum
        self.cs.Pt = 0
        self.cs.PtFunc = lambda x: self.cksum()
        # options field
        self.opt.PtFunc = self.__pad_opt
        self.opt.Len = self.ihl
        self.opt.LenFunc = lambda ihl: (int(ihl)-5)*4
    
    def __pad_opt(self, _unused):
        if isinstance(self.opt.Pt, (str, Str, Layer, RawLayer, Block)) :
            l = len(self.opt.Pt)
        if l > 0 :
            return str(self.opt.Pt) + (4-l%4)%4 * '\0'
        return ''
    
    def cksum(self):
        # must take IPv4 options into account...
        mem = self.cs.Val
        self.cs.Val = 0
        s = str(self)
        self.cs.Val = mem
        # big thanks to scapy /p.biondy:
        return checksum(s)
    

class IPv4_option(Layer):
    constructorList = [
        Int(CallName='ccn', ReprName='copy class number', Pt=0, Type='uint8', \
            Dict=IPv4_opt),
        Int(CallName='len', ReprName='length', Type='uint8', Trans=True),
        Str(CallName='val', ReprName='value', Trans=True),
        ]
    
    def __init__(self, Type=1):
        Layer.__init__(self, CallName='opt', ReprName='IPv4 option')
        # single byte options:
        # fixed length options:
        # variable length options
        self.ccn.Pt = Type
        self.val.Pt = ''
        self.val.Len = self.len
        self.val.LenFunc = lambda le: int(le)-2
        self.len.Pt = self.val
        self.len.PtFunc = lambda val: len(val)+2


class ICMP(Layer):
    constructorList = [
        Int(CallName='typ', ReprName='Type', Type='uint8'),
        Int(CallName='cod', ReprName='Code', Type='uint8'),
        Int(CallName='cs', ReprName='Header Checksum', Type='uint16'),
        Str(CallName='data', Repr='hum'),
        ]
    
    def __init__(self, type=8, code=0, data='\0\0mitsh'):
        Layer.__init__(self, CallName='icmp', ReprName='ICMP')
        self.typ.Pt = type
        self.cod.Pt = code
        self.data.Pt = data
        self.cs.Pt = 0
        self.cs.PtFunc = lambda x: self.cksum()
    
    def cksum(self):
        # must take IP header into account: in pseud...        
        mem = self.cs.Val
        self.cs.Val = 0
        icmpstr = str(self)
        self.cs.Val = mem
        return checksum(icmpstr)
    

class UDP(Layer):
    constructorList = [
        Int(CallName='src', ReprName='Source Port', Type='uint16'),
        Int(CallName='dst', ReprName='Destination Port', Type='uint16'),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='cs', ReprName='Checksum', Type='uint16', Repr='hex'),
        ]
    
    def __init__(self, src=68, dst=69, with_cs=False):
        Layer.__init__(self, CallName='udp', ReprName='UDP header')
        self.with_cs = with_cs
        self.src.Pt = src
        self.dst.Pt = dst
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8
        self.cs.Pt = 0
        self.cs.PtFunc = lambda x: self.cksum()
    
    def cksum(self):
        # do not need to checksum:
        if not self.with_cs:
            return 0
        # must take IP header into account: in pseud...        
        mem = self.cs.Val
        self.cs.Val = 0
        udpstr = str(self)
        hdrstr = str(self.get_header())
        paystr = str(self.get_payload())
        self.cs.Val = mem
        ln = len(udpstr) + len(paystr)
        if len(hdrstr)>=20 and ord(hdrstr[0])>>4 == 4 :
            pseudstr = ''.join((hdrstr[12:20], '\0', hdrstr[9:10], pack('!H', ln)))
        elif len(hdrstr)>=40 and ord(hdrstr[0])>>4 == 6 :
            # TODO: do it correctly!
            # warning, not considering IPv6 options when selecting proto field
            # double warning, not sure its the right way to do...
            pseudstr = ''.join((hdrstr[8:40], '\0' , hdrstr[6:7], pack('!H', ln)))
        else:
            pseudstr = ''.join(('\0\0', pack('!H', ln)))
        return checksum(''.join((pseudstr, udpstr, paystr)))
    

class TCP(Layer):
    constructorList = [
        Int(CallName='src', ReprName='Source Port', Type='uint16'),
        Int(CallName='dst', ReprName='Destination Port', Type='uint16'),
        Int(CallName='seq', ReprName='Sequence Number', Pt=0, Type='uint32'),
        Int(CallName='ack', ReprName='Acknowledgement Number', Pt=0, Type='uint32'),
        Bit(CallName='off', ReprName='Data Offset', BitLen=4, Repr='hum'),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=3, Repr='bin'),
        Bit(CallName='NS', Pt=0, BitLen=1),
        Bit(CallName='CWR', Pt=0, BitLen=1),
        Bit(CallName='ECE', Pt=0, BitLen=1),
        Bit(CallName='URG', Pt=0, BitLen=1),
        Bit(CallName='ACK', Pt=0, BitLen=1),
        Bit(CallName='PSH', Pt=0, BitLen=1),
        Bit(CallName='RST', Pt=0, BitLen=1),
        Bit(CallName='SYN', Pt=0, BitLen=1),
        Bit(CallName='FIN', Pt=0, BitLen=1),
        Int(CallName='win', ReprName='Window', Pt=8192, Type='uint16'),
        Int(CallName='cs', ReprName='Checksum', Type='uint16', Repr='hex'),
        Int(CallName='urg', ReprName='Urgent Pointer', Pt=0, Type='uint16'),
        Str(CallName='opt', ReprName='Options', Pt=''),
        ]
    
    def __init__(self, src=21, dst=21, flags=['SYN']):
        Layer.__init__(self, CallName='tcp', ReprName='TCP header')
        self.src.Pt = src
        self.dst.Pt = dst
        self.off.Pt = self.opt
        self.off.PtFunc = lambda opt:5+len(opt)//4
        for f in flags:
            if f in ('NS', 'CWR', 'ECE', 'URG', 'ACK', \
                     'PSH', 'RST', 'SYN', 'FIN'):
                getattr(self, f) > 1
        self.cs.Pt = 0
        self.cs.PtFunc = lambda x: self.cksum()
        # options field
        self.opt.PtFunc = self.__pad_opt
        self.opt.Len = self.off
        self.opt.LenFunc = lambda off: (int(off)-5)*4
    
    def __pad_opt(self, _unused):
        if isinstance(self.opt.Pt, (str, Str, Layer, RawLayer, Block)) :
            l = len(self.opt.Pt)
        if l > 0 :
            return self.opt.Pt + (4-l%4)%4 * '\0'
        return ''
    
    def cksum(self):
        # must take IP header into account: in pseud...        
        mem = self.cs.Val
        self.cs.Val = 0
        tcpstr = str(self)
        hdrstr = str(self.get_header())
        paystr = str(self.get_payload())
        self.cs.Val = mem
        ln = len(tcpstr) + len(paystr)
        if len(hdrstr)>=20 and ord(hdrstr[0])>>4 == 4 :
            pseudstr = ''.join((hdrstr[12:20], '\0', hdrstr[9:10], pack('!H', ln)))
        elif len(hdrstr)>=40 and ord(hdrstr[0])>>4 == 6 :
            # TODO: do it correctly!
            # warning, not considering IPv6 options when selecting proto field
            # double warning, not sure its the right way to do...
            # and anyway, IPv6 is has-been
            pseudstr = ''.join((hdrstr[8:40], '\0' , hdrstr[6:7], pack('!H', ln)))
        else:
            pseudstr = ''.join(('\0\0', pack('!H', ln)))
        return checksum(''.join((pseudstr, tcpstr, paystr)))
    

class IPv6(Layer):
    constructorList = [
        Bit(CallName='ver', ReprName='Version', Pt=6, BitLen=4, Repr='hum'),
        Bit(CallName='cla', ReprName='Traffic class', Pt=0, BitLen=8, \

            Repr='hum'),
        Bit(CallName='flo', ReprName='Flow label', Pt=0, BitLen=20, \
            Repr='hex'),
        Int(CallName='plen', ReprName='Payload length', Type='uint16'),
        Int(CallName='next', ReprName='Next header', Pt=0, Type='uint8'),
        Int(CallName='hlim', ReprName='Hop limit', Pt=24, Type='uint8'),
        Str(CallName='src', ReprName='Source address', Pt=15*'\0'+'\x01', \
            Len=16, Repr='hex'),
        Str(CallName='dst', ReprName='Destination address', Pt=15*'\0'+'\x01', \
            Len=16, Repr='hex'),
        ]
    
    def __init__(self, src=15*'\0'+'\x01', dst=15*'\0'+'\x01'):
        Layer.__init__(self, CallName='ipv6', ReprName='IPv6 header')
        self.src.Pt = src
        self.dst.Pt = dst
        # manages payload length
        self.plen.Pt = self.get_payload
        self.plen.PtFunc = lambda pay: pay()
    


binder = {
    RawLayer : 0x0000,
    Vlan : 0x8100,
    IPv4 : 0x0800,
    ARP  : 0x0806,
    IPv6 : 0x86DD,
    }
    
binderIP = {
    RawLayer : 255,
    ICMP : 1,
    TCP : 6,
    UDP : 17,
    #SCTP : 132,
    }

