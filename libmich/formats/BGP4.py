# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.1 
# *
# * Copyright © 2011. Benoit Michau.
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
# * File Name : formats/BGP4.py
# * Created : 2011-10-24
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python
#
# Border Gateway Protocol format:
# http://tools.ietf.org/html/rfc4271

from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show, debug
from binascii import hexlify, unhexlify

# local BGP identifier
# corresponds to IPv4 address in use
# here is: 127.0.0.1 (0x7f000001)
BGP_id=2130706433

MsgType={
    0:'Reserved',
    1:'OPEN',
    2:'UPDATE',
    3:'NOTIFICATION',
    4:'KEEPALIVE',
    5:'ROUTE-REFRESH',
    }

Err_dict = {
    0:'Reserved',
    1:'Message Header Error',
    2:'OPEN Message Error',
    3:'UPDATE Message Error',
    4:'Hold Timer Expired',
    5:'Finite State Machine Error',
    6:'Cease',
    }

Hdrerr_dict = {
    0:'Unspecific',
    1:'Connection Not Synchronized',
    2:'Bad Message Length',
    3:'Bad Message Type',
    }

Openerr_dict = {
    0:'Unspecific',
    1:'Unsupported Version Number',
    2:'Bad Peer AS',
    3:'Bad BGP Identifier',
    4:'Unsupported Optional Parameter',
    5:'[Deprecated]',
    6:'Unacceptable Hold Time',
    7:'Unsupported Capability',
    }

Updateerr_dict = {
    0:'Unspecific',
    1:'Malformed Attribute List',
    2:'Unrecognized Well-known Attribute',
    3:'Missing Well-known Attribute',
    4:'Attribute Flags Error',
    5:'Attribute Length Error',
    6:'Invalid ORIGIN Attribute',
    7:'[Deprecated]',
    8:'Invalid NEXT_HOP Attribute',
    9:'Optional Attribute Error',
    10:'Invalid Network Field',
    11:'Malformed AS_PATH',
    }

Ceaseerr_dict = {
    0:'Unspecific',
    1:'Malformed Attribute List',
    2:'Unrecognized Well-known Attribute',
    3:'Missing Well-known Attribute',
    4:'Attribute Flags Error',
    5:'Attribute Length Error',
    6:'Invalid ORIGIN Attribute',
    7:'[Deprecated]',
    8:'Invalid NEXT_HOP Attribute',
    9:'Optional Attribute Error',
    10:'Invalid Network Field',
    11:'Malformed AS_PATH',
    }

Generr_dict = {
    0:'Unspecific',
    }

Opt_dict = {
    0:'Reserved',
    1:'Authentication',
    2:'Capabilities',
    }

PA_dict = {
    0:'Reserved',
    1:'ORIGIN',
    2:'AS_PATH',
    3:'NEXT_HOP',
    4:'MULTI_EXIT_DISC',
    5:'LOCAL_PREF',
    6:'ATOMIC_AGGREGATE',
    7:'AGGREGATOR',
    8:'COMMUNITY',
    9:'ORIGINATOR_ID',
    10:'CLUSTER_LIST',
    11:'DPA',
    12:'ADVERTISER (Historic)',
    13:'RCID_PATH / CLUSTER_ID (Historic)',
    14:'MP_REACH_NLRI',
    15:'MP_UNREACH_NLRI',
    16:'EXTENDED COMMUNITIES',
    17:'AS4_PATH',
    18:'AS4_AGGREGATOR',
    19:'SAFI Specific Attribute (SSA) (deprecated)',
    20:'Connector Attribute (deprecated)',
    21:'AS_PATHLIMIT (deprecated)',
    22:'PMSI_TUNNEL',
    23:'Tunnel Encapsulation Attribute',
    24:'Traffic Engineering',
    25:'IPv6 Address Specific Extended Community',
    26:'AIGP (TEMPORARY)',
    128:'ATTR_SET',
    255:'Reserved for development',
    }

#
# Global BGP4 block definition and parsing facility
class BGP4(Block):
    
    def __init__(self):
        Block.__init__(self, Name='BGP4')
        self.append(HEADER())
    
    def parse(self, s=''):
        # parse initial header
        self.map(s[:19])
        s = s[19:]
        # control BGP marker
        if self[-1].marker() != 16*'\xFF':
            debug(self.dbg, 1, 'bad BGP marker in header')
        # then
        # iteratively parse successive payloads and headers
        while len(s) > 0:
            # append BGP payload
            if isinstance(self[-1], HEADER):
                pay_type = self[-1].type()
                pay_len = self[-1].len()-19
                if pay_type in MsgCall.keys():
                    # BGP payload is recognized: youpi!!!!
                    self << MsgCall[pay_type]()
                    #print('%s' % self[-1].show())
                    self[-1].map(s)
                    # control payload length
                    if len(self[-1]) != pay_len:
                        debug(self.dbg, 1, 'inconsistent length between BGP '\
                        'header and payload')
                else:
                    # unknown payload
                    self << RawLayer()
                    self[-1].map(s[:pay_len])
            # append more BGP headers
            else:
                self.append( HEADER() )
                self[-1].map(s)
                # control BGP marker
                if self[-1].marker() != 16*'\xFF':
                    debug(self.dbg, 1, 'bad BGP marker in header')
            # truncate string buffer, and iterate
            s = s[len(self[-1]):]

#
# BGPv4 HEADER
class HEADER(Layer):
    constructorList = [
        Str('marker', Pt=16*'\xFF', Len=16),
        Int('len', Type='uint16'),
        Int('type', Type='uint8', Dict=MsgType),
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.len > self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+19
        self.type > self.get_payload
        self.type.PtFunc = self.__get_msg_type
    
    def __get_msg_type(self, pay):
        cmd = pay()[0]
        if isinstance(cmd, MsgType):
            return MsgType.index(type(cmd))
        else:
            return 4
#
# OPEN message
class opt(Layer):
    constructorList = [
        Int('T', Pt=2, Type='uint8', Dict=Opt_dict),
        Int('L', Type='uint8'),
        Str('V', Pt='')
        ]
    
    def __init__(self, tag=2, value=''):
        Layer.__init__(self)
        self.T > tag
        self.L > self.V
        self.L.PtFunc = lambda v: len(v)
        self.V > value
        self.V.Len = self.L
        self.V.LenFunc = lambda l: l()

class OPEN(Layer):
    constructorList = [
        Int('Version', Pt=4, Type='uint8'),
        Int('AutSys', ReprName='Sender Autonomous System', Pt=0, Type='uint16'),
        Int('HoldT', ReprName='Hold Timer (sec)', Pt=3, Type='uint16'),
        Int('BGPId', ReprName='BGP Identifier', Pt=BGP_id, Type='uint32'),
        Int('OptLen', ReprName='Optional Parameters Length', Pt=0, Type='uint8'),
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.append(Layer('Options'))
        self.OptLen > self.Options
        self.OptLen.PtFunc = lambda opt: len(opt)
    
    # overwrite .map() to fill .Options with opt()
    def map(self, string=''):
        self.map(string)
        string = string[len(self):]
        while len(string) > 0:
            o = opt()
            o.map(string)
            o.inc_hierarchy(self.hierarchy)
            self.Options.append(o)
            string = string[len(o):]

#
# UPDATE message
# IPv4 address prefix, for Withdrawn Routes:
class pref(Layer):
    constructorList = [
        Int('L', Type='uint8'),
        Str('Prefix', Pt='', Repr='hex')
        ]
    # TODO: Len in bit length,
    # hence some padding may be concatenated to Prefix
    # and Prefix length must be handled more accurately...
    def __init__(self, prefix=''):
        Layer.__init__(self)
        self.L > self.Prefix
        self.L.PtFunc = lambda pref: len(pref)*8
        self.Prefix > prefix
        self.Prefix.Len = self.L
        self.Prefix.LenFunc = lambda l: l()//8

# for Path Attributes:
class path(Layer):
    constructorList = [
        Bit('Optional', BitLen=1),
        Bit('Transitive', Pt=1, BitLen=1),
        Bit('Partial', Pt=0, BitLen=1),
        Bit('Extended', Pt=0, BitLen=1),
        Bit('res', Pt=0, BitLen=4),
        Int('Code', Pt=1, Type='uint8', Dict=PA_dict),
        Int('L', Type='uint8'),
        Str('V', Pt='')]
        
    def __init__(self, code=1, value=''):
        Layer.__init__(self)
        self.Extended > self.V
        self.Extended.PtFunc = self.__set_ext
        self.Code > code
        self.L > self.V
        self.L.PtFunc = lambda v: len(v)
        self.V > value
        self.V.Len = self.L
        self.V.LenFunc = lambda l: l()
    
    def __set_ext(self, V):
        if len(V) > 0xFF:
            self.L.Type='uint16'
            return 1
        else:
            self.L.Type='uint8'
            return 0
    
    # overwrite Layer.map() to handle extended length flag
    def map(self, s='\0'):
        # extended length set
        if ord(s[0]) & 0x10 == 0x10:
            self.L.Type='uint16'
        else:
            self.L.Type='uint8'
        Layer.map(self, s)

# UPDATE full layer
class UPDATE(Layer):
    constructorList = [
        Int('WRLen', Pt=0, Type='uint16'),
        Int('TPALen', Pt=0, Type='uint16'),
        Str('NLRI', ReprName='Network Layer Reachability Info', Pt='')
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.insert(1, Layer('WR', ReprName='Withdrawn Routes'))
        self.insert(3, Layer('TPA', ReprName='Total Path Attribute'))
        # handle "Withdrawn Routes"
        self.WRLen > self.WR
        self.WRLen.PtFunc = lambda wr: len(wr)
        # handle "Path Attributes"
        self.TPALen > self.TPA
        self.TPALen.PtFunc = lambda tpa: len(tpa)
        # finally handle net reachibility info
        self.NLRI.Len = (self.get_header, self.WRLen, self.TPALen)
        self.NLRI.LenFunc = lambda args: args[0]().len() - \
                                        (23 + args[1]() + args[2]())
    
    def map(self, string=''):
        # handle all the withdrawn routes
        self.WRLen.map(string)
        wr_len = self.WRLen()
        wr_s = string[2:2+wr_len]
        #print('[+] parsing wr_s: %s' % hexlify(wr_s))
        # fill iteratively withdrawn routes
        while len(wr_s) > 0:
            prefix = pref()
            prefix.map(wr_s)
            self.WR.append(prefix)
            wr_s = wr_s[len(prefix):]
        string = string[2+wr_len:]
        #
        # handle all the path attributes
        self.TPALen.map(string)
        tpa_len = self.TPALen()
        tpa_s = string[2:2+tpa_len]
        #print('[+] parsing tpa_s: %s' % hexlify(tpa_s))
        # fill iteratively withdrawn routes
        while len(tpa_s) > 0:
            pathat = path()
            pathat.map(tpa_s)
            self.TPA.append(pathat)
            tpa_s = tpa_s[len(pathat):]
        string = string[2+tpa_len:]
        #
        # lastly, handle NLRI
        self.NLRI.map(string)
        

#
# NOTIFICATION message
class NOTIFICATION(Layer):
    constructorList = [
        Int('Code', Pt=1, Type='uint8', Dict=Err_dict),
        Int('Subcode', Pt=0, Type='uint8'),
        Str('Data', Pt='')
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.Subcode.Dict = self.Code
        self.Subcode.DictFunc = self.__get_suberr
        self.Data.Len = self.get_header
        self.Data.LenFunc = lambda hdr: hdr.len()-21
        
    def __get_suberr(self, C):
        if C() == 1: return Hdrerr_dict
        elif C() == 2: return Openerr_dict
        elif C() == 3: return Updateerr_dict
        elif C() == 6: return Ceaseerr_dict
        else: return Generr_dict

#
# KEEPALIVE message
# should never contain anything
class KEEPALIVE(RawLayer):
    constructorList = [
        Str('Null', Pt='', Len=0)
        ]
    
    def __init__(self):
        Layer.__init__(self)

#
# dictionary to call right Layers
MsgCall = {
    1:OPEN,
    2:UPDATE,
    3:NOTIFICATION,
    4:KEEPALIVE,
    #5:ROUTE_REFRESH
    }
# tuple of payload' type to get right type value in header:
MsgType = (HEADER, OPEN, UPDATE, NOTIFICATION, KEEPALIVE) #, ROUTE_REFRESH)


# BGP4 test buffer (from wireshark WIKI)
testbuf = \
unhexlify('ffffffffffffffffffffffffffffffff001304fffffffffffffffffffffffffffff'\
'fff006202000000484001010240020a010201f401f40201febb400304c0a8000f400504000000'\
'64400600c00706febac0a8000ac0080cfebf000103160004015400fa800904c0a8000f800a04c'\
'0a800fa10ac10ffffffffffffffffffffffffffffffff006302000000484001010040020a0102'\
'01f401f40201febb400304c0a8000f40050400000064400600c00706febac0a8000ac0080cfeb'\
'f000103160004015400fa800904c0a8000f800a04c0a800fa16c0a804')

