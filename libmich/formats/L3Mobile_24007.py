# −*− coding: UTF−8 −*−
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
# * File Name : formats/L3Mobile_24007.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Element, Str, Int, Bit, \
     Layer, RawLayer, Block, show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.formats import L3Mobile_IE
from binascii import hexlify

# TS 24.007 standard message format
# section 11.2.1.1
class Type1_V(Layer):
    # actually Type1_TV consists only of 4 bits (MSB or LSB)
    constructorList = [
        Bit(CallName='V', BitLen=8),
        ]
    def __init__(self, CallName='', ReprName='', V=0, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.V.Pt = V

class Type1_TV(Layer):
    constructorList = [
        Bit(CallName='T', BitLen=4, Repr='hum'),
        Bit(CallName='V', BitLen=4), #, Repr='hum'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V=0, \
                 Trans=False, Dict=None):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.V.Pt = V
        if Dict:
            self.V.Dict = Dict
            self.V.Repr = 'hum'

class Type2(Layer):
    constructorList = [
        Int(CallName='T', Type='uint8'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T

class Type3_V(Layer):
    constructorList = [
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0', len=1, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.V.Pt = V
        self.V.Len = len

class Type3_TV(Layer):
    constructorList = [
        Int(CallName='T', Type='uint8'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V='\0', len=1, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.V.Pt = V
        self.V.Len = len

class Type4_LV(Layer):
    constructorList = [
        Int(CallName='L', Type='uint8'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0', Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

class Type4_TLV(Layer):
    constructorList = [
        Int(CallName='T', Type='uint8'),
        Int(CallName='L', Type='uint8'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V='\0', Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

class Type6_LVE(Layer):
    constructorList = [
        Int(CallName='L', Type='uint16'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0', Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

class Type6_TLVE(Layer):
    constructorList = [
        Int(CallName='T', Pt=0, Type='uint8'),
        Int(CallName='L', Type='uint16'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V='\0', Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

# Layer3 messages
# define a specific way to map string on L3Mobile Layer:
class Layer3(Layer):

    # debugging facility level
    dbg = 1
    
    # message format dependancy: Net / ME
    # needed for some messages in L3Mobile_CC
    initiator = 'Net'
    #initiator = 'ME'
    
    def __init__(self, CallName='', ReprName='', Trans=False):
        Layer.__init__(self, CallName='', ReprName='', Trans=Trans)
    
    # handles optional tag (TLV) transparency at initialization
    def _post_init(self, with_options=True):
        for ie in self:
            if hasattr(ie, 'T') and ie.Trans is False:
                ie.Trans = not with_options
    
    # need a specific parser to manage optional or conditional IE
    # as explained in TS 24.007, section 11
    # and pointing to specific L3Mobile_IE when exists
    def map(self, string=''):
        s = string
        BitStack, BitStack_len = [], 0
        for e in self:
            if isinstance(e, Bit):
                if e.TransFunc is not None:
                    assert( type(e.TransFunc(e.Trans)) is bool )
                    if not e.TransFunc(e.Trans):
                        BitStack += [e]
                        BitStack_len += e.bit_len()
                elif not e.Trans:
                    assert( type(e.Trans) is bool )
                    BitStack += [e]
                    BitStack_len += e.bit_len()
                if not BitStack_len % 8:
                    s_stack = s[:BitStack_len//8]
                    s_bin = ''
                    while s_stack:
                        s_bin_temp = bin( ord(s_stack[0]) )[2:]
                        s_bin += ( 8 - len(s_bin_temp) )*'0' + s_bin_temp
                        s_stack = s_stack[1:]
                    for B in BitStack:
                        B.map_bit( int(s_bin[:B.bit_len()], 2) )
                        s_bin = s_bin[B.bit_len():]
                    s = s[BitStack_len//8:]
                    BitStack, BitStack_len = [], 0
            else:
                if BitStack_len > 0: 
                    debug(self.dbg, 2, '(Layer) some of the Bit elements ' \
                          'have not been mapped in the "Layer"')
                # need to manage smartly Type1_TV, Type2, 
                # Type3_TV, Type4_TLV, Type6_TLVE
                # as it corresponds to optional / conditionnal fields
                # in Layer3 messages...
                # Tagged IE always come after mandatory IE
                # so we handle it in another method and break
                if isinstance(e, (Type1_TV, Type2, Type3_TV, \
                                  Type4_TLV, Type6_TLVE)):
                    self.__map_opts(s)
                    break
                if isinstance(e, Layer) and not e.Trans \
                or isinstance(e, Element):
                    e.map(s)
                    s = s[e.map_len():]
        # Go again through all L3 fields, 
        # and check if L3Mobile_IE is available for even more interpretation
        for e in self:
            if hasattr(L3Mobile_IE, e.CallName):
                self.interpret_IE(e)
    
    def interpret_IE(self, field):
        # work only when field is named like an existing IE
        f_name = field.CallName
        if not hasattr(L3Mobile_IE, f_name):
            return
        # check if direct field, or (T)LV-like field
        if hasattr(field, 'V'):
            buf = str(field.V)
            ie = getattr(L3Mobile_IE, f_name)()
            ie.map(buf)
            # take care in case we got corrupted data
            # not corresponding to the structure of the IE...
            if len(ie) == len(buf):
                field.V < None
                field.V > ie
        else:
            buf = str(field)
            ie = getattr(L3Mobile_IE, f_name)()
            ie.map(buf)
            # take care in case we got corrupted data...
            if len(ie) == len(buf):
                field < None
                field > ie
    
    def __map_opts(self, s=''):
        # Get list of (tag:field) for optional fields,
        # and starting position for those optional fields in the layer
        opt_start, tags = self.__get_start_opt()
        debug(self.dbg, 3, '(Layer3) opt_start: %s, ' \
              'tags: %s' % (opt_start, [t[0] for t in tags]))
        # remove all optional fields from the message
        # they will be reinserted from the `tags` list during parsing
        for f in self[opt_start:]:
            self.remove(f)
        # consume the s buffer:
        while len(s) > 0:
            # check each iteration for 4 bits and 8 bits tags
            t4, t8 = ord(s[0])>>4, ord(s[0])
            debug(self.dbg, 3, '(Layer3) t4, t8: %s, %s\ntaglist: %s' \
                  % (t4, t8, [t[0] for t in tags]))
            # handle 4 bits tag in priority
            # however, 4 bits and 8 bits tags should never clash...
            # ...
            # actually, this is not the case for tag 4 (BearerCap) 
            # and 64 (SuppCodecs)
            
            if t4 in [t[0] for t in tags]:
                s, tags = self.__map_opt(t4, tags, s)
            elif t8 in [t[0] for t in tags]:
                s, tags = self.__map_opt(t8, tags, s)
            else:
                debug(self.dbg, 2, '(Layer3) unknown optional IE')
                # could try to map it as a TLV, or TLVextended, or TV, or T ...
                # check the TS 24.007, section 11.2.4, for being amazed...
                s = self.__map_unknown_opt(s)
        if len(s) > 0:
            debug(self.dbg, 2, '(Layer3) string not completely mapped ' \
                  'remains: %s' % s)
        if len(tags) > 0:
            debug(self.dbg, 3, '(Layer3) not all optional IE used ' \
                  'tags: %s' % [t[0] for t in tags])
    
    def __get_start_opt(self):
        tags, rk, opt_start = [], 0, 0
        for f in self:
            if hasattr(f, 'T'):
                if not opt_start:
                    opt_start = rk
                tags.append((f.T(), f))
                # make all fields not transparent
                # will be revert back by __map_opts epilog
                f.Trans = False
            else:
                if opt_start:
                    debug(self.dbg, 2, '(Layer3) optional fields ' \
                          'seems not stacked correctly')
            rk += 1
        return opt_start, tags
        
    def __map_opt(self, tag, taglist, s):
        # retrieve option(s) for the given tag
        opt = [t[1] for t in taglist if t[0]==tag]
        # if repeated options, get the 1st one
        # anyway, ... get the 1st one
        debug(self.dbg, 3, '(Layer3) string: %s\ntag: %s, opt: %s' \
              % (s, tag, opt))
        opt = opt[0]
        opt.map(s)
        # append it on the L3 message
        self.append(opt)
        s = s[opt.map_len():]
        # and remove it from the `tags` list
        # python's magic: list.remove() removes only the 1st iteration
        taglist.remove((tag, opt))
        return s, taglist
    
    def __map_unknown_opt(self, s):
        # TODO: to handle correctly EPS EMM and ESM
        if ord(s[0]) >> 7:
            opt = Type2()
        else:
            opt = Type4_TLV()
        opt.map(s)
        self.append(opt)
        s = s[opt.map_len():]
        return s
        
#
# TS 24.007, section 11.2.3.1.1
# Protocol Discriminator dict
PD_dict = IANA_dict({
    0:"group call control",
    1:("broadcast call control", "BC"),
    2:"EPS session management messages",
    3:("call control; call related SS messages", "CC"),
    4:"GPRS Transparent Transport Protocol (GTTP)",
    5:("mobility management messages", "MM"),
    6:("radio resources management messages", "RR"),
    7:"EPS mobility management messages",
    8:"GPRS mobility management messages",
    9:("short messages service", "SMS"),
    10:"GPRS session management messages",
    11:"non call related SS messages",
    12:"Location services", # specified in 3GPP TS 44.071 [8a]
    13:"reserved for extension of the PD to one octet length",
    14:"testing",
    })
#



#######################################
# and still to be handled ... somewhere
# ... actually should be elsewhere
#######################################

# Packet Service Mobility Management procedures dict
#PS_MM = {
#    1:"GPRS - Attach request",
#    2:"GPRS - Attach accept",
#    3:"GPRS - Attach complete",
#    4:"GPRS - Attach reject",
#    5:"GPRS - Detach request",
#    6:"GPRS - Detach accept",
#    8:"GPRS - Routing area update request",
#    9:"GPRS - Routing area update accept",
#    10:"GPRS - Routing area update complete",
#    11:"GPRS - Routing area update reject",
#    12:"GPRS - Service Request",
#    13:"GPRS - Service Accept",
#    14:"GPRS - Service Reject",
#    16:"GPRS - P-TMSI reallocation command",
#    17:"GPRS - P-TMSI reallocation complete",
#    18:"GPRS - Authentication and ciphering request",
#    19:"GPRS - Authentication and ciphering response",
#    20:"GPRS - Authentication and ciphering reject",
#    28:"GPRS - Authentication and ciphering failure",
#    21:"GPRS - Identity request",
#    22:"GPRS - Identity response",
#    32:"GPRS - GMM status",
#    33:"GPRS - GMM information",
#    }

# Packet Service Session Management procedures dict
#PS_SM = {
#    65:"GPRS - Activate PDP context request",
#    66:"GPRS - Activate PDP context accept",
#    67:"GPRS - Activate PDP context reject",
#    68:"GPRS - Request PDP context activation",
#    69:"GPRS - Request PDP context activation rejection",
#    70:"GPRS - Deactivate PDP context request",
#    71:"GPRS - Deactivate PDP context accept",
#    72:"GPRS - Modify PDP context request(Network to MS direction)",
#    73:"GPRS - Modify PDP context accept (MS to network direction)",
#    74:"GPRS - Modify PDP context request(MS to network direction)",
#    75:"GPRS - Modify PDP context accept (Network to MS direction)",
#    76:"GPRS - Modify PDP context reject",
#    77:"GPRS - Activate secondary PDP context request",
#    78:"GPRS - Activate secondary PDP context accept",
#    79:"GPRS - Activate secondary PDP context reject",
#    80:"GPRS - Reserved",
#    81:"GPRS - Reserved",
#    82:"GPRS - Reserved",
#    83:"GPRS - Reserved",
#    84:"GPRS - Reserved",
#    85:"GPRS - SM Status",
#    86:"GPRS - Activate MBMS Context Request",
#    87:"GPRS - Activate MBMS Context Accept",
#    88:"GPRS - Activate MBMS Context Reject",
#    89:"GPRS - Request MBMS Context Activation",
#    90:"GPRS - Request MBMS Context Activation Reject",
#    91:"GPRS - Request Secondary PDP Context Activation",
#    92:"GPRS - Request Secondary PDP Context Activation Reject",
#    93:"GPRS - Notification",
#    }
#'''


