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
# * File Name : formats/L3Mobile_24007.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# exporting
__all__ = ['Type1_V', 'Type1_TV', 'Type2', 'Type3_V', 'Type3_TV', \
           'Type4_LV', 'Type4_TLV', 'Type6_LVE', 'Type6_TLVE', \
           'PD_dict', 'IE_lookup', \
           'RR_in_CCCH', 'StrRR', 'Layer3']

from libmich.core.element import Element, Str, Int, Bit, Layer, RawLayer, \
     Block, show, log, ERR, WNG, DBG
from libmich.core.IANA_dict import IANA_dict
from binascii import hexlify
from re import search

# these are the libraries for IE interpretation 
from libmich.formats.L3Mobile_IE import *
from libmich.formats.L3GSM_IE import *
from libmich.formats.L3GSM_rest import *
#
#
######
# TS 24.007, section 11.2.3.1.1
# Protocol Discriminator dict
PD_dict = IANA_dict({
    0:("group call control", "GCC"),
    1:("broadcast call control", "BC"),
    2:("EPS session management messages", "ESM"),
    3:("call control; call related SS messages", "CC"),
    4:("GPRS Transparent Transport Protocol", "GTTP"),
    5:("mobility management messages", "MM"),
    6:("radio resources management messages", "RR"),
    7:("EPS mobility management messages", "EMM"),
    8:("GPRS mobility management messages", "GMM"),
    9:("short messages service", "SMS"),
    10:("GPRS session management messages", "SM"),
    11:("non call related SS messages", "SS"),
    12:("Location services", "LCS"), # specified in 3GPP TS 44.071 [8a]
    13:"reserved for extension of the PD to one octet length",
    14:"testing",
    })

#
# the following list is used when parsing L3 messages
# if a field has 1 of the following name (possibly with an _[0-9]{1,} suffix)
# its content will be mapped onto the corresponding Information Element
IE_lookup = {
    # L3Mobile_IE.py: 2G / 3G IE
    'BCDNumber' : BCDNumber,
    'CallingBCD' : BCDNumber,
    'CalledBCD' : BCDNumber,
    'RedirectingBCD' : BCDNumber,
    'LAI' : LAI,
    'RAI' : RAI,
    'ID' : ID,
    'IMEISV' : ID,
    'MSCm1' : MSCm1,
    'MSCm2' : MSCm2,
    'MSCm3' : MSCm3,
    'PLMN' : PLMN,
    'PLMNList' : PLMNList,
    'AuxState' : AuxState,
    'BearerCap' : BearerCap,
    'CCCap' : CCCap,
    'PDPAddr' : PDPAddr,
    'QoS' : QoS,
    'ProtConfig' : ProtConfig,
    'PFlowID' : PacketFlowID,
    'MSNetCap' : MSNetCap,
    'MSRACap' : MSRACap,
    # L3Mobile_IE.py: LTE / EPC IE
    'GUTI' : GUTI, 
    'EPSFeatSup' : EPSFeatSup,
    'TAI' : TAI,
    'TAIList' : TAIList,
    'UENetCap' : UENetCap,
    'UESecCap' : UESecCap,
    'CLI' : BCDNumber,
    'APN_AMBR' : APN_AMBR,
    # L3Mobile_IE.py: supplementary services
    'Facility' : Facility,
    #'SSscreen' : SSscreen,
    'SSversion' : SSversion,
    # L3GSM_IE.py
    'CellChan' : CellChan,
    'BCCHFreq' : BCCHFreq,
    'ExtBCCHFreq' : ExtBCCHFreq,
    'RACHCtrl' : RACHCtrl,
    'CChanDesc' : CChanDesc,
    'CellOpt' : CellOpt,
    'CellSel' : CellSel,
    'ChanDesc' : ChanDesc,
    'MobAlloc' : MobAlloc,
    'PChanDesc' : PChanDesc, 
    'ReqRef' : ReqRef,
    # L3GSM_rest.py
    'P1RestOctets' : P1RestOctets,
    'P2RestOctets' : P2RestOctets,
    'P3RestOctets' : P3RestOctets,
    'IARestOctets' : IARestOctets,
    'SI1RestOctets' : SI1RestOctets,
    'SI2terRestOctets' : SI2terRestOctets,
    'SI2quaterRestOctets' : SI2quaterRestOctets,
    'SI3RestOctets' : SI3RestOctets,
    'SI4RestOctets' : SI4RestOctets,
    'SI13RestOctets' : SI13RestOctets,
    }
IE_list = IE_lookup.keys()

######
# TS 24.007 standard message format
# section 11.2.1.1
# This is particularly used to distinguish optional / conditional IE (with tag)
# generally: Type1_TV(), Type3_TV(), Type4_TLV(), Type6_TLVE()
# from mandatory IE (without tag) 
# generally: Str(), Int(), Bit(), Type4_LV(), Type6_LVE()
#

class LayerTLV(Layer):
    def getobj(self):
        if isinstance(self.V.Pt, (Element, Layer, tuple, list)) \
        and not self.V.Val:
            return self.V.Pt
        else:
            return self.V()

# Type1_V() will certainly not be used, better call directly Bit()
class Type1_V(LayerTLV):
    # Type1_TV consists only of 4 bits (MSB or LSB)
    _byte_aligned = False
    constructorList = [
        Bit(CallName='V', BitLen=4),
        ]
    def __init__(self, CallName='', ReprName='', V=0):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName)
        self.V.Pt = V

class Type1_TV(LayerTLV):
    constructorList = [
        Bit(CallName='T', BitLen=4, Repr='hum'),
        Bit(CallName='V', BitLen=4, Repr='bin'), # or Repr='hum'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V=0, \
                 Trans=False, Dict=None):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.V.Pt = V
        if Dict:
            self.V.Dict = Dict
            self.V.Repr = 'hum'
    # optional tag, 
    # in case is "transparent", need to set length to 0
    def __len__(self):
        if self.Trans:
            return 0
        else:
            return 1

# Type2() must be used instead of Int() or Str() for optional IE 
# that is a single tag (/ uchar) flag
class Type2(LayerTLV):
    constructorList = [
        Int(CallName='T', Type='uint8'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
    # optional tag, 
    # in case is "transparent", need to set length to 0
    def __len__(self):
        if self.Trans:
            return 0
        else:
            return 1

# Type3_V() will certainly not be used, better call directly Str()
# anyway, "Trans" should always stay False
class Type3_V(LayerTLV):
    constructorList = [
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0', Len=1):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName)
        self.V.Pt = V
        self.V.Len = Len

class Type3_TV(LayerTLV):
    constructorList = [
        Int(CallName='T', Type='uint8'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', T=0, V='\0', \
                 Len=1, Trans=False):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=Trans)
        self.T.Pt = T
        self.V.Pt = V
        self.V.Len = Len
    # optional tag, 
    # in case is "transparent", need to set length to 0
    def __len__(self):
        if self.Trans: return 0
        else: return self.V.Len + 1

# "Trans" should always stay False
class Type4_LV(LayerTLV):
    constructorList = [
        Int(CallName='L', Type='uint8'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0'):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=False)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

class Type4_TLV(LayerTLV):
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
    # optional tag, 
    # in case is "transparent", need to set length to 0
    def __len__(self):
        if self.Trans:
            return 0
        else:
            return self.L() + 2

# "Trans" should always stay False
class Type6_LVE(LayerTLV):
    constructorList = [
        Int(CallName='L', Type='uint16'),
        Str(CallName='V'),
        ]
    def __init__(self, CallName='', ReprName='', V='\0'):
        Layer.__init__(self, CallName=CallName, ReprName=ReprName, Trans=False)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.V.Pt = V

class Type6_TLVE(LayerTLV):
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
    # optional tag, 
    # in case is "transparent", need to set length to 0
    def __len__(self):
        if self.Trans:
            return 0
        else:
            return self.L() + 3

######
# for GSM RR over broadcast channel, we have 
# extra length and padding processing for signalling messages
#
# TS 44.006 defines data link format
# which carries signalling for 2G mobile networks
# section 5: Frame structure for p2p communication
#
# 44006, section 5.1
# frame Bbis, for BCCH, PCH, NCH, AGCH
######
# Defining a Str class that will handle '2b' padding
# This kind of StrRR is only good for rest octets in GSM RR
# if used in standard (TLV-like) object, will certainly lead to infinite loop...
class StrRR(Str):
    _padding_byte = '\x2b'
    def __call__(self):
        # when length has fixed or known value:
        if self.LenFunc is not None:
            if self.safe:
                assert(type(self.LenFunc(self.Len)) is int)
            l = self.LenFunc(self.Len)
        else:
            l = None
        return Str.__call__(self, l)

# > Now in L2GSM
# 44006, section 6.6
# Length indicator field
#class LengthRR(Layer):
#    constructorList = [
#        Bit('len', ReprName='L2 pseudo length', Pt=0, BitLen=6, Repr='hum'),
#        Bit('M', ReprName='More data bit', Pt=0, BitLen=1),
#        Bit('EL', ReprName='Length field not extended', Pt=1, BitLen=1)]
#

RR_in_CCCH = [
'IMMEDIATE_ASSIGNMENT', 'PAGING_REQUEST_1', 'PAGING_REQUEST_2', \
'PAGING_REQUEST_3', 'SI_1', 'SI_2', 'SI_2bis', 'SI_2ter', 'SI_2quater', \
'SI_3', 'SI_4', 'SI_13']

           
######
# Now is for any mobile L3 messages (including GSM RR)
# define a specific way to map string for mobile signalling
# as defined mainly in TS 24007
# and including GSM RR extra prefix / suffix
class Layer3(Layer):
    
    # debugging facility level
    dbg = 1
    
    # message format dependancy: Net / ME
    # needed for some messages in L3Mobile_CC
    #initiator = 'Net'
    _initiator = 'ME'
    
    # for a complete decoding
    _interpret_IE = True
    # for IE representation in .show()
    _IE_with_repr = ['LAI', 'ID', 'PLMN']
    #_IE_no_show = []
    _IE_no_show = ['CSN1_padding', 'CSN1_condition']
    
    # not representing transparent IE
    _repr_trans = False
    
    def __init__(self, CallName='', ReprName='', Trans=False, **kwargs):
        Layer.__init__(self, CallName='', ReprName='', Trans=Trans)
        #
        for ie in self:
            if hasattr(ie, 'CallName') and ie.CallName in kwargs:
                if hasattr(ie, 'V'):
                    ie.V > kwargs[ie.CallName]
                else:
                    ie > kwargs[ie.CallName]
    
    # handles optional tag (TLV) transparency at initialization
    def _post_init(self, with_options=True, **kwargs):
        for ie in self:
            # this condition changes the way messages with repeated indicator 
            # and IEs are generated
            # TODO: take a decision on which condition is the most convinient!
            #if hasattr(ie, 'T') and ie.Trans is False:
            if hasattr(ie, 'T'):
                ie.Trans = not with_options
            if hasattr(ie, 'CallName') and ie.CallName in kwargs:
                if hasattr(ie, 'V'):
                    ie.V > kwargs[ie.CallName]
                else:
                    ie > kwargs[ie.CallName]
                ie.Trans = False
    
    # Patch L2 length for dummy GSM RR length computation !!!
    def _len_gsmrr(self, string=''):
        # In general, we can trust the L2 length value from LengthRR header:
        l2_len = ord(string[0])>>2
        rr_type = ord(string[2])
        # however, some SI have fake length (e.g. 0 or 1): WTF ?!?!
        # SI 13, SI 2 Quater -> need to be 2
        # SI 2 Ter -> need to be 18
        if rr_type in (0, 7) and l2_len in (0, 1): return 2
        elif rr_type == 3: return 18
        return l2_len

    # need a specific parser to manage optional or conditional IE
    # as explained in TS 24.007, section 11
    # and pointing to specific libraries in IE_sources when exists
    def map(self, string=''):
        # Layer3 have optional fields that need special processing
        # they all have a tag (attribute .T)
        opt_fields = (Type1_TV, Type2, Type3_TV, Type4_TLV, Type6_TLVE)
        GSM_RR = False
        # handle special string truncature for L3GSM_RR that is on CCCH
        # cause opts may not be there, but we still have rest octets to map
        if self.CallName in RR_in_CCCH:
            if self.safe:
                assert(isinstance(self[0], Bit) and self[0].CallName=='len')
            GSM_RR, l2_len = True, self._len_gsmrr(string)
            string, rest = string[:l2_len+1], string[l2_len+1:]
            if self.dbg >= DBG:
                log(DBG, '(Layer3 GSM_RR - %s)\nl2len: %i\nstring: %s\nrest: %s' \
                    % (self.CallName, l2_len, hexlify(string), hexlify(rest)))
        # Otherwise we mimic standard Layer().map() behaviour
        self._Layer__BitStack = []
        self._Layer__BitStack_len = 0
        #
        for e in self:
            # special processing for Bit() element:
            if isinstance(e, Bit):
                self._Layer__add_to_bitstack(e)
                # if BitStack is byte aligned, map string to it:
                if self._Layer__BitStack_len % 8 == 0:
                    if self.dbg >= DBG:
                        log(DBG, '(Layer3 - %s) mapping %s to bitstack %s' \
                            % (self.__class__, hexlify(string), \
                               self._Layer__BitStack))
                    string = self._Layer__map_to_bitstack(string)
            else:
                if self._Layer__BitStack_len > 0 and self.dbg >= ERR:
                    log(ERR, '(Layer3 - %s) some of the Bit elements have not ' \
                        'been mapped in the "Layer": not byte-aligned' \
                        % self.CallName)
                ### special Layer3 processing ###
                # need to manage smartly optional / conditionnal fields
                # Tagged IE always come after mandatory IE
                # so we handle it in another sub method and break the parsing
                if isinstance(e, opt_fields):
                    # for standard L3 messages
                    self.__map_opts(string)
                    break
                ###
                # and for mandatory IE (not tagged)
                if isinstance(e, (Layer, Element)) and not e.is_transparent():
                    if self.dbg >= DBG:
                        log(DBG, '(Layer3 - %s) mapping %s on %s' \
                            % (self.__class__, hexlify(string), e.CallName))
                    e.map(string)
                    string = string[e.map_len():]
        # for GSM RR: map rest octets, that comes after tagged IE
        if GSM_RR and rest:
            if isinstance(self[-1], StrRR):
                self[-1].Trans = False
            else:
                self.append(StrRR('RestOctets', Repr='hex'))
            self[-1].map(rest)
        # delete .map() *internal* attributes
        del self._Layer__BitStack
        del self._Layer__BitStack_len
        #
        ### special Layer3 processing ###
        if not self._interpret_IE:
            return
        #
        # Go again through all L3 fields that are not transparent
        # (tested with their length, WNG: do not work for LV(), however,
        # LV field should always be there...) 
        # and check if L3Mobile_IE is available for even more interpretation
        for e in [f for f in self if len(f)]:
            cn = e.CallName
            if self.dbg >= DBG:
                log(DBG, 'L3Mobile_24007 - map: checking for IE %s ' \
                    'interpretation' % cn)
            # truncate possible digit addition at the end of the CallName
            # 11/06/2012: this ugly hack is not supported anymore...
            # 13/06/2012: this ugly hack is back ! 
            # with an '_' in front of the digit
            digit = search('_[1-9]{1,}$', e.CallName)
            if digit:
                cn = cn[:digit.start()]
            # check for potential IE interpretation
            #if hasattr(L3Mobile_IE, cn) or hasattr(L3GSM_IE, cn):
            if cn in IE_list:
                self.interpret_IE(e, cn)
    
    def interpret_IE(self, field, cn):
        # interpret field as cn
        # cn is looked up in L3Mobile_IE, L3GSM_IE or L3GSM_RR libs
        if self.dbg >= DBG:
            log(DBG, 'Layer3 - interpret IE: %s' % cn)
        # check if direct field, or (T)LV-like field
        if hasattr(field, 'V'):
            # bypass IE interpretation in case of LV or TLV with null length
            if hasattr(field, 'L') and field.L() == 0:
                return
            f_val = field.V
        else:
            f_val = field
        # replace the raw field value by pointing to the retrieved IE
        buf = str(f_val)
        ie = IE_lookup[cn]()
        try:
            ie.map(buf)
        except:
            if self.dbg >= WNG:
                log(WNG, 'Layer3 - IE mapping failed for %s' % ie.__class__) 
        else:
            # only update the field if we got correct length data for the IE
            if str(ie) == buf:
            #if len(ie) == len(buf):
                f_val < None
                f_val > ie
                # and go for human representation...
                f_val.Repr = 'hum'
    
    def __map_opts(self, string=''):
        # retrieve all optional IE from the Layer3 into opt_ie list
        opt_ie = self.__get_opts()
        taglist = [ie[0]() for ie in opt_ie if not isinstance(ie, StrRR)]
        if self.dbg >= DBG:
            log(DBG, '(Layer3 - %s) opt_ie: %s' % (self.CallName, opt_ie))
        # go over the string and map to optional IE found
        while len(string) > 0:
            # check each iteration for the right tag
            t = self._select_tag(string[0], taglist)
            if t:
                string, opt_ie = self.__map_opt(t, string, opt_ie)
                taglist.remove(t)
            #
            else:
                if self.dbg >= ERR:
                    log(WNG, '(Layer3 - %s) unknown optional IE' \
                        % self.CallName)
                # could try to map it as a TLV, or TLVextended, or TV, or T...
                # check the TS 24.007, section 11.2.4, for being amazed...
                string2 = self.__map_unknown_opt(string)
                if string2 == string:
                    break
                string = string2
            #
        # optional IE that have not been mapped have to go "transparent"
        if len(opt_ie) > 0:
            [setattr(ie, 'Trans', True) for ie in opt_ie]
            if self.dbg >= DBG:
                log(DBG, '(Layer3 - %s) not all optional IE used\nremaining:' \
                    ' %s' % (self.CallName, opt_ie))
        # this should only happen when __map_unknown_opt() cannot 
        # consume remaining string.
        if len(string) > 0 and self.dbg >= ERR:
            log(ERR, '(Layer3 - %s) string not completely mapped\nremaining: ' \
                '%s' % (self.CallName, string))
    
    def _select_tag_old_(self, s='\0', taglist=[]):
        # check for 4 bits and 8 bits tags
        t4, t8 = ord(s[0])>>4, ord(s[0])
        if self.dbg >= DBG:
            log(DBG, '(Layer3 - %s) t4, t8: %s, %s\ntaglist: %s' \
                     % (self.CallName, t4, t8, taglist))
        #
        # handle 4 bits tag in priority
        # guessing from 3GPP spec:
        #   4 bits and 8 bits tags should never clash...
        # actually, this is not always the case 
        #   e.g. for tag 4 (BearerCap) and 64 (SuppCodecs)
        # TODO: this is actually a real issue,
        # e.g. with GSM RR ASSIGNMENT_COMMAND
        if t4 in taglist:
            return t4
        elif t8 in taglist:
            return t8
        return None
    
    def _select_tag(self, s='\0', taglist=[]):
        # check for 4 bits and 8 bits tags
        t4, t8 = ord(s[0])>>4, ord(s[0])
        if self.dbg >= DBG:
            log(DBG, '(Layer3 - %s) t4, t8: %s, %s\ntaglist: %s' \
                     % (self.CallName, t4, t8, taglist))
        #
        # try another way:
        # prefer the tag which is 1st in the taglist, whatever tag length
        for t in taglist:
            if t in (t4, t8):
                return t
        return None
    
    def __get_opts(self):
        found_opt, opt_ie = False, []
        # we have at least 3 mandatory fields (L3 header: SI, PD, Type)
        # and we should not have any IE left, except StrRR for GSM RR
        if isinstance(self[-1], StrRR): ie_to_check = self[3:-1]
        else: ie_to_check = self[3:]
        #
        for ie in ie_to_check:
            if hasattr(ie, 'T') or isinstance(ie, (Type2, StrRR)):
                found_opt = True
                opt_ie.append(ie)
                # make all optional fields not transparent (so all of them
                # can be mapped, whatever Layer3.__init__() options given)
                ie.Trans = False
            elif found_opt and self.dbg >= ERR:
                # we should not find mandatory IE after optional
                log(ERR, '(Layer3 - %s) mandatory IE found after ' \
                    'optional ones' % self.CallName)
        return opt_ie
    
    def __map_opt(self, tag, string, opt_ie):
        # retrieve 1st optional IE for the given tag: in opt
        opt = None
        for ie in opt_ie:
            if ie[0]() == tag:
                opt = ie
                break
        # remove it from the opt_ie list that will be further processed
        # python's "remove()" remove the 1st iteration of an element in a list
        if not opt:
            log(ERR, '(Layer3 - %s) no remaining optional field for tag %i' \
                     % (self.CallName, tag))
            return '', opt_ie
        opt_ie.remove(opt)
        # force it to be not transparent, map it and truncate the string
        opt.Trans = False
        opt.map(string)
        if self.dbg >= DBG:
            log(DBG, '(Layer3 - %s) mapping %s on %s' \
                      % (self.__class__, hexlify(string), opt.CallName))
        string = string[opt.map_len():]
        return string, opt_ie
    
    def __map_unknown_opt(self, string):
        # TODO: handle correctly EPS EMM and ESM
        opt = None
        if ord(string[0]) >> 7:
            opt = Type2()
        elif len(string) > 2:
            opt = Type4_TLV()
        if opt:
            opt.map(string)
            # In case of GSM RR, need to insert the unknown option
            # before rest octets
            if isinstance(self[-1], StrRR):
                self.insert(len(self.elementList)-1, opt)
            else:
                self.append(opt)
            string = string[opt.map_len():]
        return string
    
    def show(self, with_trans=False):
        re, tr = '', ''
        if self.ReprName != '':
            re = '%s ' % self.ReprName
        if self.is_transparent():
            # TODO: eval the best convinience here
            if not with_trans:
                return ''
            tr = ' - transparent'
        # Layer content
        #str_lst = [e.show().replace('\n', '\n ') for e in self]
        str_lst = []
        for e in self:
            if e.is_transparent():
                pass
            elif e.CallName in self._IE_no_show:
                pass
            else:
                if e.CallName not in self._IE_with_repr \
                and isinstance(e, Str) and isinstance(e.Pt, Layer) \
                and e.Val is None:
                    str_lst.append(e.Pt.show(with_trans).replace('\n', '\n '))
                else:
                    str_lst.append(e.show(with_trans).replace('\n', '\n '))
        #
        # insert spaces for nested layers and filter out empty content
        str_lst = [' %s\n' % s for s in str_lst if s]
        # insert layer's title
        str_lst.insert(0, '### %s[%s]%s ###\n' % (re, self.CallName, tr))
        # return full inline string without last CR
        return ''.join(str_lst)[:-1]
#
