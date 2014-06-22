# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2014. Benoit Michau. ANSSI.
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
# * File Name : asn1/ASN1_PER.py
# * Created : 2014-05-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python
# standard Python import (OrderedDict requires Python 2.7)
from types import NoneType
from math import ceil
from collections import OrderedDict as OD # just like OD Simpson :)
#
from libmich.core.element import Bit, Int, Str, Layer, show, showattr, \
    log, DBG, WNG, ERR
from libmich.core.shtr import decomposer, shtr
from libmich.utils.IntEncoder import *

# BIG WARNING:
# In this ASN.1 PER world, having a damned byte-aligned layer is the exception !
Layer._byte_aligned = False

################################################################################
# ASN.1 for some 3GPP data encoding / decoding with PER
################################################################################
#
# this is only a very tiny subset of the ASN.1 syntax and
# PER rules, as per ITU-T X.691
#
# ASN.1 objects currently implemented are:
# basic objects: INTEGER, ENUMERATED, BIT STRING, OCTET STRING
# container objects: CHOICE, SEQUENCE, SEQUENCE OF
#
# For each ASN.1 object, we can have:
# - preamble
#   -> bitmap for optional element in a SEQUENCE
#   -> extension bit
# - length / count determinant (depending of constraints)
# - padding, only in the octet-aligned variant
# - encoded value or encapsulated object
#
# Each of which depends of the basic type and associated constraints
# Constraints are generally of type:
# - lower bound / upper bound
# - number of enumeration / choice
# - size (in byte, in bit -for BIT STRING-, or in number of element, 
#   for SEQUENCE or CHOICE)
#
#
# WARNING: several limitations are made
# - there is no handling of object with size > 64k
#   so there is no handling of fragmentation / reassembling for large values
# - there is no encoding / decoding of unconstrained INTEGER over 64 bits
# - there is no checking on extended constraints when encoding extended values
#   of INTEGER or SIZE for iterative objects
# - there is no handling of ENUM over 255 standard values and 64 extended values
# - there is no handling of CHOICE over 64 extended values
# - there is no handling of specified alphabet for STRING (FROM("xyz")) objects
# - there is no handling of encoding ASN.1 complex (or even simple) objects within 
#   SEQUENCE that are passed with an arg equal to DEFAULT (so we are not 
#   CANONICAL)
# - CHOICE and SEQUENCE extensions are not handled correctly, if not at all
# - SET is not implemented, yet, neither SEQUENCE OF and SET OF
#
# TODO: resolve all those warnings !
#
################################################################################

# export filtering
__all__ = ['ASN1_PER_INTEGER', 'ASN1_PER_ENUMERATED', 'ASN1_PER_BIT_STRING',
           'ASN1_PER_OCTET_STRING', 'ASN1_PER_CHOICE', 'ASN1_PER_SEQUENCE'
           ]
#
# moreover, there are ASN1_PER internal structures:
# ASN1_PER_L: length determinant
# ASN1_PER_NSVAL: normally small values
# ASN1_PER_P: padding bits (for the PER octet-aligned variant)
# ASN1_PER_E: extensibility bit

################################################################################
################################################################################

###
# Helpers
###
#
# a default ASN1 PER Layer template:
# 1) there are needs to pass specific ASN1 attributes during initialization:
# constraints, extensibility, ...
# 2) there are 2 specific methods for encoding / decoding
# .encode(val), .decode(buf)
#
class ASN1_PER(Layer):
    #
    # PER variant:
    VARIANT = 'A' # 'A': aligned, 'U': unaligned
    #
    # offset (in bits), for adding padding bits during encoding / decoding
    # only used in the octet-aligned variant
    _off = 0
    #
    # this is a convinience to return constructed structures when 
    # encoding value / decoding buffer
    _RET_STRUCT = True
    #
    # this is a convinience for Value representation when
    # representing encoded / decoded Value
    _VAL_REPR = 'bin' # 'hum', 'hex' or 'bin'
    #
    # this is a trigger for enforcing constraints checking at each instance
    # initialization (useful for debug / verification)
    _SAFE = True
    
    def __init__(self, *args, **kwargs):
        # this is to pass ASN1 attributes: lower / upper bound (_lb, _ub), also
        # for SIZE, extensibility (_ext), enumerated list (_enum), ...
        #
        Layer.__init__(self, *args, **kwargs)
        for kw in kwargs:
            if hasattr(self, '_%s'%kw):
                setattr(self, '_%s'%kw, kwargs[kw])
        #
        if self._SAFE and not self.check_constraints():
            raise(ASN1_DEFINITION_ERR())
    
    def check_constraints(self):
        return True
    
    def encode(self, val):
        pass
    
    def decode(self, buf):
        pass
    
    # this is to support the standard Layer methods, from .decode(buf)
    # .map(buf) and .map_ret(buf)
    def map_ret(self, buf):
        rt = self._RET_STRUCT
        self._RET_STRUCT = False
        buf = self.decode(buf)
        return buf
        self._RET_STRUCT = rt
    
    def map(self, buf):
        ret = self.map_ret(buf)
    
    # this is to mask all the encoding business (extension bit / bitmap,
    # padding, length determinant...)
    def __repr__(self):
        return '<%s: %s>' % (self.CallName, self())


# some Exceptions when defining / encoding / decoding ASN1 PER
class ASN1_DEFINITION_ERR(Exception): pass
class ASN1_PER_ENCODER_ERR(Exception): pass
class ASN1_PER_DECODER_ERR(Exception): pass

# a switch to configure the PER variant ('Aligned' / 'Unaligned')
def switch_variant(var='A'):
    if var and var[0] not in ('A', 'U'):
        return
    ASN1_PER.VARIANT = var

###
# Length determinant, for unbounded object size
###
# in PER ALIGNED, length determinant must be left-padded with 0 to 7 bits
# to have its structure octet-aligned

_LUndef_dict = {0:'16K', 1:'32K', 2:'48K', 3:'64K'}

class ASN1_PER_L(Layer):
    # actually, this length determinant shall always be byte-aligned
    _byte_aligned = True
    constructorList = [
        Bit('Form', Pt=0, BitLen=1, Repr='hum', Dict={0:'short', 1:'long'}),
        Bit('Count', Pt=0, BitLen=7)
        ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, CallName='L', **kwargs)
        if 'Count' in kwargs:
            self.encode(kwargs['Count'])
        elif args and isinstance(args[0],  (int, long)):
            self.encode(args[0])
    
    def encode(self, count=0):
        self.__init__()
        if 0 <= count <= 127:
            self.Form > 0
            self.Count > count
        elif 128 <= count <= 16383:
            self.Form > 1
            self.insert(1, Bit('Undef', Pt=0, BitLen=1, Repr='hum'))
            self.Count.BitLen = 14
            self.Count > count
        elif count in (16384, 32768, 49152, 65536):
            self.Form > 1
            self.insert(1, Bit('Undef', Pt=1, BitLen=1, Repr='hum'))
            self.Count.BitLen = 6
            self.Count.Dict = _LUndef_dict
            self.Count > (count // 16384) - 1 
        else:
            raise(ASN1_PER_ENCODER_ERR('max length is for 16/32/48/64K '\
                                        'fragments'))
    
    def __call__(self):
        if self.Form() == 0 or self.Undef() == 0:
            return self.Count()
        else:
            return self.Count() * 16384
    
    def __repr__(self):
        return '%i' % self()
    
    def _map_pre(self, s=''):
        if not s:
            return
        # reinit to the basic representation 
        self.__init__()
        # get the Form bit
        s_0 = ord(s[0])
        F = s_0>>7
        # short form: do not change anything
        # long form:
        if F:
            self.insert(1, Bit('Undef', Pt=0, BitLen=1, Repr='hum'))
            # get the Undefinite bit
            U = (s_0>>6)&1
            if U:
                self.Count.BitLen = 6
                self.Count.Dict = _LUndef_dict
            else:
                self.Count.BitLen = 14
    
    def map(self, s=''):
        self._map_pre(s)
        # map on the structure
        Layer.map(self, s)
    
    def map_ret(self, s=''):
        self._map_pre(s)
        # map on the structure
        return Layer.map_ret(self, s)

###
# "Normally small" values, use with caution...
###
# to be used for unbounded length determinant expected to be small
# only for ENUMERATED extension
#
class ASN1_PER_NSVAL(Layer):
    constructorList = [
        Bit('Sig', Pt=0, BitLen=1, Repr='hum'), # this should always stay 0
        Bit('Value', Pt=0, BitLen=6, Repr='hum', Dict={}) # 0 to 64
        ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, CallName='Value')
        val = -1
        if 'Value' in kwargs:
            val = kwargs['Value']
        elif args and isinstance(args[0], (int, long)):
            val = args[0]
        if val >= 64:
            raise(ASN1_PER_ENCODER_ERR('value %i not encodable to normally '\
                                        'small value' % i))
        elif val >= 0:
            self.Value > val
    
    def __call__(self):
        return self.Value()
    
    def __repr__(self):
        return repr(self.Value)
    
###
# Padding
###
class ASN1_PER_P(Bit):
    CallName = 'P'
    Repr = 'bin'

###
# Extensibility
###
class ASN1_PER_E(Bit):
    CallName = 'E'
    Repr = 'bin'

###
# Bitmap (for SEQUENCE and SET)
###
class ASN1_PER_B(Bit):
    CallName = 'B'
    Repr = 'bin'

################################################################################
################################################################################

###
# INTEGER
###
class ASN1_PER_INTEGER(ASN1_PER):
    '''
    ASN1 INTEGER
    specific attributes:
        - lb: lower bound, None or integer
        - ub: upper bound, None or integer (> lb)
        - ext: extensibility, True / False
    
    .get_range() -> uint or None, range between bounds 
    .has_single_val() -> bool, True in case of equal lower and upper bounds
    .encode(int), to encode an integer value
    .decode(str) -> str, decode the buffer, returns the rest of the buffer
                    that was not consumed
    '''
    #
    # ASN1 INTEGER attributes:
    # lower and upper bounds of the integer value
    _lb = None # unconstrained
    _ub = None # infinite
    # extensibility
    _ext = False # False: no extensibility marker, True: extensibility marker
                 # e.g. INTEGER(0..255, ...)
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._lb, (NoneType, int, long)):
            print('incorrect lb (%s) in %s' % (self._lb, self.__name__))
            return False
        if not isinstance(self._ub, (NoneType, int, long)):
            print('incorrect ub (%s) in %s' % (self._ub, self.__name__))
            return False
        if not isinstance(self._ext, bool):
            print('incorrect ext (%s) in %s' % (self._ext, self.__name__))
            return False
        if isinstance(self._lb, (int, long)) \
        and isinstance(self._ub, (int, long)) \
        and self._ub < self._lb:
            print('ub (%i) less than lb (%i) in %s' \
                   % (self._ub, self._lb, self.__name__))
            return False
        return True
    
    def get_range(self):
        if isinstance(self._lb, NoneType):
            return None
        elif isinstance(self._ub, NoneType):
            return None
        else:
            return self._ub - self._lb + 1
    
    def has_single_val(self):
        # when constraints upper and lower bounds are equal
        return not self._ext \
            and isinstance(self._lb,  (int, long)) \
            and isinstance(self._ub,  (int, long)) \
            and self._lb == self._ub
    
    def encode(self, val=0):
        '''
        arg: integer
        '''
        #
        # empty internal elements
        self.elementList = []
        #
        # no lower bound provided -> unconstrained integer type
        if self._lb is None:
            #
            # check if there is an upper bound, and value provided is over it
            if isinstance(self._ub, (int, long)) and val > self._ub:
                if self._ext:
                    # in case integer is extensible, it works
                    self._encode_unconst_val(val, ext=True)
                else:
                    # otherwise, unable to encode overflowing value
                    raise(ASN1_PER_ENCODER_ERR('integer value %i over upper '\
                                                'bound' % val))
            #
            else:
                self._encode_unconst_val(val)
        #
        # lower bound provided -> semi or fully constrained
        elif isinstance(self._lb, (int, long)):
            #
            # check if value provided is under lower bound
            if val < self._lb:
                if self._ext:
                    # in case integer is extensible, it works
                    self._encode_unconst_val(val, ext=True)
                else:
                    # otherwise, unable to encode underflowing value
                    raise(ASN1_PER_ENCODER_ERR('integer value %i under lower '\
                                                'bound' % val))
            #
            # upper-bound not provided -> semi-constrained integer value
            elif self._ub is None:
                # encoding the offset to the lower bound, like an unconstrained
                self._encode_unconst_val(val-self._lb, uint=True)
            #
            # constrained integer value (PER worst case...)
            elif isinstance(self._ub,  (int, long)):
                _range = self._ub - self._lb + 1
                #
                # check if there is no choice in the possible values
                if _range == 1:
                    if val == self._lb:
                        # if only a single value is possible, 
                        # there is nothing to transfer for this given value
                        pass
                    elif self._ext:
                        # unless integer is extensible...
                        self.elementList = self._encode_unconst_val(val, ext=True)
                #
                # check if value provided is over upper bound
                elif val > self._ub:
                    if self._ext:
                        # in case integer is extensible, it works
                        self._encode_unconst_val(val, ext=True)
                    else:
                        # otherwise, unable to encode overflowing value
                        raise(ASN1_PER_ENCODER_ERR('integer value %i over upper'\
                                                    ' bound' % val))
                #
                # from here, encoding depends on the PER variant (aligned / unaligned)
                elif self.VARIANT[:1] == 'A':
                    # aligned case
                    self._encode_const_val_align(val, _range)
                #
                elif self.VARIANT[:1] == 'U':
                    # unaligned case, always encoding in the minimum number of bits
                    self._encode_minbits(val-self._lb, _range)
        #
        if self._RET_STRUCT:
            return self
    
    def _encode_unconst_val(self, val, uint=False, ext=False):
        # length determinant + minimum octets signed number (2' complement)
        #
        # WNG: this is a limitation of this encoder
        if not -2**63 <= val < 2**63:
            raise(ASN1_PER_ENCODER_ERR('unconstrained integer value %i over '\
                  'encoder limit (64 bit)' % val))
        #
        # 1) add potential extensibility header
        if self._ext:
            ext = 1 if ext else 0
            e_off = 1
            self.append( ASN1_PER_E(Pt=ext, BitLen=1) )
        else:
            e_off = 0
        # 2) add potential padding (octet-aligned variant)
        if self.VARIANT[:1] == 'A':
            pad_len = (8 - (self._off+e_off)%8) % 8
            if pad_len:
                self.append( ASN1_PER_P(BitLen=pad_len) )
        #
        # 3) check how many bytes are needed for encoding the value
        if uint: dyn, typ = minenc_uint(val)
        else: dyn, typ = minenc_int(val)
        #
        # 4) add the length determinant according to the bytes needed 
        self.append( ASN1_PER_L(dyn) )
        # 5) add the encoded value itself
        self.append( 
            Int('Value', Pt=val, Type=typ, Repr=self._VAL_REPR) )
    
    def _encode_const_val_align(self, val, _range):
        # format depends on the range between bounds
        val = val-self._lb
        if _range <= 255:
            # short integer always encode in the minimum number of bits,
            # whatever PER variant
            self._encode_minbits(val, _range)
        else:
            # 1) add potential extensibility header
            if self._ext:
                e_off = 1
                self.append( ASN1_PER_E(Pt=0, BitLen=1) )
            else:
                e_off = 0
            if 256 <= _range <= 65536:
                # 2) add potential padding
                pad_len = (8 - (self._off+e_off)%8) % 8
                if pad_len:
                    self.append( ASN1_PER_P(BitLen=pad_len) )
                # 3) add value with minimal byte-encoding
                if _range == 256:
                    self.append( 
                        Bit('Value', Pt=val, BitLen=8, Repr=self._VAL_REPR) )
                else:
                    self.append( 
                        Bit('Value', Pt=val, BitLen=16, Repr=self._VAL_REPR) )
            else:
                # 2) add custom length determinant (uint value encoded in the
                # minimum number of bytes)
                dynr = len(decomposer(256).decompose(_range))
                dyn = len(decomposer(256).decompose(val))
                self.append( Bit('L', Pt=dyn-1, BitLen=dynr-1) )
                # 3) add potential padding
                pad_len = (8 - (self._off+dynr-1+e_off)%8) % 8
                if pad_len:
                    self.append( ASN1_PER_P(BitLen=pad_len) )
                # 4) add encoded value
                self.append( 
                    Bit('Value', Pt=val, BitLen=dyn*8, Repr=self._VAL_REPR) )
    
    def _encode_minbits(self, val, _range):
        # encoding in the minimum number of bits according to the bounds
        # 1) add potential extensibility header
        if self._ext:
            self.append( ASN1_PER_E(Pt=0, BitLen=1) )
        # 2) add the value encoded in the minimum number of bits, no padding
        dyn = len(decomposer(2).decompose(_range-1))
        self.append( 
            Bit('Value', Pt=val, BitLen=dyn, Repr=self._VAL_REPR) )
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        if not buf and not self.has_single_val():
            raise(ASN1_PER_DECODER_ERR('no buffer provided for decoding'))
        #
        # unconstrained integer type
        if self._lb is None:
            buf = self._decode_unconst_val(buf)
        #
        elif isinstance(self._lb, (int, long)):
            # in case of semi or fully constrained integer, need to check 
            # the extensibility header 1st
            if self._ext and ord(buf[0])&0x80:
                # if extended integer, decoding like an unconstrained
                buf = self._decode_unconst_val(buf)
            #
            # semi-constrained integer value
            elif self._ub is None:
                # decoding like an unconstrained
                buf = self._decode_unconst_val(buf, uint=True)
            #
            # constrained integer value
            elif isinstance(self._ub, (int, long)):
                _range = self._ub - self._lb + 1
                if _range == 1:
                    # if only a single value is possible, nothing is transferred
                    pass
                #
                elif self.VARIANT[:1] == 'A':
                    # aligned case
                    buf = self._decode_const_val_align(buf, _range)
                #
                else:
                    # unaligned case, always decoding in the minimum number of bits
                    buf = self._decode_minbits(buf, _range)
        #
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf
    
    def _decode_unconst_val(self, buf, uint=False):
        #
        # 1) get potential extensibility header
        if self._ext:
            e_off = 1
            e = ASN1_PER_E(BitLen=1)
            buf = e.map_ret(buf)
            self.append(e)
        else:
            e_off = 0
        # 2) get potential padding bits
        if self.VARIANT[:1] == 'A':
            pad_len = (8 - (self._off+e_off)%8) % 8
            if pad_len:
                p = ASN1_PER_P(BitLen=pad_len)
                buf = p.map_ret(buf)
                self.append(p)
        # 3) get the length determinant
        l = ASN1_PER_L()
        buf = l.map_ret(buf)
        self.append(l)
        l_val = l()
        # WNG: this is a limitation of this decoder
        if l_val > 8:
            raise(ASN1_PER_DECODER_ERR('unconstrained integer with %i bytes '\
                  'long over decoder limit (64 bit)' % l_val))
        if uint: typ = 'uint%i' % (l_val*8)
        else: typ = 'int%i' % (l_val*8)
        # 4) deduce the length of the Int according to the determinant
        v = Int('Value', Type=typ, Repr=self._VAL_REPR)
        buf = v.map_ret(buf)
        self.append(v)
        return buf
    
    def _decode_const_val_align(self, buf, _range):
        if _range <= 255:
            return self._decode_minbits(buf, _range)
        else:
            # 1) get potential extensibility header
            if self._ext:
                e_off = 1
                e = ASN1_PER_E(BitLen=1)
                buf = e.map_ret(buf)
                self.append(e)
            else:
                e_off = 0
            # 2) get potential custom length determinant:
            # for range over 64k, decoding in the minimum number of bytes
            if _range == 256:
                dynr, dyn = 0, 1
            elif 256 < _range <= 65536:
                dynr, dyn = 0, 2
            else:
                # _range > 65536
                dynr = len(decomposer(256).decompose(_range))-1
                l = Bit('L', BitLen=dynr)
                buf = l.map_ret(buf)
                self.append(l)
                dyn = l()+1
            # 3) get potential padding
            pad_len = (8 - (self._off+e_off+dynr)%8) % 8
            if pad_len:
                p = ASN1_PER_P(BitLen=pad_len)
                buf = p.map_ret(buf)
                self.append(p)
            # 4) get integer value
            v = Bit('Value', BitLen=dyn*8, Repr=self._VAL_REPR)
            buf = v.map_ret(buf)
            self.append(v)
            return buf
    
    def _decode_minbits(self, buf, _range):
        #
        # 1) add potential extensibility header
        if self._ext:
            e = ASN1_PER_E(BitLen=1)
            buf = e.map_ret(buf)
            self.append(e)
        # 2) decoding in the minimum number of bits, no padding
        dyn = len(decomposer(2).decompose(_range-1))
        v = Bit('Value', BitLen=dyn, Repr=self._VAL_REPR)
        buf = v.map_ret(buf)
        self.append(v)
        return buf
    
    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the value of the ASN.1 INTEGER object
        if self.has_single_val():
            return self._lb
        elif hasattr(self, 'Value'):
            if hasattr(self, 'E') and self.E():
                # extended value
                return self.Value()
            elif isinstance(self._lb, (int, long)):
                return self._lb + self.Value()
            else:
                return self.Value()
        else:
            return None

###
# ENUMERATED
###
class ASN1_PER_ENUMERATED(ASN1_PER):
    '''
    ASN1 ENUMERATED
    specific attributes:
        - enum: ordered dictionnary (OD) of int:string, to be enumerated
        - ext: None or ordered dictionnary of int:string, extended enumeration
    
    .get_range() -> uint or None, number of enumerations in enum
    .get_range_ext() -> uint or None, number of extended enumerations in ext
                        (independent from enum)
    .has_single_val() -> bool, True in case of single enum with no extension
    .encode( str | int ), to encode a given string from the enum / ext, 
        or selecting it with its numerical identifier
    .decode(str) -> str, decode the buffer, returns the rest of the buffer 
                    that was not consumed
    '''
    #
    # ASN1 ENUMERATED attributes:
    # enumerated ordered list
    _enum = OD() # OD([(-2, 'blue'), (5, 'green'), (7, 'red')])
    # lower and upper bounds of the enumeration index are deduced from ._enum
    #
    # extensibility
    _ext = None # None: no extensibility marker,
                # OD([(2, 'yellow'), (6, 'orange')]) new extended values
    #
    # When translating an ASN.1 definition file, we need to take care that
    # - identified enum gets re-ordered according to their identifier
    # - unidentified enum gets identifier from 0 upward
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._enum, OD):
            print('incorrect enum in %s' % self.__name__)
            return False
        elif not all([isinstance(it[0], (int, long)) and isinstance(it[1], str)\
                       for it in self._enum.items()]):
            print('incorrect item in enum in %s' % self.__name__)
            return False
        if not isinstance(self._ext, (NoneType, OD)):
            print('incorrect ext in %s' % self.__name__)
            return False
        elif isinstance(self._ext, OD) \
        and not all([isinstance(it[0], (int, long)) and isinstance(it[1], str)\
                      for it in self._enum.items()]):
            print('incorrect item in ext in %s' % self.__name__)
            return False
        return True
    
    def get_range(self):
        return len(self._enum)
    
    def get_range_ext(self):
        if self._ext: return len(self._ext)
        else: return 0
    
    def has_single_val(self):
        return not self._ext and self.get_range() == 1
    
    def encode(self, val):
        '''
        arg:
            string (from enumerated ones in _enum / _ext)
            or
            integer (index of the enumerated string)
        '''
        #
        self.elementList = []
        #
        if self.has_single_val():
            pass
        #
        elif isinstance(val, (int, long)):
            if val in self._enum:
                self._encode_enum_int(self._enum.keys().index[val])
            elif val in self._ext:
                self._encode_enum_ext_int(self._ext.keys().index[val])
            else:
                raise(ASN1_PER_ENCODER_ERR('identifier %i not in ENUM (extended)'\
                                            ' index' % val))
        #
        elif isinstance(val, str):
            # encode the index of the string as a constrained integer
            enum_str = self._enum.values()
            ext_str = self._ext.values()
            if val in enum_str:
                self._encode_enum_int(enum_str.index(val))
            elif self._ext and val in ext_str:
                self._encode_enum_ext_int(ext_str.index(val))
            else:
                raise(ASN1_PER_ENCODER_ERR('value %s not in ENUM (extended)'\
                                            % val))
        #
        else:
            raise(ASN1_PER_ENCODER_ERR('invalid argument %s' % repr(val)))
        #
        if self._RET_STRUCT:
            return self
    
    def _encode_enum_int(self, val):
        # WNG: this encoder handles only minimum bits integer encoding
        _range = self.get_range()
        if _range >= 256:
            raise(ASN1_PER_ENCODER_ERR('ENUM indexes (%i) over the encoder '\
                  'limit (255)' % _range))
        #
        # encoding into the minimum number of bits
        # 1) add potential extensibility header
        if self._ext:
            self.append( ASN1_PER_E(Pt=0, BitLen=1) )
        # 2) add the value encoded in the minimum number of bits, no padding
        dyn = len(decomposer(2).decompose(_range))
        self.append( 
            Bit('Value', Pt=val, BitLen=dyn, Repr=self._VAL_REPR, 
                Dict=self._build_dict()) )
    
    def _encode_enum_ext_int(self, val):
        # WNG: this encoder handles only normally small values
        _range = self.get_range_ext()
        if _range >= 64:
            raise(ASN1_PER_ENCODER_ERR('extended ENUM values (%i) over the '\
                  'encoder limit (63)' % _range))
        #
        # 1) add extensibility header
        self.append( ASN1_PER_E(Pt=1, BitLen=1) )
        # 2) add the value encoded in the normally small integer value, no padding
        self.append( ASN1_PER_NSVAL(val) )
        self[-1].Value.Dict = self._build_dict(ext=True)
    
    def _build_dict(self, ext=False):
        d = {}
        if ext:
            ext_str = self._ext.values()
            for i in range(self.get_range_ext()):
                d[i] = ext_str[i]
        else:
            enum_str = self._enum.values()
            for i in range(self.get_range()):
                d[i] = enum_str[i]
        return d
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        if not buf and not self.has_single_val():
            raise(ASN1_PER_DECODER_ERR('no buffer provided for decoding'))
        #
        # 1) check for extensibility
        e = None
        if self._ext:
            e = ASN1_PER_E(BitLen=1)
            buf = e.map_ret(buf)
            self.append(e)
        # 2) if extended, decode as normally small value
        if e and e():
            _range = self.get_range_ext()
            if _range >= 64:
                raise(ASN1_PER_DECODER_ERR('extended ENUM values (%i) over the'\
                                            ' decoder limit (63)' % _range))
            v = ASN1_PER_NSVAL()
            buf = v.map_ret(buf)
            v.Value.Dict = self._build_dict(ext=True)
            self.append(v)
        # 3) otherwise, decode as minimum number of bits
        else:
            _range = self.get_range()
            if _range > 255:
                raise(ASN1_PER_ENCODER_ERR('ENUM values (%i) over the decoder'\
                                            ' limit (255)' % _range))
            dyn = len(decomposer(2).decompose(_range-1))
            v = Bit('Value', BitLen=dyn, Repr=self._VAL_REPR, 
                    Dict=self._build_dict())
            buf = v.map_ret(buf)
            self.append(v)
        #
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf

    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the value of the ASN.1 ENUMERATED object
        if self.has_single_val():
            return self._enum.values()[0]
        elif hasattr(self, 'Value'):
            if hasattr(self, 'E') and self.E():
                # extended enum: unconstrained encoding
                return self._ext.values()[self.Value()]
            else:
                return self._enum.values()[self.Value()]
        else:
            return None

###
# Iterative objects: BIT STRING, STRING, ...
###
# For iterative object, we need to specify the number of iterations
# (from 0 to ???), just like a semi-constrained integer
# the length determinant has the following form:
# - if no size upper bound, or extended size value: ASN1_PER_L
# - if unique size: no explicit length determinant
# - if upper bound provided: ASN1_PER_INTEGER

###
# BIT STRING
###
class ASN1_PER_BIT_STRING(ASN1_PER):
    '''
    ASN1 BIT STRING
    specific attributes:
        - lb: lower bound, uint (default 0), for the SIZE
        - ub: upper bound, None or uint, for the SIZE
        - ext: SIZE extensibility, True / False
    
    .has_unique_size() -> bool, True in case of unique SIZE for the bit string
    .has_zero_size() -> bool, True in case of null bit string
    .encode( uint | (str, notation) ), to encode an uint value (in its minimum 
        number of bits: not octet-aligned), or a string precising its notation
        ('B':binary, 'H':hexa, 'S':octet-aligned string)
    .decode(str) -> str, decode the buffer, returns the rest of the buffer 
                    that was not consumed
    '''
    #
    # ASN1 BIT STRING attributes:
    # lower and upper bound of the SIZE attribute
    _lb = 0 # can be > 0
    _ub = None # or uint, semi or fully-constrained
    # extensibility
    _ext = False # False: no extensibility marker, True: extensibility marker
                 # e.g. SIZE(0..255, ...)
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._lb, (int, long)) or self._lb < 0:
            print('incorrect lb (%s) in %s' % (self._lb, self.__name__))
            return False
        if not isinstance(self._ub, (NoneType, int, long)):
            print('incorrect ub (%s) in %s' % (self._ub, self.__name__))
            return False
        if not isinstance(self._ext, bool):
            print('incorrect ext (%s) in %s' % (self._ext, self.__name__))
            return False
        if isinstance(self._ub, (int, long)) \
        and self._ub < self._lb:
            print('ub (%i) less than lb (%i) in %s' \
                   % (self._ub, self._lb, self.__name__))
            return False
        return True
    
    def has_unique_size(self):
        return not self._ext and (self._ub == self._lb)
    
    def has_zero_size(self):
        return not self._ext and self._ub == 0
    
    def encode(self, arg):
        '''
        arg:
            unsigned integer (minimum number of bits, bit-aligned)
            or
            tuple (string, notation)
        
        notation:
            'S' string (byte-aligned)
            'H' hexadecimal (nibble-aligned)
            'B' binary (bit-aligned)
        '''
        # TODO: arg processing
        #
        self.elementList = []
        #
        # encode an integer value, or an octet-aligned string, 
        # to the BIT STRING
        if self.has_zero_size():
            pass
        #
        elif isinstance(arg, (int, long)) and arg >= 0:
            self._encode_int(arg)
        #
        elif isinstance(arg, tuple) and len(arg)==2:
            if arg[1] == 'S':
                self._encode_str(arg[0])
            elif arg[1] == 'H':
                self._encode_int(int(arg[0], 16))
            elif arg[1] == 'B':
                self._encode_int(int(arg[0], 2))
        #
        else:
            raise(ASN1_PER_ENCODER_ERR('invalid argument %s' % repr(val)))
        #
        if self._RET_STRUCT:
            return self
    
    def _encode_str(self, val):
        #
        bs_size = len(val)*8
        # encode any pre-stuff (extension, padding, length determinant)
        # according to the given size
        self._encode_pre(bs_size)
        #
        # add bit string value
        bs = Bit('Value', BitLen=bs_size, Repr=self._VAL_REPR)
        bs.map(val)
        bs.reautomatize()
        self.append( bs )
    
    def _encode_int(self, val):
        #
        # get size in bits required for val:
        bs_size = len(decomposer(2).decompose(val))
        # encode any pre-stuff (extension, padding, length determinant)
        # according to the given size
        self._encode_pre(bs_size)
        #
        # add bit string value
        self.append( 
            Bit('Value', Pt=val, BitLen=bs_size, Repr=self._VAL_REPR) )
    
    def _encode_pre(self, bs_size):
        #
        if bs_size > 64535:
            raise(ASN1_PER_ENCODER_ERR('value to long (%i): encoder does not '\
                  'support fragmentation (> 64k)' % bs_size))
        #
        elif not self._ub:
            # semi-constrained size
            # 1) add potential padding
            if self.VARIANT[0] == 'A':
                pad_len = (8 - (self._off%8)) % 8
                if pad_len:
                    self.append( ASN1_PER_P(BitLen=pad_len) )
            # 2) add length determinant (ASN1_PER_L)
            self.append( ASN1_PER_L(bs_size) )
        #
        elif isinstance(self._ub, (int, long)):
            if self.has_unique_size():
                if bs_size != self._lb:
                    raise(ASN1_PER_ENCODER_ERR('value with incorrect size (%i):'\
                          ' requires %i bits' % (bs_size, self._lb)))
                # 1) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
            #
            elif self._ext and bs_size > self._ub:
                # extended size
                # 1) add extensibility header
                e_off = 1
                self.append( ASN1_PER_E(Pt=1, BitLen=1) )
                # 2) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
                # 3) add length determinant (ASN1_PER_L)
                self.append( ASN1_PER_L(bs_size) )
            #
            else:
                # constrained size
                # 1) add potential extensibility header
                if self._ext:
                    e_off = 1
                    self.append( ASN1_PER_E(Pt=0, BitLen=1) )
                else:
                    e_off = 0
                # 2) add length determinant (ASN1_PER_INTEGER)
                l = ASN1_PER_INTEGER('SIZE', lb=self._lb, ub=self._ub)
                l._VAL_REPR = 'hum'
                # TODO: ensure this VARIANT / offset handling is correct
                l.VARIANT = self.VARIANT
                l._off = self._off + e_off
                l.encode(bs_size)
                self.append( l )
                # 3) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off+l.bit_len())%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        buf = self._decode(buf)
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf
    
    def _decode(self, buf=''):
        #
        if not self._ub:
            # semi-constrained size
            # 1) get potential padding
            if self.VARIANT[0] == 'A':
                pad_len = (8 - (self._off%8)) % 8
                if pad_len:
                    p = ASN1_PER_P(BitLen=pad_len)
                    buf = p.map_ret(buf)
                    self.append( p )
            # 2) get length determinant (ASN1_PER_L)
            l = ASN1_PER_L()
            buf = p.map_ret(buf)
            self.append( l )
            # 3) get value
            v = Bit('Value', BitLen=l(), Repr=self._VAL_REPR)
            buf = v.map_ret(buf)
            self.append(v)
            return buf
        #
        elif isinstance(self._ub, (int, long)):
            if self.has_unique_size():
                # 1) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
                # 2) get value
                v = Bit('Value', BitLen=self._lb, Repr=self._VAL_REPR)
                buf = v.map_ret(buf)
                self.append(v)
                return buf
            #
            elif self._ext:
                # 1) check if potentially extended
                e = ASN1_PER_E(BitLen=1)
                buf = e.map_ret(buf)
                self.append( e )
                e_off, e_ext = 1, e()
            else:
                e_off, e_ext = 0, 0
            #
            if e_ext:
                # extended size
                # 2) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
                # 3) get length determinant (ASN1_PER_L)
                l = ASN1_PER_L()
                buf = l.map_ret(buf)
                self.append( l )
            #
            else:
                # constrained size
                # 2) get length determinant (ASN1_PER_INTEGER)
                l = ASN1_PER_INTEGER('SIZE', lb=self._lb, ub=self._ub)
                l._RET_STRUCT = False
                l._VAL_REPR = 'hum'
                # TODO: ensure this VARIANT / offset handling is correct
                l.VARIANT = self.VARIANT
                l._off = self._off + e_off
                buf = l.decode(buf)
                self.append(l)
                # 3) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off+l.bit_len())%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
            # 4) get value
            v = Bit('Value', BitLen=l(), Repr=self._VAL_REPR)
            buf = v.map_ret(buf)
            self.append(v)
            return buf
    

    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the value of the ASN.1 BIT STRING object
        if self.has_zero_size():
            return 0
        elif hasattr(self, 'Value'):
            return self.Value()
            #return self.Value.__str__()
            #return self.Value.__hex__()
            #return self.Value.__bin__()
        else:
            return None

###
# OCTET STRING
###
class ASN1_PER_OCTET_STRING(ASN1_PER):
    '''
    ASN1 OCTET STRING
    specific attributes:
        - lb: lower bound, uint (default 0), for the SIZE
        - ub: upper bound, None or uint, for the SIZE
        - ext: SIZE extensibility, True / False
    
    .has_unique_size() -> bool, True in case of unique SIZE for the octet string
    .has_zero_size() -> bool, True in case of null octet string
    .encode( str | (str, notation) ), to encode an octet-aligned string, possibly
        precising the encoding notation ('S': string, 'H':hexa, 'B':binary)
    .decode(str) -> str, decode the buffer, returns the rest of the buffer 
                    that was not consumed
    '''
    #
    # ASN1 OCTET STRING attributes:
    # lower and upper bound of the SIZE attribute
    _lb = 0 # can be > 0
    _ub = None # or uint, semi or fully-constrained
    # extensibility
    _ext = False # False: no extensibility marker, True: extensibility marker
                 # e.g. SIZE(0..255, ...)
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._lb, (int, long)) or self._lb < 0:
            print('incorrect lb (%s) in %s' % (self._lb, self.__name__))
            return False
        if not isinstance(self._ub, (NoneType, int, long)):
            print('incorrect ub (%s) in %s' % (self._ub, self.__name__))
            return False
        if not isinstance(self._ext, bool):
            print('incorrect ext (%s) in %s' % (self._ext, self.__name__))
            return False
        if isinstance(self._ub, (int, long)) \
        and self._ub < self._lb:
            print('ub (%i) less than lb (%i) in %s' \
                   % (self._ub, self._lb, self.__name__))
            return False
        return True
    
    def has_unique_size(self):
        return not self._ext and (self._ub == self._lb)
    
    def has_zero_size(self):
        return not self._ext and self._ub == 0
    
    def encode(self, arg):
        '''
        arg:
            string (standard Python str)
            or
            tuple (string, notation)
        
        notation:
            'S' string (byte-aligned)
            'H' hexadecimal (must be byte-aligned)
            'B' binary (must be byte-aligned)
        '''
        #
        self.elementList = []
        #
        # encode a standard octet-aligned Python string, 
        # to the OCTET STRING
        if self.has_zero_size():
            if self._RET_STRUCT:
                return self
            return
        #
        if isinstance(arg, tuple) and len(arg) == 2 \
        and isinstance(arg[0], str):
            if arg[1] == 'H':
                # hexadecimal notation
                if len(arg[0]) % 2:
                    val = '%s0' % arg[0]
                val = val.decode('hex')
            elif arg[1] == 'B':
                # binary notation, kind of useless for OCTET STRING...
                if len(arg[0]) % 8:
                    val += '%s%s' % (arg[0], '0'*(8 - len(arg[0])%8))
                s = []
                for i in range(0, len(val), 8):
                    s.append( chr(int(val[i:i+8], 2)) )
                val = ''.join(s)
            else:
                val = arg[0]
        #
        elif isinstance(arg, str):
            # default to 'S' notation
            val = arg
        #
        else:
            raise(ASN1_PER_ENCODER_ERR('invalid argument %s' % repr(arg)))
        #
        os_size = len(val)
        # encode any pre-stuff (extension, padding, length determinant)
        # according to the given size
        self._encode_pre(os_size)
        #
        # add bit string value
        os = Str('Value', Pt=val, Len=os_size, Repr=self._VAL_REPR)
        self.append( os )
        #
        if self._RET_STRUCT:
            return self
    
    def _encode_pre(self, os_size):
        #
        if os_size > 64535:
            raise(ASN1_PER_ENCODER_ERR('value to long (%i): encoder does not '\
                  'support fragmentation (> 64k)' % os_size))
        #
        elif not self._ub:
            # semi-constrained size
            # 1) add potential padding
            if self.VARIANT[0] == 'A':
                pad_len = (8 - (self._off%8)) % 8
                if pad_len:
                    self.append( ASN1_PER_P(BitLen=pad_len) )
            # 2) add length determinant (ASN1_PER_L)
            self.append( ASN1_PER_L(os_size) )
        #
        elif isinstance(self._ub, (int, long)):
            if self.has_unique_size():
                if os_size != self._lb:
                    raise(ASN1_PER_ENCODER_ERR('value with incorrect size (%i):'\
                          ' requires %i bytes' % (os_size, self._lb)))
                # 1) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
            #
            elif self._ext and os_size > self._ub:
                # extended size
                # 1) add extensibility header
                e_off = 1
                self.append( ASN1_PER_E(Pt=1, BitLen=1) )
                # 2) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
                # 3) add length determinant (ASN1_PER_L)
                self.append( ASN1_PER_L(os_size) )
            #
            else:
                # constrained size
                # 1) add potential extensibility header
                if self._ext:
                    e_off = 1
                    self.append( ASN1_PER_E(Pt=0, BitLen=1) )
                else:
                    e_off = 0
                # 2) add length determinant (ASN1_PER_INTEGER)
                l = ASN1_PER_INTEGER('SIZE', lb=self._lb, ub=self._ub)
                l._VAL_REPR = 'hum'
                # TODO: ensure this VARIANT / offset handling is correct
                l.VARIANT = self.VARIANT
                l._off = self._off + e_off
                l.encode(os_size)
                self.append( l )
                # 3) add potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off+l.bit_len())%8) % 8
                    if pad_len:
                        self.append( ASN1_PER_P(BitLen=pad_len) )
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        buf_len = len(buf)
        #
        if not self._ub:
            # semi-constrained size
            # 1) get potential padding
            if self.VARIANT[0] == 'A':
                pad_len = (8 - (self._off%8)) % 8
                if pad_len:
                    p = ASN1_PER_P(BitLen=pad_len)
                    buf = p.map_ret(buf)
                    self.append( p )
            # 2) get length determinant (ASN1_PER_L)
            l = ASN1_PER_L()
            buf = p.map_ret(buf)
            self.append( l )
            # 3) get value
            v = Str('Value', Len=l(), Repr=self._VAL_REPR)
            buf = v.map_ret(buf[:buf_len-int(ceil(self.bit_len()/8.0))])
            self.append(v)
            return buf
        #
        elif isinstance(self._ub, (int, long)):
            if self.has_unique_size():
                # 1) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
                # 2) get value
                v = Str('Value', Len=self._lb, Repr=self._VAL_REPR)
                buf = v.map_ret(buf[:buf_len-int(ceil(self.bit_len()/8.0))])
                self.append(v)
                return buf
            #
            elif self._ext:
                # 1) check if potentially extended
                e = ASN1_PER_E(BitLen=1)
                buf = e.map_ret(buf)
                self.append( e )
                e_off, e_ext = 1, e()
            else:
                e_off, e_ext = 0, 0
            #
            if e_ext:
                # extended size
                # 2) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off)%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
                # 3) get length determinant (ASN1_PER_L)
                l = ASN1_PER_L()
                buf = l.map_ret(buf)
                self.append( l )
            #
            else:
                # constrained size
                # 2) get length determinant (ASN1_PER_INTEGER)
                l = ASN1_PER_INTEGER('SIZE', lb=self._lb, ub=self._ub)
                l._RET_STRUCT = False
                l._VAL_REPR = 'hum'
                # TODO: ensure this is correct
                l.VARIANT = self.VARIANT
                l._off = self._off + e_off
                buf = l.decode(buf)
                self.append(l)
                # 3) get potential padding
                if self.VARIANT[0] == 'A':
                    pad_len = (8 - (self._off+e_off+l.bit_len())%8) % 8
                    if pad_len:
                        p = ASN1_PER_P(BitLen=pad_len)
                        buf = p.map_ret(buf)
                        self.append( p )
            # 4) get value
            v = Str('Value', Len=l(), Repr=self._VAL_REPR)
            buf = v.map_ret(buf[:buf_len-int(ceil(self.bit_len()/8.0))])
            self.append(v)
        #
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf
    
    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the value of the ASN.1 BIT STRING object
        if self.has_zero_size():
            return 0
        elif hasattr(self, 'Value'):
            return self.Value()
            #return self.Value.__str__()
            #return self.Value.__hex__()
            #return self.Value.__bin__()
        else:
            return None

###
# Encapsulating objects: CHOICE, SEQUENCE, SEQUENCE OF, ...
###

###
# CHOICE
###
class ASN1_PER_CHOICE(ASN1_PER):
    '''
    ASN1 CHOICE
    specific attributes:
        - choice: ordered dictionnary (OD) of string:ASN1_PER types,
                  to be chosen from
        - ext: None or ordered dictionnary of string:ASN1_PER types,
               extended ASN1_PER choices
    
    .get_range() -> uint or None, number of choices in choice
    .get_range_ext() -> uint or None, number of extended choices in ext
                       (independent from choice)
    .has_single_val() -> bool, True in case of single choice with no extension
    .has_no_val() -> bool, True in case there is an empty choice
    .encode( (str, val) ), to encode an ASN1_PER instance according to a tuple
        containing its token (str) and given value to encode (val)
    .decode(str) -> str, decode the buffer, returns the rest of the buffer 
                    that was not consumed
    '''
    #
    # ASN1 CHOICE attributes:
    # ordered dictionnary of choices (aSN1_PER_tok : ASN1_PER_object)
    _choice = OD() # OD([('aSN1_PER_tok1', ASN1_PER_obj1), 
                   #     ('aSN1_PER_tok2', ASN1_PER_obj2),
                   #     ('aSN1_PER_tok3', ASN1_PER_obj3), ...])
    # lower and upper bounds of the choice index are deduced from ._choice
    #
    # extensibility
    _ext = None # None: no extensibility marker,
                # OD([('aSN1_PER_tok5', ASN1_PER_obj5), ...]) new extended choices 
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._choice, OD):
            print('incorrect choice in %s' % self.__name__)
            return False
        elif not all([isinstance(t[0], str) and issubclass(t[1], ASN1_PER) \
                       for t in self._choice.items()]):
            print('incorrect item in choice in %s' % self.__name__)
            return False
        elif not isinstance(self._ext, (NoneType, OD)):
            print('incorrect ext in %s' % self.__name__)
            return False
        elif isinstance(self._ext, list) \
        and not all([isinstance(t[0], str) and issubclass(t[1], ASN1_PER) \
                      for t in self._ext.items()]):
            print('incorrect item in ext in %s' % self.__name__)
            return False
        return True
    
    def get_range(self):
        return len(self._choice)
    
    def get_range_ext(self):
        if self._ext: return len(self._ext)
        else: return 0
    
    def has_single_val(self):
        return not self._ext and self.get_range() == 1
    
    def has_no_val(self):
        return not self._ext and self.get_range() == 0
    
    def encode(self, tup):
        '''
        arg: tuple (token, value)
        token: string as from _choice / _ext
        value: arg to be passed to the ASN.1 object instantiated 
               corresponding to the token, for encoding
        '''
        #
        self.elementList = []
        #
        if self.has_no_val():
            # empty CHOICE structure, who knows ?!...
            pass
        #
        elif isinstance(tup, tuple):
            tok = tup[0]
            val = tup[1]
            # 1) try to get the index within the root choices or 
            #    extended choices
            ind, root = self._get_index(tok), True
            if self._ext:
                e_off = 1
                if ind == -1:
                    ind = self._get_index(tok, ext=True)
                    if ind >= 0:
                        root = False
                        self.append( ASN1_PER_E(Pt=1, BitLen=1) )
                else:
                    self.append( ASN1_PER_E(Pt=0, BitLen=1) )
            else:
                e_off = 0
            #
            if ind == -1:
                raise(ASN1_PER_ENCODER_ERR('token %s is not a valid choice'\
                       % tok))
                # this prevents continuing with an invalid index
            #
            # 2) if val is in the root, val index is encoded as a 
            #    constrained integer
            if root:
                c = ASN1_PER_INTEGER('CHOICE', lb=0, ub=self.get_range())
                c._VAL_REPR = 'hum'
                # TODO: ensure this VARIANT / offset handling is correct
                c.VARIANT = self.VARIANT
                c._off = self._off + e_off
                c.encode(ind)
                c.Value.Dict = self._build_dict(ext=False)
                self.append(c)
                c_off = c.bit_len()
                #
                inst = self._choice[tok](tok)
            #
            # 3) otherwise, extended choice index is encoded as a 
            #    normally small value
            # TODO: unsure this kind of encoding is valid for CHOICE extension
            else:
                _range = self.get_range_ext()
                if _range >= 64:
                    raise(ASN1_PER_ENCODER_ERR('extended CHOICE index (%i) over'\
                          ' the encoder limit (63)' % _range))
                #
                self.append( ASN1_PER_NSVAL(ind) )
                self[-1].Value.Dict = self._build_dict(ext=True)
                c_off = 7
                #
                inst = self._ext[tok](tok)
            #
            # 4) add potential padding
            if self.VARIANT[0] == 'A':
                pad_len = (8 - (self._off+e_off+c_off)%8) % 8
                if pad_len:
                    self.append( ASN1_PER_P(BitLen=pad_len) )
            #
            # 5) encode the right instance with the given value
            inst._off = self._off + e_off + c_off
            inst.encode(val)
            self.append(inst)
        #
        else:
            raise(ASN1_PER_ENCODER_ERR('invalid argument %s' % repr(tup)))
        #
        if self._RET_STRUCT:
            return self
    
    def _get_index(self, tok, ext=False):
        if ext: 
            if self._ext: L = self._ext.keys()
            else: L = []
        else:
            L = self._choice.keys()
        #
        try:
            ind = L.index(tok)
        except ValueError:
            ind = -1
        return ind
    
    def _build_dict(self, ext=False):
        d = {}
        if ext:
            for i in range(self.get_range_ext()):
                d[i] = self._ext.keys()[i][0]
        else:
            for i in range(self.get_range()):
                d[i] = self._choice.keys()[i][0]
        return d
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        if not buf and not self.has_no_val():
            raise(ASN1_PER_DECODER_ERR('no buffer provided for decoding'))
        #
        # 1) check for extensibility
        e, e_off = None, 0
        if self._ext:
            e_off = 1
            e = ASN1_PER_E(BitLen=1)
            buf = e.map_ret(buf)
            self.append(e)
        #
        # 2) if extended, decode index as normally small value
        if e and e():
            _range = self.get_range_ext()
            if _range >= 64:
                raise(ASN1_PER_DECODER_ERR('extended CHOICE index (%i) over'\
                      ' the encoder limit (63)' % _range))
            c = ASN1_PER_NSVAL()
            buf = c.map_ret(buf)
            c.Value.Dict = self._build_dict(ext=True)
            self.append(c)
            #
            if c() >= len(self._ext):
                raise(ASN1_PER_DECODER_ERR('extended CHOICE invalid index %i'\
                      % c()))
            #
            tok = self._ext.keys()[c()]
            inst = self._ext[tok](tok)
        #
        # 3) otherwise, decode as constrained integer
        else:
            _range = self.get_range()
            c = ASN1_PER_INTEGER('CHOICE', lb=0, ub=self.get_range())
            c._VAL_REPR = 'hum'
            # TODO: ensure this VARIANT / offset handling is correct
            c.VARIANT = self.VARIANT
            c._off = self._off + e_off # not sure this is needed
            buf = c.decode(buf)
            c.Value.Dict = self._build_dict(ext=False)
            self.append(c)
            #
            if c() >= len(self._choice):
                raise(ASN1_PER_DECODER_ERR('CHOICE invalid index %i' % c()))
            #
            tok = self._choice.keys()[c()]
            inst = self._choice[tok](tok)
        # 
        buf = obj.decode(inst)
        self.append( inst )
        #
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf
    
    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the value of the ASN.1 CHOICE object encoded
        if self.elementList and isinstance(self[-1], ASN1_PER):
            return self[-1]()
        else:
            return None

###
# SEQUENCE
###
class ASN1_PER_SEQUENCE(ASN1_PER):
    '''
    ASN1 SEQUENCE
    specific attributes:
        - seq: ordered dictionnary (OD) of string:ASN1_PER types, to be sequenced
        - ext: None or ordered dictionnary of string:ASN1_PER types, extending 
               the sequence
    
    .get_range() -> uint or None, number of objects in the sequence
    .get_range_ext() -> uint or None, number of objects in the extended sequence
    .has_single_val() -> bool, True in case of single object with no extension
    .has_no_val() -> bool, True in case this is an empty sequence
    .encode( [(str1, val1), (str2, val2), ...] ), to encode all ASN1_PER instances
        according to a list containing their token (str) and given value (val)
        to encode
    .decode(str) -> str, decode the buffer, returns the rest of the buffer 
                    that was not consumed
    '''
    #
    # ASN1 SEQUENCE attributes:
    # ordered list of tuples: ASN1 PER objects, presence code[, default value]
    # presence code:
    #   0: always there
    #   1: OPTIONAL
    #   2: DEFAULT, in this case, a default value is appended (3-tuple)
    _behav_code = {0:'always', 1:'OPTIONAL', 2:'DEFAULT'}
    _behav_code_rev = {'always':0, 'OPTIONAL':1, 'DEFAULT':2}
    #
    _seq = OD() # OD([(aSN1_PER_tok1, (ASN1_PER_obj1, 0)),
                #     (aSN1_PER_tok2, (ASN1_PER_obj2, 0)),
                #     (aSN1_PER_tok3, (ASN1_PER_obj3, 1)), 
                #     (aSN1_PER_tok4, (ASN1_PER_OBJ4, 2, 20)), ...])
    # lower and upper bounds of the sequence index are deduced from ._seq
    #
    # extensibility
    _ext = None # None: no extensibility marker,
                # OD([(aSN1_PER_tok6, (ASN1_PER_obj6, 0)), 
                #     (aSN1_PER_tok7, (ASN1_PER_obj7, 1)), ...]) new extended values 
    #
    #
    ###
    # specific ASN1_PER methods
    ###
    def check_constraints(self):
        if not isinstance(self._seq, OD):
            print('incorrect sequence in %s' % self.__name__)
            return False
        elif not all([isinstance(t[0], str) and isinstance(t[1], tuple) and \
                       issubclass(t[1][0], ASN1_PER) and isinstance(t[1][1], int) \
                       for t in self._seq.items()]):
            print('incorrect item in sequence in %s' % self.__name__)
            return False
        elif not isinstance(self._ext, (NoneType, OD)):
            print('incorrect ext in %s' % self.__name__)
            return False
        elif isinstance(self._ext, OD) \
        and not all([isinstance(t[0], str) and isinstance(t[1], tuple) and \
                      issubclass(t[1][0], ASN1_PER) and isinstance(t[1][1], int) \
                      for t in self._ext.items()]):
            print('incorrect item in ext in %s' % self.__name__)
            return False
        return True
    
    def get_range(self):
        return len(self._seq)
    
    def get_range_ext(self):
        if self._ext: return len(self._ext)
        else: return 0
    
    def has_single_val(self):
        return not self._ext and self.get_range() == 1
    
    def has_no_val(self):
        return not self._ext and self.get_range() == 0
    
    def encode(self, li):
        '''
        arg: list / tuple of tuples (token, value)
        token: string as from _seq / _ext
        value: arg to be passed to the ASN.1 object instantiated 
               corresponding to the token, for encoding
        '''
        #
        self.elementList = []
        #
        if self.has_no_val():
            # empty SEQUENCE structure, who knows ?!...
            if self._RET_STRUCT:
                return self
            return
        #
        if self._SAFE:
            # this check can requires some processing...
            if not isinstance(li, (tuple, list)) \
            or not all([isinstance(t, tuple) for t in li]):
                raise(ASN1_PER_ENCODER_ERR('invalid argument: %s' % repr(li)))
        #
        # we maintain a cached list of tuples (ASN1_PER_obj, value) that
        # need to be encoded, so we are able at the end to encode everything
        # properly with correct bit offsets (extension, bitmap, ...)
        self._cached_obj_init()
        self._bitmap_init()
        #
        ind = 0
        seq_toks = self._seq.keys()
        arg_toks = [t[0] for t in li]
        arg_toks_len = len(arg_toks)
        arg_vals = [t[1] for t in li]
        #
        for tok in seq_toks:
            # for each token in the SEQUENCE
            # 1) if we have it passed as argument
            if ind < arg_toks_len and tok == arg_toks[ind]:
                # ensures the arg passed for its encoding is not equal to DEFAULT
                # WARNING: the 2nd check does not work for complex ASN.1 object
                # (but will also fail in certain case for basic object... 
                # that's life :)
                # That's not CANONICAL in any way :)
                if self._seq[tok][1] == 2 and args_vals[ind] == self._seq[tok][2]:
                    self._bitmap_zero()
                else:
                    # instantiate it in the cached objects list
                    self.__co.append( self._seq[tok][0](tok)  )
                    # create a temporary attribute to store its value to be encoded
                    self.__co[-1]._val_enc = arg_vals[ind]
                    # in case of OPTIONAL or DEFAULT, add a bitmap bit to 1
                    if self._seq[tok][1] in (1, 2):
                        self._bitmap_one()
                    # increase the index through argument tokens
                    ind += 1
            #
            # 2) if not passed as argument, and the object has OPTIONAL or 
            # DEFAULT behavior
            elif self._seq[tok][1] in (1, 2):
                # simply add a bitmap to 0
                self._bitmap_zero()
            #
            # 3) otherwise there is a missing token in the encoding argument
            else:
                raise(ASN1_PER_ENCODER_ERR('missing token %s' % tok))
        #
        if self._ext:
            ext_toks = self._ext.keys()
            self.__co.insert(0, ASN1_PER_E(Pt=0, BitLen=1))
            #
            for tok in ext_toks:
                if ind < arg_toks_len and tok == arg_toks[ind]:
                    raise(ASN1_PER_ENCODER_ERR('SEQUENCE extension encoding not'\
                                                ' implemented'))
                    #ind += 1
        #
        # 4) After having iterated over each tokens from the SEQUENCE definition
        # just needs to encode it thanks to its cached objects list
        self._cached_obj_encode()
        # TODO: some clean up
        #del self.__bm, self.__co
        #
        if self._RET_STRUCT:
            return self
    
    def _bitmap_init(self):
        self.__bm = ASN1_PER_B(BitLen=0)
        self.__co.append( self.__bm )
    
    def _bitmap_zero(self):
        self.__bm.BitLen += 1
        if self.__bm.Pt is None:
            self.__bm.Pt = 0
        else:
            self.__bm.Pt <<= 1
    
    def _bitmap_one(self):
        self.__bm.BitLen += 1
        if self.__bm.Pt is None:
            self.__bm.Pt = 1
        else:
            self.__bm.Pt <<= 1
            self.__bm.Pt += 1
    
    def _cached_obj_init(self):
        self.__co = []
    
    def _cached_obj_encode(self):
        # encode each object from the cache list
        _off = self._off
        for obj in self.__co:
            if hasattr(obj, '_val_enc'):
                obj.VARIANT = self.VARIANT
                obj._off = _off
                obj.encode( obj._val_enc )
                # TODO: maybe some clean up
                #del obj._val_enc
                _off += obj.bit_len()
            else:
                _off += obj.bit_len()
            self.append( obj )
    
    def decode(self, buf=''):
        #
        self.elementList = []
        #
        if not buf and not self.has_no_val():
            raise(ASN1_PER_DECODER_ERR('no buffer provided for decoding'))
        #
        elif self.has_no_val():
            # empty SEQUENCE structure, who knows ?!...
            if self._RET_STRUCT:
                return buf, self
            return buf
        #
        # 1) check for extensibility
        e, e_off = None, 0
        if self._ext:
            e_off = 1
            e = ASN1_PER_E(BitLen=1)
            buf = e.map_ret(buf)
            self.append(e)
        #
        if e and e():
            raise(ASN1_PER_DECODER_ERR('SEQUENCE extension decoding not '\
                                        'implemented'))
        #
        # 2) get the bitmap for OPTIONAL and DEFAULT objects
        # -> count them first
        b_off = self._bitmap_count()
        if b_off:
            bm = ASN1_PER_B(BitLen=b_off)
            buf = bm.map_ret(buf)
            self.append(bm)
        #
        # 3) iterate over self._seq, excluding those hat have a bitmap flag 0
        obj_off = 0
        bm_ind = 0
        bm_val = bm.__bin__()
        for tok in self._seq:
            if self._seq[tok][1] == 0:
                # mandatory object
                inst = self._seq[tok][0](tok)
            #
            else:
                # OPTIONAL or DEFAULT object
                if int(bm_val[bm_ind]):
                    # if bitmap bit is 1
                    inst = self._seq[tok][0](tok)
                else:
                    inst = None
                bm_ind += 1
            #
            #print tok, bm_ind, type(inst)
            if inst is not None:
                # take care of the bit offset
                inst.VARIANT = self.VARIANT
                inst._off = self._off + e_off + b_off
                # decode the object instance
                _rs = inst._RET_STRUCT
                inst._RET_STRUCT = False
                buf = inst.decode(buf)
                inst._RET_STRUCT = _rs
                # increment the bit offset
                obj_off += inst.bit_len()
                #
                self.append(inst)
                inst = None
        #
        if self._RET_STRUCT:
            return buf, self
        else:
            return buf
    
    def _bitmap_count(self):
        c = 0
        for tok in self._seq:
            if self._seq[tok][1] != 0:
                c += 1
        return c
    
    ###
    # overcharging standard Layer methods
    ###
    def __call__(self):
        # returns the string for all ASN1 PER instances sequentially encoded
        if self.elementList:
            #return self.__hex__()
            return self.__str__()
        else:
            return None
    
    def __repr__(self):
        # it would be better to represent all internal object name : values
        return '<%s: %s>' % (self.CallName, self.__hex__())

###
# SEQUENCE OF
###
class ASN1_PER_SEQUENCE_OF(ASN1_PER):
    pass


###
# generating few test-cases objects
###
def gen_test():
    
    class A(ASN1_PER_INTEGER):
        _lb = -64
        _ub = 128000
        _ext = True
    
    class B(ASN1_PER_ENUMERATED):
        _enum = OD([(0, 'yellow'), (1, 'green'), (2, 'blue')])
        _ext = OD([(0, 'red'), (1, 'orange')])
    
    class C(ASN1_PER_BIT_STRING):
        _ub = 250
        _ext = True
    
    class D(ASN1_PER_OCTET_STRING):
        _ub = 150
    
    class E(ASN1_PER_CHOICE):
        _choice = OD([('a', A), ('b', B), ('c', C)])
        _ext = OD([('d',D)])
    
    class F(ASN1_PER_SEQUENCE):
        _seq = OD([('a', (A, 0)),
                   ('b', (B, 1)),
                   ('c', (C, 2, ('0110', 'B')))])
    
    class G(ASN1_PER_SEQUENCE):
        _seq = OD([('item-code', (ASN1_PER_INTEGER, 0)),
                   ('item-name', (ASN1_PER_OCTET_STRING, 1)),
                   ('urgency', (ASN1_PER_ENUMERATED, 2, 'normal'))])
    
    G._seq['item-code'][0]._lb = 0
    G._seq['item-code'][0]._ub = 254
    G._seq['item-name'][0]._lb = 3
    G._seq['item-name'][0]._ub = 10
    G._seq['urgency'][0]._enum = OD([(0, 'normal'), (1, 'high')])
    
    return A, B, C, D, E, F, G
#