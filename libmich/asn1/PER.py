# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.3
# *
# * Copyright © 2014. Benoit Michau. ANSSI.
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
# * File Name : asn1/CODEC_PER.py
# * Created : 2014-09-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# export filter
__all__ = ['PER']

from types import NoneType
#
from libmich.core.element import Str, Int, Bit, Layer, show
from libmich.core.shtr import shtr
from libmich.core.shar import shar
from libmich.utils.IntEncoder import *
#
import ASN1
from utils import *

class ASN1_PER_ENCODER(ASN1_CODEC): pass
class ASN1_PER_DECODER(ASN1_CODEC): pass

################################################################################
# For each ASN.1 object that we want to encode / decode with PER, we can have:
# - preamble
#   -> bitmap for optional element, e.g. in a SEQUENCE
#   -> extension bit, e.g. in an INTEGER with extensible bounds
# - length / count determinant (depending of constraints)
# - padding, only in the octet-aligned variant
# - encoded content / value or encapsulated object
#
# Each of which depends of the basic type and associated constraints
# Constraints are generally of type:
# - lower bound / upper bound
# - number of enumeration / choice
# - size (in byte, in bit -for BIT STRING-, or in count of components, 
#   for SEQUENCE or CHOICE)
#
# WARNING: several limitations exists in this implementation
# - there is no handling of object with size > 64k
#   so there is no handling of fragmentation / reassembling for large values
# - there is no support of unconstrained / semi-constrained INTEGER which 
#   encodes over 64 bits
# - there is no handling of ENUMERATION with more than 255 root values 
# - there is no handling of specified alphabet for STRING (FROM("xyz")) objects
################################################################################
# few PER internal structures / naming which are useful:
# L: length determinant
# NSVAL: normally small values
# P: padding bits (mainly for the PER octet-aligned variant)
# E: extensibility marker
# B: bitmap for optional elements
# C: content (the value itself of an assigned-type)
################################################################################

#------------------------------------------------------------------------------#
# PER-specific internal objects for encoding / decoding different types
#------------------------------------------------------------------------------#
# Length determinant
_LUndef_dict = {0:'16K', 1:'32K', 2:'48K', 3:'64K'}
class _PER_L(Layer):
    # actually, this length determinant shall always be byte-aligned
    _byte_aligned = True
    constructorList = [
        Bit('Form', Pt=0, BitLen=1, Repr='bin', Dict={0:'short', 1:'long'}),
        Bit('Count', Pt=0, BitLen=7, Repr='bin')
        ]
    
    def __init__(self, *args, **kwargs):
        if 'Repr' in kwargs:
            self._Repr = kwargs['Repr']
        else:
            self._Repr = None
        Layer.__init__(self, CallName='L', **kwargs)
        if len(args) and isinstance(args[0], (int, long)):
            self.encode(args[0])
    
    def encode(self, count=0):
        self.__init__(self.CallName)
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
            raise(ASN1_PER_ENCODER('max length is for 16/32/48/64K '\
                                        'fragments'))
    
    def __call__(self):
        if self.Form() == 0 or self.Undef() == 0:
            return self.Count()
        else:
            return self.Count() * 16384
    
    def __repr__(self):
        if self._Repr:
            for e in self:
                e.Repr = self._Repr
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
    
    def map_ret_(self, s):
        if not s:
            return
        # reinit to the basic representation 
        self.__init__()
        # get the Form bit
        s_0 = s.to_uint(8)
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
        return Layer.map_ret(self, s)

# "Normally small" values
# to be used for unbounded length determinant expected to be small...
# e.g. for ENUMERATED extension
class _PER_NSVAL(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('Sig', Pt=0, BitLen=1, Repr='bin'), # this should always stay 0
        Bit('Value', Pt=0, BitLen=6, Repr='bin', Dict={}) # 0 to 63
        ]
    
    def __init__(self, *args, **kwargs):
        if 'Repr' in kwargs:
            self._Repr = kwargs['Repr']
        else:
            self._Repr = None
        if len(args) and isinstance(args[0], str):
            cn = args[0]
        else:
            cn = 'L'
        Layer.__init__(self, CallName=cn, **kwargs)
        #
        val = -1
        if len(args) > 1 and isinstance(args[1], (int, long)):
            val = args[1]
        #
        if 0 <= val <= 63:
            self.Value > val
        elif val > 63:
            # TODO: verify this
            self.Sig > 1
            self.remove(self[-1])
            Value = ASN1.ASN1Obj(name='Value', type=TYPE_INTEGER)
            Value.const.append({'type':CONST_VAL_RANGE, 
                                'lb':0, 'ub':None, 'ext':False})
            Value._encode(val)
            self.extend(Value._msg)
    
    def __call__(self):
        return self.Value()
    
    def __repr__(self):
        if self._Repr:
            for e in self:
                e.Repr = self._Repr
        return repr(self.Value)
    
    def map_ret(self, s=''):
        if not s:
            return ''
        # reinit to the basic representation 
        self.__init__()
        # get the Form bit
        Sig = ord(s[0])>>7
        # Sig = 0, small value: do not change anything
        if Sig == 0:
            return Layer.map_ret(self, s)
        # Sig = 1, not that small value: semi-constrained INTEGER
        self.Sig < 1
        self.remove(self[-1])
        s = shtr(s) << 1
        Value = ASN1.ASN1Obj(name='Value', type=TYPE_INTEGER)
        Value.const.append({'type':CONST_VAL_RANGE, 
                            'lb':0, 'ub':None, 'ext':False})
        s = Value.decode(s)
        self.append(Value._msg)
        return s
    
    def map(self, s=''):
        self.map_ret(s)
    
    def map_ret_(self, s):
        if not s:
            return s
        # reinit to the basic representation 
        self.__init__()
        # get the Form bit
        Sig = s.to_uint(1)
        # Sig = 0, small value: do not change anything
        if Sig == 0:
            return Layer.map_ret(self, s)
        # Sig = 1, not that small value: semi-constrained INTEGER
        self.Sig < 1
        s._cur += 1
        self.remove(self[-1])
        Value = ASN1.ASN1Obj(name='Value', type=TYPE_INTEGER)
        Value.const.append({'type':CONST_VAL_RANGE, 
                            'lb':0, 'ub':None, 'ext':False})
        s = Value.decode(s)
        self.append(Value._msg)
        return s
    
#------------------------------------------------------------------------------#
# PER encoder / decoder
#------------------------------------------------------------------------------#

class PER(ASN1.ASN1Codec):
    _shar = True
    #
    # used by ASN1Obj types
    _name = 'PER'
    _enc_err = ASN1_PER_ENCODER
    _dec_err = ASN1_PER_DECODER
    #
    # add some costly verification when decoding buffers
    _SAFE = True
    #
    # PER variant:
    VARIANT = 'A' # 'A': aligned, 'U': unaligned
    #
    # offset (in bits), for adding padding bits during encoding / decoding
    # only used in the octet-aligned variant
    _off = 0
    #
    # CODEC customizations:
    # to build dictionnary for encoded ENUMERATED, CHOICE, ...
    _ENUM_BUILD_DICT = True
    #
    # libmich layers' representation (only for basic types)
    _REPR_P = 'bin' # padding
    _REPR_E = 'bin' # extensibility
    _REPR_B = 'bin' # bitmap for options
    _REPR_L = 'bin' # length determinant
    _REPR_NSVAL = 'bin' # normally small value
    _REPR_BOOL = 'hum'
    _REPR_INT = 'hum'
    _REPR_ENUM = 'hum'
    _REPR_BIT_STR = 'hex'
    _REPR_OCT_STR = 'hex'
    _REPR_PRINT_STR = 'hum'
    
    def is_aligned(self):
        if self.VARIANT[:1] == 'A': return True
        else: return False
    
    #--------------------------------------------------------------------------#
    # encoder
    #--------------------------------------------------------------------------#
    def encode(self, obj, **kwargs):
        # propagate bit offset for recursive encoding
        self._off = 0
        if 'offset' in kwargs:
            self._off = kwargs['offset']
        #
        # call the appropriate type encoder
        if obj._type == TYPE_NULL:
            self.encode_null(obj)
        elif obj._type == TYPE_BOOL:
            self.encode_bool(obj)
        elif obj._type == TYPE_INTEGER:
            self.encode_int(obj)
        elif obj._type == TYPE_ENUM:
            self.encode_enum(obj)
        elif obj._type == TYPE_BIT_STR:
            self.encode_bit_str(obj)
        elif obj._type in (TYPE_OCTET_STR, TYPE_IA5_STR, TYPE_PRINT_STR):
            self.encode_oct_str(obj)
        elif obj._type == TYPE_CHOICE:
            self.encode_choice(obj)
        elif obj._type == TYPE_SEQ:
            self.encode_seq(obj)
        elif obj._type == TYPE_SEQ_OF:
            self.encode_seq_of(obj)
        elif obj._type in (TYPE_ANY, TYPE_OPEN):
            self.encode_open_type(obj)
        else:
            raise(ASN1_PER_ENCODER('%s: unsupported ASN.1 type: %s'\
                  % (obj.get_fullname(), obj._type)))
    
    #--------------------------------------------------------------------------#
    # PER prefixes
    #--------------------------------------------------------------------------#
    # Padding (for octet-aligned variant exclusively)
    def _add_P(self, obj, pad_len=None):
        if pad_len is None:
            pad_len = (8 - self._off%8) % 8
        if pad_len:
            obj._msg.append(Bit('P', Pt=0, BitLen=pad_len, Repr=self._REPR_P))
            self._off += pad_len
    
    # Extensibility marker
    def _add_E(self, obj):
        obj._msg.append(Bit('E', Pt=0, BitLen=1, Repr=self._REPR_E))
        self._off += 1
    
    #--------------------------------------------------------------------------#
    # NULL / BOOLEAN
    #--------------------------------------------------------------------------#
    def encode_null(self, obj):
        obj._msg.elementList = []
    
    def encode_bool(self, obj):
        # obj._val: True / False
        obj._msg.elementList = []
        obj._msg.append(Bit('C', Pt=(0,1)[obj._val], BitLen=1, 
                            Dict={0:'FALSE', 1:'TRUE'}, 
                            Repr=self._REPR_BOOL) )
        self._off += 1
    
    #--------------------------------------------------------------------------#
    # INTEGER
    #--------------------------------------------------------------------------#
    def encode_int(self, obj):
        # obj._val: integer
        # 1) get INTEGER constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) encode potential extensibility marker
        if ext:
            self._add_E(obj)
        #
        # 3) no lower bound
        if lb is None:
            # 3.a) no upper bound
            # check possible overflow
            if ub is not None and obj._val > ub:
                # if INTEGER is extensible, this works
                if ext:
                    obj._msg.E > 1
                    self._encode_int_unconst(obj, obj._val)
                    return
                else:
                    raise(ASN1_PER_ENCODER('%s: overflowing value %i' \
                          % (obj.get_fullname(), obj._val)))
            # 3.b) no bounds at all
            else:
                self._encode_int_unconst(obj, obj._val)
                return
        #
        # 4) lower bound provided and underflow
        if obj._val < lb:
            # if INTEGER is extensible, this works
            if ext:
                obj._msg.E > 1
                self._encode_int_unconst(obj, obj._val)
                return
            # this is handled by ASN1Obj._val_in_const()
            # with ASN1Obj._SAFE set to True
            #else:
            #    raise(ASN1_PER_ENCODER('%s: underflowing value %i' \
            #          % (obj.get_fullname(), obj._val)))
        #
        # 5) no upper bound: semi-constrained
        if ub is None:
            # encode the offset to the lower bound, like an unconstrained
            self._encode_int_semiconst(obj, obj._val-lb)
            return
        #
        # 6) both lower / upper bounds: fully constrained
        # get integer value range
        ra = ub - lb + 1
        if ra == 1:
            # only a single value
            if obj._val == lb:
                # no encoding needed
                return
            # excepted if INTEGER is extensible
            elif ext:
                obj._msg.E > 1
                self._encode_int_unconst(obj, obj._val)
                return
            # this is handled by ASN1Obj._val_in_const()
            # with ASN1Obj._SAFE set to True
            #raise(ASN1_PER_ENCODER('%s: invalid value %i' \
            #      % (obj.get_fullname(), obj._val)))
        #
        # if INTEGER needs to be extended anyway
        if obj._val > ub:
            if ext:
                obj._msg.E > 1
                self._encode_int_unconst(obj, obj._val)
                return
            # this is handled by ASN1Obj._val_in_const()
            # with ASN1Obj._SAFE set to True
            #else:
            #    raise(ASN1_PER_ENCODER('%s: overflowing value %i' \
            #          % (obj.get_fullname(), obj._val)))
        #
        # standard constrained encoding (finally)
        if self.is_aligned():
            self._encode_int_const_align(obj, obj._val-lb, ra)
        else:
            self._encode_int_minbits(obj, obj._val-lb, ra)
    
    def _encode_int_unconst(self, obj, val):
        # unconstrained integer:
        # length determinant + minimum octets signed number (2'complement)
        # TODO: support unconstrained integer over 64 bits
        #
        if not -2**63 <= val < 2**63:
            raise(ASN1_PER_ENCODER('%s: unconstrained integer value %i '\
                  'over encoder limit (64 bit)' % (obj.get_fullname(), val)))
        #
        # 1) add padding for the aligned variant
        if self.is_aligned():
            self._add_P(obj)
        #
        # 2) add the length determinant according to the number of bytes needed 
        int_dyn, int_type = minenc_int(val)
        obj._msg.append(_PER_L(int_dyn, Repr=self._REPR_L))
        # because of the 64bit limitation, _PER_L is always 1 byte
        self._off += 8
        #
        # 3) add encoded value
        obj._msg.append(Int('C', Pt=val, Type=int_type, Repr=self._REPR_INT))
        self._off += int_dyn * 8
    
    def _encode_int_semiconst(self, obj, val):
        # handling of semi-constrained is identical to unconstrained,
        # but with only unsigned integer values:
        # length determinant + minimum octets unsigned number
        # TODO: support semi-constrained integer over 64 bits
        #
        if not 0 <= val < 2**64:
            raise(ASN1_PER_ENCODER('%s: semi-constrained integer value %i '\
                  'over encoder limit (64 bit)' % (obj.get_fullname(), val)))
        #
        # 1) add padding for the aligned variant
        if self.is_aligned():
            self._add_P(obj)
        #
        # 2) add the length determinant according to the bytes needed 
        int_dyn, int_type = minenc_uint(val)
        obj._msg.append(_PER_L(int_dyn, Repr=self._REPR_L))
        # because of the 64bit limitation, L is always 1 byte
        self._off += 8
        #
        # 3) add encoded value
        obj._msg.append(Int('C', Pt=val, Type=int_type, Repr=self._REPR_INT))
        self._off += int_dyn * 8
    
    def _encode_int_const_align(self, obj, val, ra):
        # format depends on the range between bounds (ra):
        # 1) for 1 byte dynamic
        if ra <= 255:
            # short integer always encode in the minimum number of bits,
            # whatever PER variant
            self._encode_int_minbits(obj, val, ra)
            return
        #
        # 2) for 2 bytes dynamic
        if 256 <= ra <= 65536:
            # 2a) add padding
            self._add_P(obj)
            #
            # 2b) add value with minimal byte-encoding
            if ra == 256:
                obj._msg.append(Bit('C', Pt=val, BitLen=8, Repr=self._REPR_INT))
                self._off += 8
                return
            #
            obj._msg.append(Bit('C', Pt=val, BitLen=16, Repr=self._REPR_INT))
            self._off += 16
            return
        #
        # 3) for greater dynamic
        # 3a) add custom length determinant (uint value encoded in the
        # minimum number of bytes)
        # dyn_ra: number of bits required to describe the length in 
        # bytes of the maximum value that could be encoded
        dyn_ra = len_bits(len_bytes(ra))
        # dyn_val: number of bytes required to encode the given value
        dyn_val = len_bytes(val)
        obj._msg.append(Bit('L', Pt=dyn_val-1, BitLen=dyn_ra, Repr=self._REPR_L))
        self._off += dyn_ra
        #
        # 3b) add padding
        self._add_P(obj)
        #
        # 3c) encode value
        obj._msg.append(Bit('C', Pt=val, BitLen=dyn_val*8, Repr=self._REPR_INT))
        self._off += dyn_val * 8
    
    def _encode_int_minbits(self, obj, val, ra):
        # encoding in the minimum bumber of bits
        dyn_ra = len_bits(ra-1)
        obj._msg.append(Bit('C', Pt=val, BitLen=dyn_ra, Repr=self._REPR_INT))
        self._off += dyn_ra
    
    #--------------------------------------------------------------------------#
    # ENUMERATION
    #--------------------------------------------------------------------------#
    def encode_enum(self, obj):
        # obj._val: identifier (string)
        # TODO: support large number of enum (> 255) in the root
        #
        # 1) encode potential extensibility marker
        if obj._ext is not None:
            self._add_E(obj)
            # check if value to encode is in the extension (_ext)
            if obj._val in obj._ext:
                # 2) if value is in the extension
                obj._msg.E > 1
                # encoding with Normally Small Value (7 bits, no padding)
                # value is the index (starting from 0) of the identifier assigned,
                # without using its explicit tagging
                c = _PER_NSVAL('C', obj._ext.index(obj._val), 
                                   Repr=self._REPR_ENUM)
                if self._ENUM_BUILD_DICT:
                    c[-1].Dict = dict(zip(xrange(len(obj._ext)), obj._ext))
                self._off += c.bit_len()
                obj._msg.append(c)
                return
            else:
                # 3) if value is in the root, encode value as short uint
                # (no padding)
                root_num = len(obj._cont) - len(obj._ext)
        else:
            root_num = len(obj._cont)
        #
        if root_num == 0:
            # empty ENUM, who knows...
            return
        elif root_num == 1:
            # no arms, no chocolate...
            return
        elif root_num >= 256:
            # TODO: support larger enumeration
            raise(ASN1_PER_ENCODER('%s: enumeration too large (%s)' \
                  % (obj.get_fullname(), root_num)))
        #
        dyn = len_bits(root_num-1)
        obj._msg.append(Bit('C', Pt=obj._cont.keys().index(obj._val),
                            BitLen=dyn, Repr=self._REPR_ENUM))
        if self._ENUM_BUILD_DICT:
            obj._msg[-1].Dict = dict(zip(xrange(root_num), obj._cont.keys()))
        self._off += dyn
    
    #--------------------------------------------------------------------------#
    # BIT STRING
    #--------------------------------------------------------------------------#
    def encode_bit_str(self, obj):
        # obj._val: (integer, bit_length), bit_length: uint
        # 1) get SIZE constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) encode content and get bit length
        if isinstance(obj._val, ASN1.ASN1Obj):
            # corresponds to CONTAINING constraint case
            obj._val._encode(offset=0)
            # TODO: confirm padding is required
            obj._val._codec._add_P(obj._val)
            val = obj._val._msg
            size = val.bit_len()
        else:
            size = obj._val[1]
            val = Bit('C', Pt=obj._val[0], BitLen=size, Repr=self._REPR_BIT_STR)
        #
        # 3) encode potential SIZE extensibility marker
        # and extended SIZE bit string
        if ext:
            self._add_E(obj)
            # check if value to encode has an extended SIZE
            if size < lb or (ub and size > ub):
                obj._msg.E > 1
                self._encode_bit_str_noub(obj, val, size)
                return
        #
        # 4) no upper bound: semi-constrained size
        if ub is None:
            self._encode_bit_str_noub(obj, val, size)
            return
        #
        # 5) upper bound defined: fully constrained size
        if ub == 0:
            # emtpy BIT STRING, youhouhou !
            return
        if ub == lb and ub < 65536:
            # no need for length determinant (implicit bit length)
            if lb > 16 and self.is_aligned():
                # for bit string > 2 bytes, needs to be octet aligned
                self._add_P(obj)
            obj._msg.append(val)
            self._off += size
            return
        if ub >= 65536:
            raise(ASN1_PER_ENCODER('%s: length determinant for upper bound'\
                  '(%s) over encoder limit (64k)' % (obj.get_fullname(), ub)))
        #
        # ub > lb: first add INTEGER as length determinant
        # TODO: verify no padding is required before the length prefix,
        # instead of after it
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        l.set_val(size)
        l._encode(offset=self._off)
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        # potential padding
        if self.is_aligned():
            self._add_P(obj)
        # finally encode content
        obj._msg.append(val)
        self._off += size
    
    def _encode_bit_str_noub(self, obj, val, size):
        # first pad
        if self.is_aligned():
            self._add_P(obj)
        # then add general length determinant
        try:
            l = _PER_L(size, Repr=self._REPR_L)
        except ASN1_PER_ENCODER:
            raise(ASN1_PER_ENCODER('%s: bit length over encoder limit (%s)'\
                  % (obj.get_fullname(), size)))
        obj._msg.append(l)
        # finally append content
        obj._msg.append(val)
        self._off += l.bit_len() + size
    
    #--------------------------------------------------------------------------#
    # OCTET STRING
    #--------------------------------------------------------------------------#
    def encode_oct_str(self, obj):
        # obj._val: string
        # 1) get SIZE constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) encode content and get byte length
        if isinstance(obj._val, ASN1.ASN1Obj):
            # corresponds to CONTAINING constraint case
            obj._val._encode(offset=0)
            obj._val._codec._add_P(obj._val)
            val = obj._val._msg
            size = len(val)
        else:
            size = len(obj._val)
            if obj._type == TYPE_PRINT_STR:
                val = Str('C', Pt=obj._val, Len=size, Repr=self._REPR_PRINT_STR)
            else:
                val = Str('C', Pt=obj._val, Len=size, Repr=self._REPR_OCT_STR)
        #
        # 3) encode potential SIZE extensibility
        if ext:
            self._add_E(obj)
            # check if value to encode has an extended SIZE
            if size < lb or (ub and size > ub):
                obj._msg.E > 1
                self._encode_oct_str_noub(obj, val, size)
                return
        #
        # 4) no upper bound: semi-constrained size
        if ub is None:
            self._encode_oct_str_noub(obj, val, size)
            return
        #
        # 5) upper bound defined: fully constrained size
        if ub == 0:
            # emtpy STRING, yahaha !
            return
        #
        if ub == lb and ub < 65536:
            # no need for length determinant (implicit byte length)
            if lb > 2 and self.is_aligned():
                # for string > 2 bytes, needs to be octet aligned
                self._add_P(obj)
            obj._msg.append(val)
            self._off += size*8
            return
        # TODO: handle fragmentation
        if ub >= 65536:
            raise(ASN1_PER_ENCODER('%s: length determinant for upper bound'\
                  '(%s) over encoder limit (64k)' % (obj.get_fullname(), ub)))
        #
        # ub > lb: first add INTEGER as length determinant
        # TODO: verify no padding is required before the length prefix,
        # instead of after it
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        l.set_val(size)
        l._encode(offset=self._off)
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        # for empty string, that's enough
        if size == 0:
            return
        # then pad
        if self.is_aligned():
            self._add_P(obj)
        # finally append content
        obj._msg.append(val)
        self._off += size*8
    
    def _encode_oct_str_noub(self, obj, val, size):
        # first pad
        if self.is_aligned():
            self._add_P(obj)
        # then add general length determinant
        try:
            l = _PER_L(size, Repr=self._REPR_L)
        except ASN1_PER_ENCODER:
            raise(ASN1_PER_ENCODER('%s: byte length over encoder limit (%s)'\
                  % (obj.get_fullname(), size)))
        obj._msg.append(l)
        # finally append content
        obj._msg.append(val)
        self._off += l.bit_len() + size*8
    
    #--------------------------------------------------------------------------#
    # CHOICE
    #--------------------------------------------------------------------------#
    def encode_choice(self, obj):
        # obj._val: str (name), single_value (type-dependent)
        # 1) for empty CHOICE
        if len(obj._cont) == 0 and obj._ext is None:
            return
        #
        # 2) extended CHOICE
        if obj._ext is not None:
            self._add_E(obj)
            root_names = [i for i in obj._cont if i not in obj._ext]
            # check if CHOICE to encode is an extended one
            if obj._val[0] in obj._ext:
                obj._msg.E > 1
                self._encode_choice_ext(obj)
                return
        else:
            root_names = obj._cont.keys()
        #
        # 3) CHOICE in the root
        # 3.1) add choice's index
        # nothing to choose:
        if len(obj._cont) == 0:
            return
        # single choice possible: no index
        # mutliple choices possible: use INTEGER for encoding choice index
        elif len(obj._cont) > 1:
            ind = ASN1.ASN1Obj(name='I', type=TYPE_INTEGER)
            ind._const.append({'type':CONST_VAL_RANGE, 
                               'lb':0, 'ub':len(root_names)-1, 'ext':False})
            ind.set_val(obj._cont.keys().index(obj._val[0]))
            ind._encode(offset=self._off)
            if self._ENUM_BUILD_DICT:
                ind._msg.C.Dict = dict(zip(xrange(len(obj._cont)),
                                           obj._cont.keys()))
            obj._msg.append(ind._msg)
            self._off += ind._msg.bit_len()
        #
        # 3.2) add potential padding
        #if self.is_aligned():
        #    self._add_P(obj)
        #
        # 3.3) add the encoded value chosen
        cho = obj._cont[obj._val[0]]
        cho.set_val(obj._val[1])
        cho._encode(offset=self._off)
        obj._msg.append(cho._msg)
        self._off += cho._msg.bit_len()
        # clean up content object
        cho._val = None
    
    def _encode_choice_ext(self, obj):
        # 1) always encode the index of the choice within the extension as
        # a normally small value
        # value is the index (starting from 0) of the identifier assigned,
        # without using its explicit tagging
        i = _PER_NSVAL('I', obj._ext.index(obj._val[0]), 
                       Repr=self._REPR_ENUM)
        if self._ENUM_BUILD_DICT:
            i[-1].Dict = dict(zip(xrange(len(obj._ext)), obj._ext))
        obj._msg.append(i)
        self._off += i.bit_len()
        #
        # 4) add padding
        if self.is_aligned:
            self._add_P(obj)
        #
        # 5) wrap into an LV structure
        # extended value chosen is encoded like an OPEN TYPE
        cho = obj._cont[obj._val[0]]
        cho.set_val( obj._val[1] )
        self._wrap_open_type(obj, cho)
        # clean up content object
        cho._val = None
    
    def _wrap_open_type(self, obj, wrapped):
        # if raw string buffer passed
        if isinstance(wrapped, str):
            #if len(wrapped) == 0:
            #    wrapped = '\0'
            # this can be funny to test this corner case
            w_name = ''
            w = Str('C', Pt=wrapped, Len=len(wrapped), Repr=self._REPR_OCT_STR)
        else:
            # 1) encode wrapped (octet-aligned)
            wrapped._encode(offset=0)
            # 2) outermost type requires padding:
            # for wrapped which encodes to zero bits, 8 bits padding are required
            if wrapped._msg.bit_len() == 0:
                wrapped._codec._add_P(wrapped, 8)
            else:
                wrapped._codec._add_P(wrapped)
            w_name = wrapped._name
            w = wrapped._msg
        #
        # 3) add byte-length prefix
        # libmich provides the correct byte-size (including padding bits)
        size = len(w)
        try:
            obj._msg.append(_PER_L(size, Repr=self._REPR_L))
        except ASN1_PER_ENCODER:
            raise(ASN1_PER_ENCODER('%s: byte length over encoder limit (%s) '\
                  'for wrapped object %s'\
                  % (obj.get_fullname(), size, w_name)))
        self._off += obj._msg[-1].bit_len()
        #
        # 4) add potential padding
        if self.is_aligned():
            self._add_P(obj)
        #
        # 5) add encoded wrapped
        obj._msg.append(w)
        self._off += size*8
    
    #--------------------------------------------------------------------------#
    # SEQUENCE
    #--------------------------------------------------------------------------#
    # values with DEFAULT and grouped extension are checked and enforced by
    # .set_val() and ._encode() methods in ASN1.ASN1Obj
    #
    # WNG: in order to provide testing facilities,
    # there is no checking on CONST_SET_REF constraint
    def encode_seq(self, obj):
        # obj._val: dict {str (name): single_value (type-dependent)}
        # 1) for empty SEQUENCE
        if len(obj._cont) == 0 and obj._ext is None:
            return
        #
        # 2) check if extended values needs to be encoded
        extended = False
        if obj._ext is not None:
            self._add_E(obj)
            if any([name in obj._ext_flat for name in obj._val]):
                extended = True
                obj._msg.E > 1
        #
        # 3) build en empty bitmap preamble for OPTIONAL / DEFAULT components
        bm_len = len(obj._root_opt)
        if bm_len:
            bm = Bit('B', Pt=0, BitLen=bm_len, Repr=self._REPR_B)
            obj._msg.append(bm)
            self._off += bm_len
            # bitmap value, in order to set the proper value to the bitmap field
            # after encoding all root components
            bm_val = 0
        #
        if obj._val is None:
            # if there is no value to encode, just return
            return
        #
        # 4) append root components
        for name in obj._root_comp:
            if name in obj._val:
                comp = obj._cont[name]
                # go on a byte boundary for wrapped objects
                if self.is_aligned() and comp._type in (TYPE_OPEN, TYPE_ANY):
                    self._add_P(obj)
                # set the value to the component and encode it
                comp._val = obj._val[name]
                comp._encode(offset=self._off)
                # if the component encodes (value different to DEFAULT one)
                # add a 1-bit flag to the bitmap value
                if bm_len and name in obj._root_opt:
                    if hasattr(comp, '_not_encoded'):
                        del comp._not_encoded
                    else:
                        bm_val += 1 << (bm_len - obj._root_opt.index(name) - 1)
                        obj._msg.append(comp._msg)
                        self._off += comp._msg.bit_len()
                else:
                    obj._msg.append(comp._msg)
                    self._off += comp._msg.bit_len()
                # clean up component internal value
                comp._val = None
        #
        # 4bis) fill-in the potential bitmap preamble with an integral value
        if bm_len and bm_val:
            bm > bm_val
        #
        if extended:
            # 5) go over all extended components,
            # and build the extended bitmap preamble
            self._add_bitmap_ext(obj)
            #
            if self.is_aligned():
                # extended fields are always starting on an octet-boundary
                self._add_P(obj)
            #
            # 6) append extended fields encapsulated like OPEN TYPE
            for name in obj._ext:
                if isinstance(name, str) and name in obj._val:
                    # single extension
                    comp = obj._cont[name]
                    comp._val = obj._val[name]
                    self._wrap_open_type(obj, comp)
                    # clean up content object
                    obj._cont[name]._val = None
                elif isinstance(name, (tuple, list)) and name[0] in obj._val:
                    # group of extensions, to be encapsulated in a SEQUENCE
                    comp = ASN1.ASN1Obj(name=repr(name), type=TYPE_SEQ)
                    comp._cont = OD()
                    comp._val = {}
                    for n in name:
                        comp._cont[n] = obj._cont[n]
                        comp._val[n] = obj._val[n]
                    self._wrap_open_type(obj, comp)
                    # clean up content objects
                    for n in name:
                        obj._cont[n]._val = None
    
    def _add_bitmap_ext(self, obj):
        # 0) extended bitmap is always starting on an octet-boundary
        if self.is_aligned():
                self._add_P(obj)
        # 1) add a length determinant for the count of bitmap 
        # for extended fields / groups
        l = _PER_NSVAL('L', len(obj._ext)-1, Repr=self._REPR_L)
        obj._msg.append(l)
        self._off += l.bit_len()
        #
        # 2) build a bitmap for all extended fields / groups
        group_num, bitmap = -1, []
        for name in obj._ext_flat:
            if name in obj._val:
                if obj._cont[name]._group == -1 \
                or obj._cont[name]._group > group_num: 
                    bitmap.append(1)
            else:
                if obj._cont[name]._group == -1 \
                or obj._cont[name]._group > group_num: 
                    bitmap.append(0)
            group_num = obj._cont[name]._group
        if bitmap:
            assert( len(bitmap) == len(obj._ext) )
            self._add_B(obj, bitmap)
    
    # Bitmap for optional components
    def _add_B(self, obj, bitmap=[]):
        # convert bitmap to integer
        i = 0
        for b in bitmap:
            i <<= 1
            if b == 1:
                i += 1
        # add Bit field
        obj._msg.append(Bit('B', Pt=i, BitLen=len(bitmap), Repr=self._REPR_B) )
        self._off += len(bitmap)
    
    #--------------------------------------------------------------------------#
    # SEQUENCE OF
    #--------------------------------------------------------------------------#
    def encode_seq_of(self, obj):
        # 1) get SIZE constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) get count of sequenced objects
        count = len(obj._val)
        #
        # 3) encode potential count extensibility
        if ext:
            self._add_E(obj)
            # check if values to encode count is over the bounds
            if count < lb or (ub and count > ub):
                obj._msg.E > 1
                self._encode_seq_of_noub(obj, count)
                return
        #
        # 4) no upper-bound: semi-constrained count
        if ub is None:
            self._encode_seq_of_noub(obj, count)
        #
        # 5) upper bound defined: fully constrained count
        if ub == lb and ub < 65536:
            # no need for length determinant (implicit count)
            self._encode_seq_of_obj(obj)
        if ub >= 65536:
            raise(ASN1_PER_ENCODER('%s: length determinant for upper bound'\
                  '(%s) over encoder limit (64k)' % (obj.get_fullname(), ub)))
        #
        # ub > lb: first add INTEGER as length determinant
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        l.set_val(count)
        l._encode(offset=self._off)
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        # finally encode content
        self._encode_seq_of_obj(obj)
    
    def _encode_seq_of_noub(self, obj, count):
        # 1) pad
        if self.is_aligned():
            self._add_P(obj)
        # 2) add general count
        try:
            obj._msg.append(_PER_L(count, Repr=self._REPR_L))
        except ASN1_PER_ENCODER:
            raise(ASN1_PER_ENCODER('%s: count over encoder limit (%s)'\
                  % (obj.get_fullname(), count)))
        # 3) add encoded objects
        self._encode_seq_of_obj(obj)
    
    def _encode_seq_of_obj(self, obj):
        for value in obj._val:
            obj._cont.set_val(value)
            obj._cont._encode(offset=self._off)
            obj._msg.append(obj._cont._msg)
            self._off += obj._cont._msg.bit_len()
        # clean up content object
        obj._cont._val = None
    
    #--------------------------------------------------------------------------#
    # OPEN TYPE
    #--------------------------------------------------------------------------#
    def encode_open_type(self, obj):
        if isinstance(obj._val, tuple):
            obj._cont._val = obj._val[1]
            self._wrap_open_type(obj, obj._cont)
            obj._cont._val = None
        elif isinstance(obj._val, str):
            self._wrap_open_type(obj, obj._val)
        else:
            self._wrap_open_type(obj, '')
    
    #--------------------------------------------------------------------------#
    # decoder
    #--------------------------------------------------------------------------#
    def decode(self, obj, buf, **kwargs):
        # propagate bit offset for recursive decoding
        self._off = 0
        if 'offset' in kwargs:
            self._off = kwargs['offset']
        #
        # call the appropriate type decoder
        if obj._type == TYPE_NULL:
            return self.decode_null(obj, buf)
        elif obj._type == TYPE_BOOL:
            return self.decode_bool(obj, buf)
        elif obj._type == TYPE_INTEGER:
            return self.decode_int(obj, buf)
        elif obj._type == TYPE_ENUM:
            return self.decode_enum(obj, buf)
        elif obj._type == TYPE_BIT_STR:
            return self.decode_bit_str(obj, buf)
        elif obj._type in (TYPE_OCTET_STR, TYPE_IA5_STR, TYPE_PRINT_STR):
            return self.decode_oct_str(obj, buf)
        elif obj._type == TYPE_CHOICE:
            return self.decode_choice(obj, buf)
        elif obj._type == TYPE_SEQ:
            return self.decode_seq(obj, buf)
        elif obj._type == TYPE_SEQ_OF:
            return self.decode_seq_of(obj, buf)
        elif obj._type in (TYPE_ANY, TYPE_OPEN):
            return self.decode_open_type(obj, buf)
        else:
            raise(ASN1_PER_DECODER('%s: unsupported ASN.1 type'\
                  % obj.get_fullname()))
    
    #--------------------------------------------------------------------------#
    # PER prefixes
    #--------------------------------------------------------------------------#
    # Padding (octet-aligned variant)
    def _get_P(self, obj, buf, pad_len=None):
        if pad_len is None:
            pad_len = (8 - self._off%8) % 8
        if pad_len:
            p = Bit('P', Pt=0, BitLen=pad_len, Repr=self._REPR_P)
            buf = p.map_ret(buf)
            assert( p() == 0 )
            obj._msg.append( p )
            self._off += pad_len
        return buf
    
    # Extensibility marker
    def _get_E(self, obj, buf):
        e = Bit('E', Pt=0, BitLen=1, Repr=self._REPR_E)
        buf = e.map_ret(buf)
        obj._msg.append( e )
        self._off += 1
        return buf
    
    # Bitmap for optional content
    def _get_B(self, obj, buf, bitmap_len=1):
        b = Bit('B', BitLen=bitmap_len, Repr=self._REPR_B)
        buf = b.map_ret(buf)
        obj._msg.append( b )
        self._off += bitmap_len
        return buf
    
    #--------------------------------------------------------------------------#
    # NULL / BOOLEAN
    #--------------------------------------------------------------------------#
    def decode_null(self, obj, buf):
        obj._val = None
        return buf
    
    def decode_bool(self, obj, buf):
        # obj._val : True / False
        b = Bit('C', BitLen=1, Dict={0:'FALSE', 1:'TRUE'}, Repr=self._REPR_BOOL)
        buf = b.map_ret(buf)
        obj._msg.append(b)
        self._off += 1
        #
        obj._val = (False, True)[b()]
        return buf
    
    #--------------------------------------------------------------------------#
    # INTEGER
    #--------------------------------------------------------------------------#
    def decode_int(self, obj, buf):
        # obj._val: integer
        # 1) resolve INTEGER constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) decode potential extensibility marker
        if ext:
            buf = self._get_E(obj, buf)
            # if INTEGER is extended
            if obj._msg.E():
                return self._decode_int_unconst(obj, buf)
        #
        # 3) no lower bound
        if lb is None:
            return self._decode_int_unconst(obj, buf)
        #
        # 4) no upper bound: semi-constrained
        if ub is None:
            return self._decode_int_semiconst(obj, buf, lb)
        #
        # 5) both lower / upper bounds: fully constrained
        # get integer value range
        ra = ub - lb + 1
        if ra == 1:
            # only a single value is possible: no decoding needed
            obj._val = lb
            return buf
        #
        # standard constrained encoding (finally)
        if self.is_aligned():
            return self._decode_int_const_align(obj, buf, lb, ra)
        else:
            return self._decode_int_minbits(obj, buf, lb, ra)
    
    def _decode_int_unconst(self, obj, buf):
        # 1) get padding for the aligned variant
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        #
        # 2) get the length determinant
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append( l )
        self._off += l.bit_len()
        size = l()
        #
        # 3) decode signed integer value
        if size > 8:
            raise(ASN1_PER_DECODER('%s: unconstrained integer value too '\
                  'long (%i), over decoder limit (64 bit)'\
                  % (obj.get_fullname(), size)))
        #
        c = Int('C', Type='int%i' % (8*size), Repr=self._REPR_INT)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += 8*size
        #
        obj._val = c()
        return buf
    
    def _decode_int_semiconst(self, obj, buf, lb):
        # 1) get padding for the aligned variant
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        #
        # 2) get the length determinant
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append( l )
        self._off += l.bit_len()
        size = l() 
        #
        # 3) decode unsigned integer value
        if size > 8:
            raise(ASN1_PER_DECODER('%s: semi-constrained integer value too '\
                  'large (%i), over decoder limit (64 bit)'\
                  % (obj.get_fullname(), size)))
        #
        c = Int('C', Type='uint%i' % (8*size), Repr=self._REPR_INT)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += 8*size
        #
        obj._val = c() + lb
        return buf
    
    def _decode_int_const_align(self, obj, buf, lb, ra):
        # format depends on the range between bounds:
        # 1) for 1 byte dynamic
        if ra <= 255:
            # short integer always decode in the minimum number of bits,
            # whatever PER variant
            return self._decode_int_minbits(obj, buf, lb, ra)
        #
        # 2) for 2 bytes dynamic
        if 256 <= ra <= 65536:
            # 2a) get padding
            buf = self._get_P(obj, buf)
            #
            # 2b) add value with minimal byte-encoding
            if ra == 256:
                c = Bit('C', BitLen=8, Repr=self._REPR_INT)
                buf = c.map_ret(buf)
                obj._msg.append(c)
                self._off += 8
                #
                obj._val = c() + lb
                return buf
            #
            c = Bit('C', BitLen=16, Repr=self._REPR_INT)
            buf = c.map_ret(buf)
            obj._msg.append(c)
            self._off += 16
            #
            obj._val = c() + lb
            return buf
        #
        # 3) for greater dynamic: uint value encoded in the minimum number of bytes
        # 3a) get custom length determinant
        # dyn_ra: number of bits required to describe the length in 
        # bytes of the maximum value that could be encoded
        dyn_ra = len_bits(len_bytes(ra))
        l = Bit('L', BitLen=dyn_ra, Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append( l )
        self._off += dyn_ra
        size = l() + 1
        #
        # 3b) get padding
        buf = self._get_P(obj, buf)
        #
        # 3c) decode value
        c = Bit('C', BitLen=size*8, Repr=self._REPR_INT)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += size*8
        #
        obj._val = c() + lb
        return buf
    
    def _decode_int_minbits(self, obj, buf, lb, ra):
        # decoding in the minimum number of bits
        dyn_ra = len_bits(ra-1)
        c = Bit('C', BitLen=dyn_ra, Repr=self._REPR_INT)
        buf = c.map_ret(buf)
        obj._msg.append( c )
        self._off += dyn_ra
        #
        obj._val = c() + lb
        return buf
    
    #--------------------------------------------------------------------------#
    # ENUMERATION
    #--------------------------------------------------------------------------#
    def decode_enum(self, obj, buf):
        # obj._val: identifier (string)
        # 1) decode potential extensibility marker
        if obj._ext is not None:
            buf = self._get_E(obj, buf)
            if obj._msg.E():
                # 2) value is in the extension
                c = _PER_NSVAL('C', Repr=self._REPR_ENUM)
                buf = c.map_ret(buf)
                if self._ENUM_BUILD_DICT:
                    c[-1].Dict = dict(zip(xrange(len(obj._ext)), obj._ext))
                obj._msg.append(c)
                self._off += c.bit_len()
                #
                val = c()
                if val < len(obj._ext):
                    obj._val = obj._ext[val]
                # if extended index value is unknown,
                # the decoded value cannot be retrieved
                # WNG: this is silently handled here, 
                # as no concrete value is set for within obj._val
                return buf
            else:
                # 3) value is in the root
                root_num = len(obj._cont) - len(obj._ext)
        else:
            root_num = len(obj._cont)
        #
        if root_num == 0:
            # empty ENUM, who knows...
            return buf
        elif root_num == 1:
            # no arms, no chocolate...
            obj._val = obj._cont.keys()[0]
            return buf
        elif root_num >= 256:
            # TODO: support larger enumeration
            raise(ASN1_PER_DECODER('%s: enumeration too large (%s)' \
                  % (obj.get_fullname(), len(obj._cont))))
        #
        dyn = len_bits(root_num-1)
        c = Bit('C', BitLen=dyn, Repr=self._REPR_ENUM)
        buf = c.map_ret(buf)
        if self._ENUM_BUILD_DICT:
            c.Dict = dict(zip(xrange(root_num), obj._cont.keys()))
        obj._msg.append(c)
        self._off += dyn
        #
        ind = c()
        if ind >= root_num:
            raise(ASN1_PER_DECODER('%s: invalid enumerated index (%s)'\
                  % (obj.get_fullname(), ind)))
        obj._val = obj._cont.keys()[ind]
        return buf
    
    #--------------------------------------------------------------------------#
    # BIT STRING
    #--------------------------------------------------------------------------#
    # TODO: decode to another ASN1Obj corresponding to the CONTAINING constraint
    def decode_bit_str(self, obj, buf):
        # obj._val: (integer, bit_length), bit_length: uint
        # 1) resolve SIZE constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) decode potential extensibility marker
        if ext:
            buf = self._get_E(obj, buf)
            if obj._msg.E():
                # 3) BIT STRING SIZE is extended
                return self._decode_bit_str_noub(obj, buf)
        #
        # 4) no upper bound: semi-constrained size
        if ub is None:
            return self._decode_bit_str_noub(obj, buf)
        #
        # 5) upper bound defined: fully constrained size
        if lb == ub and ub < 65536:
            # no need for length determinant
            if lb > 16 and self.is_aligned():
                # for bit string > 2 bytes, needs to be octet aligned
                buf = self._get_P(obj, buf)
            c = Bit('C', BitLen=lb, Repr=self._REPR_BIT_STR)
            buf = c.map_ret(buf)
            obj._msg.append(c)
            self._off += lb
            #
            obj._val = (c(), lb)
            return buf
        #
        # ub > lb: first add INTEGER as length determinant
        if ub >= 65536:
            raise(ASN1_PER_DECODER('%s: length determinant for upper bound'\
                  '(%s) over decoder limit (64k)' % (obj.get_fullname(), ub)))
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        buf = l._decode(buf, offset=self._off)
        size = l()
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        # potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        # finally decode content
        c = Bit('C', BitLen=size, Repr=self._REPR_BIT_STR)
        buf = c.map_ret(buf)
        obj._msg.append( c )
        self._off += size
        #
        obj._val = (c(), size)
        return buf
    
    def _decode_bit_str_noub(self, obj, buf):
        # potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        # get general length determinant
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append(l)
        self._off += l.bit_len()
        size = l()
        # finally decode content
        c = Bit('C', BitLen=size, Repr=self._REPR_BIT_STR)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += size
        #
        obj._val = (c(), size)
        return buf
    
    #--------------------------------------------------------------------------#
    # OCTET STRING
    #--------------------------------------------------------------------------#
    # TODO: decode to another ASN1Obj corresponding to the CONTAINING constraint
    def decode_oct_str(self, obj, buf):
        # obj._val: string
        # 1) resolve INTEGER constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) decode potential extensibility marker
        if ext:
            buf = self._get_E(obj, buf)
            if obj._msg.E():
                # 3) OCTET STRING SIZE is extended
                return self._decode_oct_str_noub(obj, buf)
        #
        # 4) no upper bound: semi-constrained size
        if ub is None:
            return self._decode_oct_str_noub(obj, buf)
        #
        # 5) upper bound defined: fully constrained size
        if lb == ub and ub <= 65536:
            # no need for length determinant
            if lb > 2 and self.is_aligned():
                # for string > 2 bytes, needs to be octet aligned
                buf = self._get_P(obj, buf)
            if obj._type == TYPE_PRINT_STR:
                c = Str('C', Len=lb, Repr=self._REPR_PRINT_STR)
            else:
                c = Str('C', Len=lb, Repr=self._REPR_OCT_STR)
            buf = c.map_ret(buf)
            obj._msg.append(c)
            self._off += lb*8
            #
            obj._val = c()
            return buf
        #
        # ub > lb: first add INTEGER as length determinant
        if ub >= 65536:
            raise(ASN1_PER_DECODER('%s: length determinant for upper bound'\
                  '(%s) over decoder limit (64k)' % (obj.get_fullname(), ub)))
        
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        buf = l._decode(buf, offset=self._off)
        size = l() 
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        # for empty string, that's enough
        if size == 0:
            obj._val = ''
            return buf
        #
        # potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        # finally decode content
        if obj._type == TYPE_PRINT_STR:
            c = Str('C', Len=size, Repr=self._REPR_PRINT_STR)
        else:
            c = Str('C', Len=size, Repr=self._REPR_OCT_STR)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += size*8
        #
        obj._val = c()
        return buf
    
    def _decode_oct_str_noub(self, obj, buf):
        # potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        # get general length determinant
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append(l)
        self._off += l.bit_len()
        size = l()
        # finally decode content
        if obj._type == TYPE_PRINT_STR:
            c = Str('C', Len=size, Repr=self._REPR_PRINT_STR)
        else:
            c = Str('C', Len=size, Repr=self._REPR_OCT_STR)
        buf = c.map_ret(buf)
        obj._msg.append(c)
        self._off += size*8
        #
        obj._val = c()
        return buf
    
    #--------------------------------------------------------------------------#
    # CHOICE
    #--------------------------------------------------------------------------#
    def decode_choice(self, obj, buf):
        # 1) for empty choice
        if len(obj._cont) == 0 and obj._ext is None:
            return buf
        #
        # 2) decode potential extensibility marker
        if obj._ext is not None:
            buf = self._get_E(obj, buf)
            root_names = [i for i in obj._cont if i not in obj._ext]
            # check if extended
            if obj._msg.E():
                return self._decode_choice_ext(obj, buf)
        else:
            root_names = obj._cont.keys()
        #
        # for CHOICE in the root
        # 3) get choice's name
        if len(obj._cont) == 0:
            # nothing to choose... who knows !
            return buf
        elif len(obj._cont) == 1:
            # single choice possible, no encoding of choice index
            cho_name = obj._cont.keys()[0]
            cho = obj._cont[cho_name]
        else:
            # multiple choices possible: use INTEGER for decoding choice index
            ind = ASN1.ASN1Obj(name='I', type=TYPE_INTEGER)
            ind._const.append({'type':CONST_VAL_RANGE,
                               'lb':0, 'ub':len(root_names)-1, 'ext':False})
            buf = ind._decode(buf, offset=self._off)
            ind_val = ind._val
            if self._ENUM_BUILD_DICT:
                ind._msg.C.Dict = dict(zip(xrange(len(root_names)), 
                                           root_names))
            obj._msg.append(ind._msg)
            self._off += ind._msg.bit_len()
            if ind._val >= len(root_names):
                raise(ASN1_PER_DECODER('%s: invalid choice index (%s)'\
                      % (obj.get_fullname(), ind._val)))
            cho_name = obj._cont.keys()[ind._val]
            cho = obj._cont[cho_name]
        #
        # 3bis) get potential padding
        #if self.is_aligned():
        #    buf = self._get_P(obj, buf)
        #
        # 4) decode the object chosen according to the index
        buf = cho._decode(buf, offset=self._off)
        obj._msg.append(cho._msg)
        self._off += cho._msg.bit_len()
        #
        obj._val = (cho_name, cho._val)
        # clean up content object
        cho._val = None
        return buf
    
    def _decode_choice_ext(self, obj, buf):
        # 1) get extended choice's index,
        # use NSVAL for decoding choice index
        ind = _PER_NSVAL('I', Repr=self._REPR_ENUM)
        buf = ind.map_ret(buf)
        if self._ENUM_BUILD_DICT:
            ind[-1].Dict = dict(zip(xrange(len(obj._ext)), obj._ext))
        obj._msg.append(ind)
        self._off += ind.bit_len()
        ind_val = ind()
        if ind_val >= len(obj._ext):
            # hack for supporting unknown extension
            cho_name = '_ext_%i' % ind_val
            cho = None
        else:
            cho_name = obj._ext[ind()]
            cho = obj._cont[cho_name]
        #
        # 4) potential padding
        if self.is_aligned:
            buf = self._get_P(obj, buf)
        #
        # 5) extended value chosen needs to be decoded like an OPEN TYPE
        # unwrap from the LV structure 
        buf = self._unwrap_open_type(obj, buf, cho)
        # hack for supporting unknown extension
        if cho is None:
            obj._val = (cho_name, str(obj._msg[-1]))
        else:
            obj._val = (cho_name, cho._val)
            # clean up content object
            cho._val = None
        return buf
    
    def _unwrap_open_type(self, obj, buf, wrapped):
        # 1) decode length determinant
        # get general length determinant
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append(l)
        self._off += l.bit_len()
        size = l()
        #
        # 2) get potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        #
        # 3) if wrapped type is unknown, just get the buffer
        if wrapped is None:
            c = Str('C', Len=size, Repr=self._REPR_OCT_STR)
            buf = c.map_ret(buf)
            obj._msg.append( c )
            self._off += size*8
            return buf
        #
        # 4) if wrapped is defined, decode it completely
        buf = wrapped._decode(buf, offset=0)
        # 5) get padding for it as it is an outermost type
        # zero bit field are padded with 8 bits
        if wrapped._msg.bit_len() == 0:
            buf = wrapped._codec._get_P(wrapped, buf, 8)
        else:
            buf = wrapped._codec._get_P(wrapped, buf)
        if self._SAFE:
            assert( wrapped._msg.bit_len() == size*8 )
        obj._msg.append( wrapped._msg )
        self._off += size*8
        return buf
    
    #--------------------------------------------------------------------------#
    # SEQUENCE
    #--------------------------------------------------------------------------#
    # WNG: in order to provide testing facilities,
    # the only action with CONST_SET_REF constraint is to set referred type
    # to any OPEN / ANY type which has such constraint
    def decode_seq(self, obj, buf):
        # obj._val: dict {str (name): single_value (type-dependent)}
        # 1) for empty SEQUENCE
        if len(obj._cont) == 0 and obj._ext is None:
            return
        #
        # 2) decode potential extensibility marker
        extended = False
        if obj._ext is not None:
            buf = self._get_E(obj, buf)
            if obj._msg.E():
                extended = True
        #
        # 3) get the bitmap preamble for OPTIONAL / DEFAULT components
        # WNG: during the decoding process, OPTIONAL and DEFAULT components
        # are handled in exactly the same way
        # there is no assumption about the canonicity or even correctness
        # of the encoder for DEFAULT values handling
        if obj._root_opt:
            buf = self._get_B(obj, buf, bitmap_len=len(obj._root_opt))
            # keep only component that are identified by the bitmap
            opt_names = filter(lambda x:x!=None, 
                               map(lambda x,y:x if y=='1' else None,
                                   obj._root_opt, obj._msg[-1].__bin__()))
        #
        # 4) decode each component in the root
        # including those optional / default indicated in the bitmap
        obj._val = dict()
        for name in obj._root_comp:
            comp = None
            if obj._cont[name]._flags is None:
                # mandatory component
                comp = obj._cont[name]
            elif name in opt_names:
                # OPTIONAL / DEFAULT component which is present
                comp = obj._cont[name]
            elif FLAG_DEF in obj._cont[name]._flags:
                # DEFAULT component which is not present
                # for those, we restore the DEFAULT value
                obj._val[name] = obj._cont[name]._flags[FLAG_DEF]
            #
            if comp is not None:
                if comp._type in (TYPE_OPEN, TYPE_ANY):
                    # 4bis) get potential padding before OPEN TYPE
                    if self.is_aligned():
                        buf = self._get_P(obj, buf)
                    buf = comp._decode(buf, offset=0)
                    # 4ter) decode further OPEN TYPE with reference constraint
                    # CONST_SET_REF
                    const = comp.get_const_ref()
                    if const:
                        comp_ref, done = self._decode_open_ref(obj, comp, const)
                        if done:
                            # further decoding was done correctly
                            comp._msg = comp_ref._msg
                            comp._val = (comp_ref._name, comp_ref._val)
                else:
                    # 5) decode standard ASN1 object
                    buf = comp._decode(buf, offset=self._off)
                #
                obj._msg.append(comp._msg)
                self._off += comp._msg.bit_len()
                # we need to assign decoded value to obj._val
                obj._val[name] = comp._val
                # clean up component value
                comp._val = None
        #
        # 6) process potential extension
        if extended:
            buf = self._decode_seq_ext(obj, buf)
        #
        if not obj._val:
            obj._val = None
        return buf
    
    def _decode_open_ref(self, obj, comp, const):
        if not const['at']:
            raise(ASN1_OBJ('%s: invalid SET_REF constraint'\
                  % obj.get_fullname()))
        # get the value referred by @ identifier from obj
        if const['at'] not in obj._val:
            # this would mean the @ identifier field is placed 
            # after the OPEN TYPE to decode
            # -> terrible protocol design !
            #raise(ASN1_OBJ('%s: not able to retrieve value for @ '\
            #      'component %s' % (obj.get_fullname(), const['at'])))
            return (comp, False)
        #
        at_val = obj._val[const['at']]
        try:
            obj_ref = const['ref'](const['at'], at_val)
        except:
            # invalid value passed against object info value set
            return (comp, False)
        #
        comp_typename = comp.get_typename()
        if comp_typename not in obj_ref:
            raise(ASN1_OBJ('%s: not able to retrieve %s within '\
                  'object info set' % (obj.get_fullname(), comp_typename)))
        comp_ref = obj_ref[comp_typename].clone_light()
        #
        # decode the raw OPEN TYPE buf with the new ASN1 object
        try:
            buf = comp_ref._decode(str(comp._msg[-1]), offset=0)
            comp_ref._codec._get_P(comp_ref, buf)
        except:
            # in case the decoder did some bullshit
            return (comp, False)
        # TODO: this assertion should be removed after enough testing
        if self._SAFE:
            assert( str(comp_ref) == str(comp._msg[-1]) )
        # comp_ref must get the Length prefix from comp LV structure
        comp_ref._msg.insert(0, comp._msg[0])
        return (comp_ref, True)
    
    def _decode_seq_ext(self, obj, buf):
        # 1) get the bitmap preamble for extended fields
        # bitmap length is indicated by an NSVAL length determinant
        l = _PER_NSVAL('L', Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append(l)
        self._off += l.bit_len()
        buf = self._get_B(obj, buf, bitmap_len=1+l())
        ext_bm = obj._msg[-1].__bin__()
        #
        # 2) get potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        #
        # 3) decode each (group of) extended fields according to obj._ext
        # or like OPEN TYPE
        open_names = []
        ind_val = 0
        for b in ext_bm:
            if b == '1':
                if ind_val < len(obj._ext):
                    # 4) known extended field / group
                    comp = obj._ext[ind_val]
                    if isinstance(comp, str):
                        # single field
                        name = comp
                        comp_obj = obj._cont[name]
                        if comp_obj._type in (TYPE_OPEN, TYPE_ANY):
                            # TODO: decode further OPEN TYPE with CONST_SET_REF
                            pass
                        buf = self._unwrap_open_type(obj, buf, comp_obj)
                        obj._val[name] = comp_obj._val
                        # clean up content object
                        comp_obj._val = None
                    elif isinstance(comp, (list, tuple)):
                        # grouped fields
                        comp_obj = ASN1.ASN1Obj(name=repr(comp), type=TYPE_SEQ)
                        comp_obj._cont = OD()
                        for name in comp:
                            comp_obj._cont[name] = obj._cont[name]
                            if obj._cont[name]._type in (TYPE_OPEN, TYPE_ANY):
                                # TODO: decode further OPEN TYPE with CONST_SET_REF
                                pass
                        buf = self._unwrap_open_type(obj, buf, comp_obj)
                        # assign values and clean up content objects
                        for name in comp:
                            obj._val[name] = obj._cont[name]._val
                            obj._cont[name]._val = None
                else:
                    # 5) unknown extended field
                    buf = self._unwrap_open_type(obj, buf, None)
                    # hack for supporting unknown extension
                    obj._val = ('_ext_%i' % ind_val, str(obj._msg[-1]))
            ind_val += 1
        #
        return buf
    
    #--------------------------------------------------------------------------#
    # SEQUENCE OF
    #--------------------------------------------------------------------------#
    def decode_seq_of(self, obj, buf):
        # 1) get SIZE constraints
        lb, ub, ext = obj.get_const_int()
        #
        # 2) decode potential count extensibility
        if ext:
            buf = self._get_E(obj, buf)
            if obj._msg.E():
                # 3) SEQUENCE OF SIZE is extended
                return self._decode_seq_of_noub(obj, buf)
        #
        # no upper-bound: semi-constrained count
        if ub is None:
            return self._decode_seq_of_noub(obj, buf)
        #
        # 4) upper-bound defined: fully constrained count
        if lb == ub:
            # no length determinant (implicit count)
            return self._decode_seq_of_obj(obj, buf, lb)
        # ub > lb, not extended
        if ub >= 65536:
            raise(ASN1_PER_DECODER('%s: length determinant for upper bound'\
                  '(%s) over decoder limit (64k)' % (obj.get_fullname(), ub)))
        #
        l = ASN1.ASN1Obj(name='L', type=TYPE_INTEGER)
        l._const.append({'type':CONST_VAL_RANGE, 'lb':lb, 'ub':ub, 'ext':False})
        buf = l._decode(buf, offset=self._off)
        size = l()
        obj._msg.append(l._msg)
        self._off += l._msg.bit_len()
        #
        return self._decode_seq_of_obj(obj, buf, size)
    
    def _decode_seq_of_noub(self, obj, buf):
        # 1) get potential padding
        if self.is_aligned():
            buf = self._get_P(obj, buf)
        # 2) get general count
        l = _PER_L(Repr=self._REPR_L)
        buf = l.map_ret(buf)
        obj._msg.append(l)
        self._off += l.bit_len()
        size = l()
        # 3) get decoded object
        return self._decode_seq_of_obj(obj, buf, l())
    
    def _decode_seq_of_obj(self, obj, buf, count):
        obj._val = []
        for i in xrange(count):
            buf = obj._cont._decode(buf, offset=self._off)
            self._off += obj._cont._msg.bit_len()
            obj._msg.append(obj._cont._msg)
            obj._val.append(obj._cont._val)
        # clean up content object
        obj._cont._val = None
        #
        return buf
    
    #--------------------------------------------------------------------------#
    # OPEN TYPE
    #--------------------------------------------------------------------------#
    def decode_open_type(self, obj, buf):
        return self._unwrap_open_type(obj, buf, None)
#