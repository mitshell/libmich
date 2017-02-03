# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.3
# *
# * Copyright © 2015. Benoit Michau. ANSSI.
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
# * File Name : asn1/BER.py
# * Created : 2015-01-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# export filter
__all__ = ['BER', 'T', 'L', 'BER_TLV']

from libmich.core.element import Element, Str, Int, Bit, Layer, show
from libmich.core.shtr import shtr
from libmich.utils.IntEncoder import *
#
import ASN1
from utils import *

class ASN1_BER_ENCODER(ASN1_CODEC): pass
class ASN1_BER_DECODER(ASN1_CODEC): pass

################################################################################
# For each ASN.1 object that we want to encode / decode with BER, we have:
# - tag: 1 or more bytes
#   -> encoding ASN.1 object's tag 
#   -> plus 1 bit for basic / constructed type distinction
# - length: 1 or more bytes, length of the value field in bytes
# - value: 0 or more bytes, value assigned to the ASN.1 object
#
# WARNING: several limitations exists in this implementation
# - EXPLICIT tagging, as I understand it, is not supported, except for specific
# CHOICE or OPEN types within SEQUENCE / SET
################################################################################
# few BER internal structures / naming which are useful:
# T: tag
# L: length
# V: value
# BER_TLV: standard TLV structure
################################################################################

_IntToStruct = {
    1 : 'b',
    2 : 'h',
    4 : 'i',
    8 : 'q',
    }

#------------------------------------------------------------------------------#
# BER-specific internal objects for encoding / decoding different types
#------------------------------------------------------------------------------#
BERTagClass_dict = {
    0 : TAG_UNIVERSAL,
    1 : TAG_APPLICATION,
    2 : TAG_CONTEXT_SPEC,
    3 : TAG_PRIVATE
    }
BERTagPC_dict = {
    0 : 'Primitive',
    1 : 'Constructed',
    }
class T(Layer):
    _dict = {31:'extended form'}
    _byte_aligned = True
    constructorList = [
        Bit('Class', Pt=0, BitLen=2, Repr='hum', Dict=BERTagClass_dict),
        Bit('PC', Pt=0, BitLen=1, Repr='hum', Dict=BERTagPC_dict),
        Bit('T', Pt=0, BitLen=5, Repr='hum')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        if self.T() == 31:
            self.set( kwargs['T'] )
        self.T.Dict = self.Class
        self.T.DictFunc = self._get_tag_dict
    
    def _get_tag_dict(self, cla):
        if cla() == 0:
            return TAG_UNIV_VALTOTYPE
        else:
            return self._dict
    
    def set(self, T=0):
        if T <= 30:
            self.T > T
        else:
            self.T.Pt = 31
            self._val = T
            T = bin(T)[2:] # string of '100110010'
            # pad the Tag with bits 0 on the left side to be a multiple
            # of 7-bits word
            tag_len, r = len(T)//7, len(T)%7
            if r:
                T = (7-r)*'0' + T
                tag_len += 1
            # interpolate a bit 1 after each block of 7 bits
            # except fot last block which get a bit 0
            # and convert it to a string
            tag_str = ''.join(map(lambda v: chr(int(v, 2)),
                                  ['1'+T[i:i+7] for i in \
                                   range(0, (tag_len-1)*7, 7)]+['0'+T[-7:]]))
            self.append( Str('T_ext', Pt=tag_str, Repr='hex') )
    
    def get(self):
        return self()
    
    def map(self, s=''):
        if len(s) < 1:
            return ''
        if len(self.elementList) != 3:
            self.__init__()
        Layer.map(self, s[0])
        if self.T() == 31:
            s = s[1:]
            # extended form: consume the buffer until a MSBit is null
            cur = 0
            while cur < len(s)-1:
                if ord(s[cur]) & 0x80 == 0x80:
                    cur += 1
                else:
                    break
            tag_str = s[:cur+1]
            self.append( Str('T_ext', Pt=tag_str, Repr='hex') )
            # get the integral value after removing MSBit of each byte
            self._val = reduce(lambda x,y: (x<<7)+y, 
                               map(lambda c: ord(c)&0x7F, tag_str))
    
    def __call__(self):
        if not hasattr(self, '_val'):
            return self.T()
        else:
            return self._val
    
    def __repr__(self):
        t_val = self()
        if t_val in self._dict:
            t_val = '%s - %s' % (t_val, self._dict[t_val])
        return '<Tag [%s - %s]: %s>' % (self.Class.Dict[self.Class()],
                                        self.PC.Dict[self.PC()],
                                        t_val)

class L(Layer):
    _byte_aligned = True
    constructorList = [
        Bit('Form', Pt=0, BitLen=1, Repr='hum', Dict={0:'short', 1:'long'}),
        Bit('L', Pt=0, BitLen=7, Repr='hum')
        ]
    
    def __init__(self, **kwargs):
        if 'indefinite' in kwargs and kwargs['indefinite']:
            # indefinite form
            Layer.__init__(self, Form=1, L=0)
        else:
            # default short definite form
            Layer.__init__(self, **kwargs)
            if self.Form():
                # long definite form
                self.set(kwargs['L'], force_long=True)
    
    def set(self, L=0, force_long=False):
        if L <= 127 and not force_long:
            self.Form.Pt = 0
            self.L.Pt = L
        else:
            self.Form.Pt = 1
            # encode the length in the minimum number of bytes
            len_hex = hex(L)[2:]
            if len_hex[-1] == 'L':
                len_hex = len_hex[:-1]
            if len(len_hex) % 2:
                len_hex = '0'+len_hex
            self.L.Pt = len(len_hex)//2
            self.append( Bit('L_ext', Pt=L, BitLen=len(len_hex)*4, Repr='hum') )
    
    def get(self):
        return self()
    
    def map(self, s=''):
        if len(s) < 1:
            return ''
        if len(self.elementList) != 2:
            self.__init__()
        Layer.map(self, s[0])
        if self.Form() and self.L():
            self.append( Bit('L_ext', BitLen=self.L()*8, Repr='hum') )
            self[-1].map(s[1:])
    
    def __call__(self):
        if self.Form():
            if self.L() == 0:
                return -1
            else:
                return self.L_ext()
        else:
            return self.L()
    
    def __repr__(self):
        form = self.Form.Dict[self.Form()]
        if self() == -1:
            form = 'indefinite'
        return '<Len [%s]: %s>' % (form, self())

class BER_TLV(Layer):
    _LEN_MAX_INDEF = 1048576
    _LEN_FORCE_LONG = False
    #
    _byte_aligned = True
    constructorList = [
        T(),
        L(),
        Str('V', Pt='')
        ]
    
    def __init__(self, name='', **kwargs):
        Layer.__init__(self)
        if name:
            self.CallName = name
        if 'Tag' in kwargs:
            self.T.set(kwargs['Tag'])
        elif 'T' in kwargs:
            self.T.set(kwargs['T'])
        if 'Val' in kwargs:
            self.V.Pt = kwargs['Val']
            self.L.set(len(self.V), force_long=self._LEN_FORCE_LONG)
        elif 'V' in kwargs:
            self.V.Pt = kwargs['V']
            self.L.set(len(self.V), force_long=self._LEN_FORCE_LONG)
        self.V.Len = self.L
        self.V.LenFunc = lambda l: l() if l() >= 0 else self._LEN_MAX_INDEF
        # TODO: for indefinite length
        # we should better parse recursively BER_TLV struct within V
        # when of type constructed
    
    def set(self, V=''):
        if isinstance(V, BER_TLV):
            self.remove(self[2])
            self.append(V)
            self[0].PC > 1
            self[1].set(len(V), force_long=self._LEN_FORCE_LONG)
        elif isinstance(V, (tuple, list)) \
        and all([isinstance(comp, BER_TLV) for comp in V]):
            self.remove(self.V)
            for comp in V:
                self.append(comp)
            self[0].PC > 1
            self[1].set(sum(map(len, V)), force_long=self._LEN_FORCE_LONG)
        elif isinstance(V, (Element, Layer)):
            self.replace(self.V, V)
            self[1].set(len(V), force_long=self._LEN_FORCE_LONG)
        else:
            self.V.Pt = V
            self[1].set(len(V), force_long=self._LEN_FORCE_LONG)
    
    def get(self):
        return self[2]
    
    def parse(self, buf=''):
        self.__init__(self.CallName)
        self.map(buf)
        L = len(self)
        #
        # parse nested BER_TLV structures within the Value
        if self[0].PC():
            # indefinite form
            indef = self[1]() == -1
            # parsing further internal Value
            buf = str(self[2])
            inner = []
            marker = None
            while buf:
                tlv = BER_TLV()
                tlv.parse(buf)
                buf = buf[len(tlv):]
                if indef and (tlv[0]() == 0 and tlv[1]() == 0):
                    marker = tlv
                    marker.CallName = '_end_'
                    break
                else:
                    inner.append(tlv)
            if inner:
                self.remove(self[2])
                V = Layer('V')
                V.extend(inner)
                self.append(V)
            if marker:
                self.append(marker)
        # returns the length parsed
        return L

#------------------------------------------------------------------------------#
# BER encoder / decoder
#------------------------------------------------------------------------------#

class BER(ASN1.ASN1Codec):
    #
    # used by ASN1Obj types
    _name = 'BER'
    _enc_err = ASN1_BER_ENCODER
    _dec_err = ASN1_BER_DECODER
    #
    # add some costly verification when decoding buffers
    _SAFE = True
    #
    # CODEC customizations:
    # encoder customizations
    # always force setting length with the long form
    _ENC_LEN_FORCE_LONG = False
    # static value given to BOOLEAN TRUE 
    _ENC_BOOL_TRUE = 0xFF
    # force integer length for INTEGER
    _ENC_INT_LEN = None # could be any multiple of 8 bits (e.g. 64, 1024, ...)
    # force integer length for ENUMERATED
    _ENC_ENUM_LEN = None # just like _ENC_INT_LEN
    #
    # to build dictionnary for encoded / decoded ENUMERATED, CHOICE, ...
    _ENUM_BUILD_DICT = True
    #
    # libmich layers' representation (only for basic types)
    _REPR_BOOL = 'hex'
    _REPR_INT = 'hum'
    _REPR_ENUM = 'hum'
    _REPR_BIT_STR = 'hex'
    _REPR_OCT_STR = 'hex'
    _REPR_PRINT_STR = 'hum'
    
    #--------------------------------------------------------------------------#
    # encoder
    #--------------------------------------------------------------------------#
    def encode(self, obj, **kwargs):
        BER_TLV._LEN_FORCE_LONG = self._ENC_LEN_FORCE_LONG
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
        elif obj._type in (TYPE_OCTET_STR, TYPE_IA5_STR, TYPE_PRINT_STR, 
                           TYPE_NUM_STR):
            self.encode_oct_str(obj)
        elif obj._type == TYPE_CHOICE:
            self.encode_choice(obj)
        elif obj._type == TYPE_SEQ:
            self.encode_seq(obj)
        elif obj._type == TYPE_SEQ_OF:
            self.encode_seq_of(obj)
        elif obj._type == TYPE_SET:
            self.encode_set(obj)
        elif obj._type == TYPE_SET_OF:
            self.encode_set_of(obj)
        elif obj._type in (TYPE_ANY, TYPE_OPEN):
            self.encode_open_type(obj)
        elif obj._type == TYPE_EXT:
            self.encode_oct_str(obj)
        else:
            raise(ASN1_BER_ENCODER('%s: unsupported ASN.1 type: %s'\
                  % (obj.get_fullname(), obj._type)))
    
    def handle_tag_enc(self, obj):
        # get tag: class, primitive / constructed (pc), val
        tag = obj.get_tag()
        if tag is None:
            raise(ASN1_BER_ENCODER('%s: no tag retrieved' % obj.get_fullname()))
        mode = tag[1]
        cla, val = obj.get_tag_val()
        if obj._type in TYPE_CONSTRUCTED or obj._type == TYPE_EXT:
            pc = 1
        elif hasattr(obj, '_tag_pc'):
            pc = obj._tag_pc
        else:
            pc = 0
        #
        # 1) tag in IMPLICIT mode by default
        obj._msg[0].Class.Pt = cla
        obj._msg[0].PC.Pt = pc
        obj._msg[0].set(val)
        #
        # 2) for EXPLICIT mode, if not already UNIVERSAL, add an encapsulation
        if mode == TAG_EXPLICIT and cla != 0:
            inner = BER_TLV(obj.get_name())
            inner[0].Class.Pt = 0
            inner[0].PC.Pt = pc
            inner[0].set( TAG_UNIV_TYPETOVAL[obj._type] )
            inner.set( obj._msg.get() )
            obj._msg.set( inner )
            obj._msg[0].PC.Pt = 1
    
    #--------------------------------------------------------------------------#
    # NULL / BOOLEAN
    #--------------------------------------------------------------------------#
    def encode_null(self, obj):
        obj._msg = BER_TLV(obj.get_name(), V='')
        self.handle_tag_enc(obj)
    
    def encode_bool(self, obj):
        # obj._val = True / False
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set( chr((0, self._ENC_BOOL_TRUE)[obj._val]) )
        obj._msg[-1].Repr = self._REPR_BOOL
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # INTEGER
    #--------------------------------------------------------------------------#
    def encode_int(self, obj):
        # determine the length required to encode as a standard integer
        if isinstance(self._ENC_INT_LEN, (int, long)) \
        and self._ENC_INT_LEN % 8 == 0:
            # encoder forcing INTEGER length
            bit_len = abs(self._ENC_INT_LEN)
        else:
            # minimum byte length for INTEGER
            bit_len = 1 + len_bits(abs(obj._val))
            miss_len = bit_len % 8
            if miss_len != 0:
                bit_len += 8 - miss_len
        # encode it with libmich Int
        obj._msg = BER_TLV(obj.get_name()) 
        obj._msg.set( Int('V', Pt=obj._val, Type='int%s'%bit_len,
                          Repr=self._REPR_INT) )
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # ENUMERATION
    #--------------------------------------------------------------------------#
    def encode_enum(self, obj):
        # empty enum
        if len(obj._cont) == 0:
            obj._msg = BER_TLV(self.get_name())
            return
        # get the maximum integer value to know the length on which to encode
        if isinstance(self._ENC_ENUM_LEN, (int, long)) \
        and self._ENC_ENUM_LEN % 8 == 0:
            # encoder forcing ENUMERATED length
            bit_len = abs(self._ENC_ENUM_LEN)
        else:
            # minimum byte length for ENUMERATED
            bit_len = 1 + len_bits(max(obj._cont.values()))
            miss_len = bit_len % 8
            if miss_len != 0:
                bit_len += 8 - miss_len
        # and get the identifier integer value from the string value
        V = Int('V', Pt=obj._cont[obj._val], Type='int%s'%bit_len,
                Repr=self._REPR_ENUM)
        if self._ENUM_BUILD_DICT:
            V.Dict = dict([(i[1], i[0]) for i in obj._cont.items()])
        #
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # BIT STRING
    #--------------------------------------------------------------------------#
    def encode_bit_str(self, obj):
        if isinstance(obj._val, ASN1.ASN1Obj):
            # obj._val: ASN1Obj, according to CONTAINING constraint
            V = Layer('V')
            V.append(Int('pad_len', Pt=0, Type='uint8'))
            obj._val._encode()
            V.extend(obj._val._msg)
            obj._val._msg = None
        #
        else:
            # obj._val: (BE uint value, BE uint bit length)
            val_len = obj._val[1] // 8
            val_ext = obj._val[1] % 8
            if val_ext:
                val_len += 1
            V = Layer('V')
            V.append(Int('pad_len', Pt=(8-val_ext)%8, Type='uint8'))
            V.append(Bit('val', Pt=obj._val[0], BitLen=obj._val[1], 
                         Repr=self._REPR_BIT_STR))
            if val_ext > 0:
                V.append(Bit('pad', Pt=0, BitLen=8-val_ext, 
                             Repr=self._REPR_BIT_STR))
        #
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # OCTET STRING
    #--------------------------------------------------------------------------#
    def encode_oct_str(self, obj):
        if isinstance(obj._val, ASN1.ASN1Obj):
            # obj._val: ASN1Obj, according to CONTAINING constraint
            obj._val._encode()
            V = obj._val._msg
            obj._val._msg = None
            obj._msg = BER_TLV(obj.get_name())
            obj._msg.set(V)
        #
        else:
            # obj._val: str
            obj._msg = BER_TLV(obj.get_name(), V=obj._val)
        #
        if obj._type == TYPE_PRINT_STR:
            obj._msg[-1].Repr = self._REPR_PRINT_STR
        else:
            obj._msg[-1].Repr = self._REPR_OCT_STR
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # CHOICE
    #--------------------------------------------------------------------------#
    def encode_choice(self, obj):
        # obj._val = (choice name, type-dependent value)
        # if choice is tagged, need to encode it like a constructed one
        # otherwise, just encode the chosen component
        cho = obj._cont[obj._val[0]]
        cho._val = obj._val[1]
        cho._encode()
        tag = obj.get_tag_val()
        if tag is not None:
            obj._msg = BER_TLV(obj.get_name())
            obj._msg[0].Class.Pt = tag[0]
            obj._msg[0].PC.Pt = 1
            obj._msg[0].set(tag[1])
            obj._msg.set(cho._msg)
        else:
            cho._msg.CallName = '%s.%s' % (obj.get_name(), cho._msg.CallName)
            obj._msg = cho._msg
        cho._val = None
        cho._msg = None
    
    #--------------------------------------------------------------------------#
    # SEQUENCE
    #--------------------------------------------------------------------------#
    # values with DEFAULT and grouped extension are checked and enforced by
    # .set_val() and ._encode() methods in ASN1.ASN1Obj
    #
    # WNG: in order to provide testing facilities,
    # there is no checking on CONST_SET_REF constraint
    def encode_seq(self, obj):
        V = Layer('V')
        for name in obj._cont:
            if name in obj._val:
                comp = obj._cont[name]
                comp._val = obj._val[name]
                comp._encode()
                V.append(comp._msg)
                comp._msg = None
        #
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # SEQUENCE OF
    #--------------------------------------------------------------------------#
    def encode_seq_of(self, obj):
        V = Layer('V')
        for val in obj._val:
            obj._cont._val = val
            obj._cont._encode()
            V.append(obj._cont._msg)
        #
        obj._cont._msg = None
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # SET
    #--------------------------------------------------------------------------#
    def encode_set(self, obj):
        V = Layer('V')
        for name in obj._cont:
            if name in obj._val:
                comp = obj._cont[name]
                comp._val = obj._val[name]
                comp._encode()
                V.append(comp._msg)
                comp._msg = None
        #
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # SET OF
    #--------------------------------------------------------------------------#
    def encode_set_of(self, obj):
        V = Layer('V')
        for val in obj._val:
            obj._cont._val = val
            obj._cont._encode()
            V.append(obj._cont._msg)
        #
        obj._cont._msg = None
        obj._msg = BER_TLV(obj.get_name())
        obj._msg.set(V)
        self.handle_tag_enc(obj)
    
    #--------------------------------------------------------------------------#
    # OPEN TYPE
    #--------------------------------------------------------------------------#
    def encode_open_type(self, obj):
        # I did not really understand how it goes here...
        # default tag is UNIVERSAL OCTET STRING, 
        # when nothing is specified for the encapsulated type
        default_tag = (2, 4)
        #
        if isinstance(obj._cont, ASN1.ASN1Obj) and isinstance(obj._val, tuple) \
        and obj._val[0] == obj._cont._name:
            cont = obj._cont
            cont._val = obj._val[1]
            cont._encode()
            obj._msg = cont._msg
            cont._val = None
            cont._msg = None
        elif isinstance(obj._val, str):
            obj._msg = BER_TLV(obj.get_name(), V=obj._val)
            obj._msg[0].Class.Pt = default_tag[0]
            obj._msg[0].set( default_tag[1] )
        else:
            obj._msg = BER_TLV(obj.get_name(), V='')
            obj._msg[0].Class.Pt = default_tag[0]
            obj._msg[0].set( default_tag[1] )
        #
        tag = obj.get_tag_val()
        if tag is not None:
            encap = BER_TLV(obj.get_name())
            encap[0].Class.Pt = tag[0]
            encap[0].set(tag[1])
            encap.set(obj._msg)
            obj._msg = encap
    
    #--------------------------------------------------------------------------#
    # decoder
    #--------------------------------------------------------------------------#
    
    def decode(self, obj, buf, **kwargs):
        obj._msg = BER_TLV(obj.get_name())
        # this makes use of the generic (nested) BER_TLV decoder
        # whatever type obj is
        L = obj._msg.parse(buf)
        self.decode_val(obj)
        return buf[L:]
    
    def decode_val(self, obj):
        #
        # call the appropriate value type decoder
        if obj._type == TYPE_NULL:
            return self.decode_null_val(obj)
        elif obj._type == TYPE_BOOL:
            return self.decode_bool_val(obj)
        elif obj._type == TYPE_INTEGER:
            return self.decode_int_val(obj)
        elif obj._type == TYPE_ENUM:
            return self.decode_enum_val(obj)
        elif obj._type == TYPE_BIT_STR:
            return self.decode_bit_str_val(obj)
        elif obj._type in (TYPE_OCTET_STR, TYPE_IA5_STR, TYPE_PRINT_STR,
                           TYPE_NUM_STR):
            return self.decode_oct_str_val(obj)
        elif obj._type == TYPE_CHOICE:
            return self.decode_choice_val(obj)
        elif obj._type == TYPE_SEQ:
            return self.decode_seq_val(obj)
        elif obj._type == TYPE_SEQ_OF:
            return self.decode_seq_of_val(obj)
        elif obj._type == TYPE_SET:
            return self.decode_set_val(obj)
        elif obj._type == TYPE_SET_OF:
            return self.decode_set_of_val(obj)
        elif obj._type in (TYPE_ANY, TYPE_OPEN):
            return self.decode_open_type_val(obj)
        elif obj._type == TYPE_EXT:
            return self.decode_oct_str_val(obj)
        else:
            raise(ASN1_BER_DECODER('%s: unsupported ASN.1 type'\
                  % obj.get_fullname()))
    
    def handle_tag_dec(self, obj):
        # this get the tag (IMPLICIT case) or chain of tags until the
        # UNIVERSAL one (EXPLICIT case),
        # and returns:
        #   the length of the outermost BER_TLV
        #   the innermost BER_TLV
        #
        tag = obj.get_tag()
        if tag is None:
            raise(ASN1_BER_DECODER('%s: no tag retrieved' % obj.get_fullname()))
        val, mode, cla = tag
        #
        tlv = obj._msg
        #
        if self._SAFE and tlv[0]() not in (0, val):
            raise(ASN1_BER_DECODER('%s: invalid tag provided %s compared to '\
                  'expected one %s' % (obj.get_fullname(), repr(tlv[0]), 
                                       repr(tag))))
            # TODO: we should also enforce the comparison of the Class
            # of the tag
        #
        if mode == TAG_EXPLICIT:
            # retrieve UNIVERSAL tag from the nested TLV structures
            while tlv[0].PC() and tlv[0].Class() != 0:
                tlv = tlv.get()
                if not isinstance(tlv[0], T):
                    raise(ASN1_BER_DECODER('%s: unable to retrieve UNIVERSAL '\
                      'tag' % obj.get_fullname()))
            #
            if self._SAFE and (tlv[0].Class() != 0 \
             or tlv[0]() not in (0, TAG_UNIV_TYPETOVAL[obj._type])):
                raise(ASN1_BER_DECODER('%s: invalid UNIVERSAL tag provided %s'\
                      'compared to %s' % (obj.get_fullname(), repr(tlv[0]), 
                      TAG_UNIV_TYPETOVAL[obj._type])))
            #
        return tlv
    
    #--------------------------------------------------------------------------#
    # NULL / BOOLEAN
    #--------------------------------------------------------------------------#
    def decode_null_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        obj._val = None
    
    def decode_bool_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        tlv[2].Repr = self._REPR_BOOL
        if len(tlv[2]):
            if str(tlv[2])[0] == '\0':
                obj._val = False
            else:
                obj._val = True
    
    #--------------------------------------------------------------------------#
    # INTEGER
    #--------------------------------------------------------------------------#
    
    def decode_int_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        # map to an Int, given the length of the value part
        bit_len = tlv[1]()*8
        V = Int('V', Type='int%s'%bit_len, Repr=self._REPR_INT)
        V.map(str(tlv[2]))
        tlv.set(V)
        #
        obj._val = V()
    
    #--------------------------------------------------------------------------#
    # ENUMERATION
    #--------------------------------------------------------------------------#
    
    def decode_enum_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        # map to an Int, given the length of the value part
        bit_len = tlv[1]()*8
        if bit_len:
            V = Int('V', Type='int%s'%bit_len, Repr=self._REPR_ENUM)
            V.map(str(tlv[2]))
            if self._ENUM_BUILD_TYPE:
                V.Dict = dict([(i[1], i[0]) for i in obj._cont.items()])
            tlv.set(V)
            #
            val_int = V()
            enum_int = obj._cont.values()
            if val_int in enum_int:
                obj._val = obj._cont.keys()[enum_int.index(val_int)]
            elif obj._ext is not None:
                # if extended index value is unknown,
                # the decoded value cannot be retrieved
                # WNG: we put a dummy string here as value
                obj._val = '_ext_%i' % val_int
            elif self._SAFE:
                raise(ASN1_BER_DECODER('%s: invalid ENUMERATED identifier %s' \
                      % (obj.get_fullname(), val_int)))
    
    #--------------------------------------------------------------------------#
    # BIT STRING
    #--------------------------------------------------------------------------#
    # TODO: decode to another ASN1Obj corresponding to the CONTAINING constraint
    
    def decode_bit_str_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        # obj._val: (BE uint value, BE uint bit length)
        # map to a Layer including the pad_len initial octet
        v_str = str(tlv[2])
        if len(v_str) > 1:
            pad_len = ord(v_str[0])
            bit_len = 8*(len(v_str)-1)-pad_len
            V = Layer('V')
            V.append(Int('pad_len', Type='uint8'))
            V.append(Bit('val', BitLen=bit_len, Repr=self._REPR_BIT_STR))
            if pad_len > 0:
                V.append(Bit('pad', BitLen=pad_len, Repr=self._REPR_BIT_STR))
            V.map(v_str)
            tlv.set(V)
            #
            obj._val = (V[1](), bit_len)
        else:
            obj._val = (0, 0)
    
    
    #--------------------------------------------------------------------------#
    # OCTET STRING
    #--------------------------------------------------------------------------#
    # TODO: decode to another ASN1Obj corresponding to the CONTAINING constraint
    
    def decode_oct_str_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        if obj._type == TYPE_PRINT_STR:
            tlv[2].Repr = self._REPR_PRINT_STR
        else:
            tlv[2].Repr = self._REPR_OCT_STR
        obj._val = str(tlv[2])
    
    #--------------------------------------------------------------------------#
    # CHOICE
    #--------------------------------------------------------------------------#
    # TODO: decode unknown extension according to their UNIVERSAL tag,
    # when provided by the encoder
    #    
    def decode_choice_val(self, obj):
        # obj._val = (name, value)
        # check if CHOICE is tagged by the application
        tag = obj.get_tag()
        if tag is not None:
            # if CHOICE is tagged, need to get its tag first
            if self._SAFE and obj._msg[0]() != tag[0]:
                raise(ASN1_BER_DECODER('%s: invalid CHOICE tag provided %s ' \
                      'compared to expected one %s' \
                      % (obj.get_fullname(), repr(obj._msg[0]), tag)))
            tlv = obj._msg.get()[0]
        else:
            # otherwise, tag is directly corresponding to the chosen object
            tlv = obj._msg
        tag = (tlv[0].Class(), tlv[0]())
        #
        if tag in obj._cont_tags:
            # select the chosen object according to the tag
            cho_names = obj._cont_tags[tag]
            cho = obj._cont[cho_names[0]]
            if len(cho_names) > 1:
                # chain of untagged CHOICE
                for name in cho_names[1:]:
                    cho = cho._cont[name]
            #
            obj._val = nest(cho_names,
                            self._decode_comp_val(obj, cho, tlv))
        #
        elif obj._ext is not None:
            # extended unknown object
            obj._val = ('_ext_%i' % tag[1], str(tlv[2]))
            # TODO, if we have an UNIVERSAL tag, we can decode the passed value
        #
        elif self._SAFE:
            raise(ASN1_BER_DECODER('%s: invalid CHOICE tag %s' \
                  % (obj.get_fullname(), tag)))
    
    def _decode_comp_val(self, obj, comp, tlv):
        #print('decoding value for component %s of %s' \
        #      % (comp._name, obj.get_fullname()))
        if comp._type in (TYPE_OPEN, TYPE_ANY):
            const = comp.get_const_ref()
            if const:
                done, ref = self._get_open_ref(obj, comp, const)
                if done:
                    #log('CONST_SET_REF, ref: %s' % ref._name)
                    comp._cont = ref
        #
        comp = comp.clone_light()
        comp._msg = tlv
        tlv.CallName = comp.get_name()
        self.decode_val(comp)
        val = comp._val
        comp._val = None
        #comp._msg = None
        #print('decoded %s' % comp._name)
        return val
    
    def _get_open_ref(self, obj, comp, const):
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
            return (False, None)
        #
        at_val = obj._val[const['at']]
        #log('_get_open_ref, at: %s, at_val: %s' % (const['at'], at_val))
        try:
            ref = const['ref'](const['at'], at_val)
        except:
            # invalid value passed against object info value set
            return (False, None)
        #
        comp_typename = comp.get_typename()
        #log('_get_open_ref, comp_typename: %s' % comp_typename)
        if comp_typename not in ref:
            raise(ASN1_OBJ('%s: not able to retrieve %s within '\
                  'object info set' % (obj.get_fullname(), comp_typename)))
        return (True, ref[comp_typename].clone_light()) 
    
    #--------------------------------------------------------------------------#
    # SEQUENCE
    #--------------------------------------------------------------------------#
    # TODO: 
    # - untagged OPEN / ANY types are not handled, which will certainly raise
    # if present in the encoded SEQUENCE
    # - value of unknown extended components are not handled 
    def decode_seq_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        compts = tlv.get()
        # Empty sequence
        if len(compts) == 0:
            return
        # compts must be Layer containing BER_TLV layers
        if self._SAFE \
        and not all([isinstance(comp, BER_TLV) for comp in compts]):
            raise(ASN1_BER_DECODER('%s: invalid SEQUENCE encoded content'\
                  % obj.get_fullname()))
        #
        # cursors for going over the components and _cont_tags list
        cur_compts = 0
        cur_tag = 0
        obj._val = dict()
        # going over all components of the compiled SEQUENCE
        for name in obj._cont:
            if cur_compts >= len(compts.elementList):
                break
            tlv_inner = compts[cur_compts]
            #print('cur: %s, component: %s' % (cur_compts, repr(tlv_inner)))
            tag = (tlv_inner[0].Class(), tlv_inner[0]())
            comp = obj._cont[name]
            comp_tag = comp.get_tag_val()
            #print('expected name / tag: %s / %s' % (name, repr(comp_tag)))
            #
            if comp_tag is None:
                # untagged component: CHOICE / OPEN / ANY type
                # TODO: handle OPEN / ANY types
                #
                # get all possible tags within the CHOICE
                if comp._type == TYPE_CHOICE:
                    tags = [t[0] for t in obj._cont_tags[cur_tag:] \
                            if t[1][0] == name]
                    if tag in tags:
                        obj._val[name] = self._decode_comp_val(obj,
                                                               comp,
                                                               tlv_inner)
                        tlv_inner.CallName = '.'.join(obj._cont_tags[cur_tag:]\
                                                     [tags.index(tag)][1])
                        cur_compts += 1
                    cur_tag += len(tags)
                else:
                    # OPEN TYPE
                    obj._val[name] = self._decode_comp_val(obj,
                                                           comp,
                                                           tlv_inner)
                    cur_compts += 1
                    cur_tag += 1
            else:
                if comp_tag == tag:
                    # tagged component, including CHOICE / OPEN / ANY type
                    obj._val[name] = self._decode_comp_val(obj,
                                                           comp,
                                                           tlv_inner)
                    cur_compts += 1
                cur_tag += 1
        #
        for name in [n for n in obj._root_comp if n not in obj._root_opt]:
            if name not in obj._val:
                # mandatory component was not present in the decoded components
                raise(ASN1_BER_DECODER('%s: missing mandatory component %s' \
                      % (obj.get_fullname(), name)))
    
    #--------------------------------------------------------------------------#
    # SEQUENCE OF
    #--------------------------------------------------------------------------#
    def decode_seq_of_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        compts = tlv.get()
        if self._SAFE \
        and not all([isinstance(comp, BER_TLV) for comp in compts]):
            raise(ASN1_BER_DECODER('%s: invalid SEQUENCE OF encoded content'\
                  % obj.get_fullname()))
        #
        obj._val = []
        for tlv in compts:
            obj._val.append( self._decode_comp_val(obj, obj._cont, tlv) )
    
    #--------------------------------------------------------------------------#
    # SET
    #--------------------------------------------------------------------------#
    def decode_set_val(self, obj):
        tlv = self.handle_tag_dec(obj)
        compts = tlv.get()
        # compts must be Layer containing BER_TLV layers
        if self._SAFE \
        and not all([isinstance(comp, BER_TLV) for comp in compts]):
            raise(ASN1_BER_DECODER('%s: invalid SET encoded content'\
                  % obj.get_fullname()))
        #
        # remainder for components
        tags = list(obj._cont_tags)
        obj._val = dict()
        # going over all components of the decoded SET
        for tlv in compts:
            tag = (tlv[0].Class(), tlv[0]())
            if tag in obj._cont_tags:
                # known component
                if self._SAFE and tag not in tags:
                    raise(ASN1_BER_DECODER('%s: multiple SET component %s' \
                          % (obj.get_fullname(), obj._cont_tags[tag][0])))
                name = obj._cont_tags[tag][0]
                comp = obj._cont[name]
                obj._val[name] = self._decode_comp_val(obj, comp, tlv)
                tags.remove(tag)
        #
        for name in [n for n in obj._root_comp if n not in obj._root_opt]:
            if name not in obj._val:
                # mandatory component was not present in the decoded "compts"
                raise(ASN1_BER_DECODER('%s: missing mandatory component %s' \
                      % (obj.get_fullname(), name)))
    
    #--------------------------------------------------------------------------#
    # SEQUENCE OF
    #--------------------------------------------------------------------------#
    def decode_set_of(self, obj):
        tlv = self.handle_tag_dec(obj)
        compts = tlv.get()
        if self._SAFE \
        and not all([isinstance(comp, BER_TLV) for comp in compts]):
            raise(ASN1_BER_DECODER('%s: invalid SET OF encoded content'\
                  % obj.get_fullname()))
        #
        obj._val = []
        for tlv in compts:
            obj._val.append( self._decode_comp_val(obj, obj._cont, tlv) )
    
    #--------------------------------------------------------------------------#
    # OPEN TYPE
    #--------------------------------------------------------------------------#
    # TODO: decode unknown OPEN TYPE according to their UNIVERSAL tag,
    # when provided by the encoder
    #
    def decode_open_type_val(self, obj):
        # check if OPEN / ANY type is tagged by the application
        tag = obj.get_tag()
        if tag is not None:
            # if tagged, need to get its tag first
            if self._SAFE and obj._msg[0]() != tag[0]:
                raise(ASN1_BER_DECODER('%s: invalid OPEN TYPE tag provided %s ' \
                      'compared to expected one %s' \
                      % (obj.get_fullname(), repr(obj._msg[0]), tag)))
            tlv = obj._msg.get()[0]
        else:
            # otherwise, tag is directly corresponding to the chosen object
            tlv = obj._msg
        #
        if isinstance(obj._cont, ASN1.ASN1Obj):
            obj._val = (obj._cont._name,
                        self._decode_comp_val(obj, obj._cont, tlv))
        else:
            obj._val = str(tlv[2])
    
