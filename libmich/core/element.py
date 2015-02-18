# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.3.0
# *
# * Copyright © 2012. Benoit Michau. France Telecom.
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
# * File Name : core/element.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#------------------------------------------------------------------------------#
#                                   The Libmich                                #
#------------------------------------------------------------------------------#
# Python library, works with Python 2.6 and 2.7
# not tested with older version
# and not going to support Python 3 (str / bytes is PITA here)
#
# version: 0.3
# author: Benoit Michau
#
# defines 3 kind of primary elements:
#   `Str': for byte stream
#   `Bit': for bit stream (actually managed like an integer value)
#   `Int': for integer value
#   all are subclasses of the common `Element' class
#
# elements can be stacked into a layer: 
#   `Layer': stacks [Str, Bit, Byte, Layer] (yes, it's recursive)
#   allows to manage dependencies between elements within the layer,
#   and with surrounding layers (next, previous, header, payload)
#   when placed in a block
#   
# layers can be stacked into a block:
#   `Block': stacks [Layer] (and only Layer)
#   allows to manage intelligently dependencies between layers 
#   (next, previous, header, payload)
#   with a hierarchy attribute assigned to each layer.
#
# Particularly convinient for building / parsing complex and mixed data 
# structure like network protocols: IKEv2, SCTP, Diameter, EAP, UMA...
# or like file structure: zip, PNG, ELF, MPEG4, ...
#
# TODO:
# + actually, still a lot !
# + defines plenty of formats
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# import business
#------------------------------------------------------------------------------#
# check python version for deepcopy bug in 2.6
# and raise if Python version is not correct
import sys
def __version_err():
    print('[ERR] only python 2.6 and 2.7 are supported (unfortunately)')
    raise(Exception)
if sys.version_info[0] == 2:
    if sys.version_info[1] == 6:
        import copy
        import types
        def _deepcopy_method(x, memo):
            return type(x)(x.im_func, deepcopy(x.im_self, memo), x.im_class)
        copy._deepcopy_dispatch[types.MethodType] = _deepcopy_method
    elif sys.version_info[1] != 7:
        __version_err()
else:
    __version_err()

# export filtering
#
# exports the following constants:
# type_funcs, debug_level, ERR, WNG, DBG,
# functions: 
# log(), debug(), show(), showattr(), test()
# classes:
# Element(), Str(), Int(), Bit(), Layer(), RawLayer(), Block()
__all__ = ['Element', 'Str', 'Int', 'Bit', 'Layer', 'RawLayer', 'Block',
           'type_funcs', 'debug_level', 'ERR', 'WNG', 'DBG', 'log', 'debug',
           'show', 'showattr',
           'test', 'test0', 'test1', 'test2',
           'testTLV', 'testA', 'testB']

from copy import deepcopy
from struct import pack, unpack
from socket import inet_ntoa
from binascii import hexlify, unhexlify
from re import split, sub

from libmich.core.shar import shar
from libmich.core.shtr import shtr, decomposer, decompose
# TODO: cleanup the rest of libmich-related code to remove this import here
from libmich.utils.repr import show, showattr

#------------------------------------------------------------------------------#
# helping routines
#------------------------------------------------------------------------------#
# defines a tuple of function-like 
class Dummy(object):
    def __init__(self):
        pass
type_funcs = ( type(lambda x:1), \
               type(Dummy().__init__), \
               type(inet_ntoa) )
del Dummy
#
# defines debugging facility
debug_level = {1:'ERR', 2:'WNG', 3:'DBG'}
ERR = 1
WNG = 2
DBG = 3

def log(level=DBG, string=''):
    # if needed, can be changed to write somewhere else
    # will redirect all logs from the library
    print('[libmich %s] %s' % (debug_level[level], string))

def debug(thres, level, string):
    if level and level<=thres:
        print('[%s] %s' %(debug_level[level], string))

#------------------------------------------------------------------------------#
# basic Element definitions
#------------------------------------------------------------------------------#
# Now defines Elements: Str, Int, Bit
# Element is a wrapping object for all the 3 following
# and has some common methods 
class Element(object):
    '''
    encapsulating class for: Str, Bit, Int
    '''
    # checking Element boundaries extensively
    #safe = True
    safe = False
    
    # Element debugging threshold: 0, ERR, WNG, DBG
    dbg = ERR
    
    # value assignment facilities
    def __lt__(self, Val):
        self.Val = Val
    
    def __gt__(self, Pt):
        self.Pt = Pt
    
    # transparency handling, common to all Element:
    def is_transparent(self):
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): 
                return True
            else:
                return False
        elif self.Trans:
            if self.safe:
                assert(type(self.Trans) is bool)
            return True
        else:
            return False
    
    # an Element can point to another Element or Layer
    def getobj(self):
        if isinstance(self.Pt, (Element, Layer, tuple, list)) and not self.Val:
            return self.Pt
        else:
            return self()
    
    # this is to get a nice object representation:
    # can possibly be called with `show(element)`
    def show(self, with_trans=False):
        tr, re = '', ''
        if self.is_transparent():
            # TODO: eval the best convinience here
            if not with_trans:
                return ''
            tr = ' - transparent'
        else:
            tr = ''
        if self.ReprName != '':
            re = ''.join((self.ReprName, ' '))
        return '<%s[%s%s] : %s>' % ( re, self.CallName, tr, repr(self) )
    
    # when willing to bit shift str, call this instead of standard __str__()
    def shtr(self):
        return shtr(self.__str__())
    
    # this is to retrieve element's dynamicity from a mapped buffer
    def reautomatize(self):
        if self.Val is not None:
            if not self.PtFunc:
                self.Pt = self.Val
            self.Val = None
    
	# this is for uniformity with Block()
    def parse(self, s=''):
        self.map(s)

class Str(Element):
    '''
    class defining a standard Element, 
    managed like a stream of byte(s), or string.
    It is always byte-aligned (in term of length, at least)
    
    attributes:
    Pt: to point to another stream object (can simply be a string);
    PtFunc: when defined, PtFunc(Pt) is used 
            to generate the str() / len() representation;
    Val: when defined, overwrites the Pt (and PtFunc) string value, 
         used when mapping a string buffer to the element;
    Len: can be set to a fixed int value, or to another object
         when called by LenFunc
    LenFunc: to be used when mapping string buffer with variable length
             (e.g. in TLV object), LenFunc(Len) is used;
    Repr: python representation; binary, hexa, human or ipv4;
    Trans: to define transparent element which has empty str() and len() to 0,
           it "nullifies" its existence; can point to something for automation;
    TransFunc: when defined, TransFunc(Trans) is used to automate the 
               transparency aspect: used e.g. for conditional element;
    '''
    
    # this is used when printing the object representation
    _repr_limit = 1024
    _reprs = ['hex', 'bin', 'hum', 'ipv4']
    
    # padding is used when .Pt and .Val are None, 
    # but Str instance has still a defined .Len attribute
    _padding_byte = '\0'
    
    def __init__(self, CallName='', ReprName=None, 
                 Pt=None, PtFunc=None, Val=None, 
                 Len=None, LenFunc=None,
                 Repr="hum",
                 Trans=False, TransFunc=None):
        if CallName or not self.CallName:
            self.CallName = CallName
        if ReprName is None :
            self.ReprName = ''
        else :
            self.ReprName = ReprName
        self.Pt = Pt
        self.PtFunc = PtFunc
        self.Val = Val
        self.Len = Len
        self.LenFunc = LenFunc
        self.Type = 'stream'
        self.Repr = Repr
        self.Trans = Trans
        self.TransFunc = TransFunc
    
    def __setattr__(self, attr, val):
        # ensures no bullshit is provided into element's attributes 
        # (however, it is not a exhaustive test...)
        # managed with the class "safe" trigger
        if self.safe :
            if attr == 'CallName' :
                if type(val) is not str or len(val) == 0 :
                    raise AttributeError('CallName must be a non-null string')
            elif attr == 'ReprName' :
                if type(val) is not str:
                    raise AttributeError('ReprName must be a string')
            elif attr == 'PtFunc' :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('PtFunc must be a function')
            elif attr == 'Val' :
                if val is not None and not isinstance(val, \
                (str, bytes, Element, Layer, Block, tuple, list)) :
                    raise AttributeError('Val must be a string or something ' \
                    'that makes a string at the end...')
            elif attr == 'Len' :
                if val is not None and not isinstance(val, \
                (int, tuple, Element, type_funcs)) :
                    raise AttributeError('Len must be an int or element')
            elif attr == 'LenFunc' :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('LenFunc must be a function')
            elif attr == 'Repr' :
                if val not in self._reprs :
                    raise AttributeError('Repr %s does not exist, only: %s' \
                          % (val, self._reprs))
            elif attr == 'TransFunc' :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('TransFunc must be a function')
        # this is for Layer() pointed by Pt attr in Str() object
        #if isinstance(self.Pt, Layer) and hasattr(self.Pt, attr):
        #    setattr(self.Pt, attr, val)
        # ...does not work properly
        # and the final standard python behaviour
        object.__setattr__(self, attr, val)
    
    def __getattr__(self, attr):
        # this is for Layer() pointed by Pt attr in Str() object
        if isinstance(self.Pt, Layer) and hasattr(self.Pt, attr):
            return getattr(self.Pt, attr)
        # and the final standard python behaviour
        object.__getattr__(self, attr)
    
    # the libmich internal instances check
    # this is highly experimental...
    def __is_intern_inst(self, obj):
        return isinstance(obj, (Element, Layer, Block))
    
    # building basic methods for manipulating easily the Element 
    # from its attributes
    def __call__(self, l=None):
        # when length has fixed value:
        if not l and type(self.Len) is int:
            l = self.Len
        #else:
        #    l = None
        # when no values are defined at all:
        if self.Val is None and self.Pt is None: 
            if l: return l * self._padding_byte
            else: return ''
        # returning the right string:
        # if defined, self.Val overrides self.Pt capabilities
        elif self.Val is not None:
            # allow to pass tuple or list of libmich internal instances
            if isinstance(self.Val, (list, tuple)) \
            and False not in map(self.__is_intern_inst, self.Val):
                return ''.join(map(str, self.Val))[:l]
            return str(self.Val)[:l]
        # else: use self.Pt capabilities to get the string
        elif self.PtFunc is not None: 
            if self.safe: 
                assert(hasattr(self.PtFunc(self.Pt), '__str__'))
            return str(self.PtFunc(self.Pt))[:l]
        else:
            # allow to pass tuple or list of libmich internal instances
            if isinstance(self.Pt, (list, tuple)) \
            and False not in map(self.__is_intern_inst, self.Pt):
                return ''.join(map(str, self.Pt))[:l]
            # otherwise, handle simply as is
            if self.safe: 
                assert(hasattr(self.Pt, '__str__'))
            return str(self.Pt)[:l]
    
    def __str__(self):
        # when Element is Transparent:
        if self.is_transparent():
            return ''
        #else:
        return self()
    
    def __len__(self):
        # does not take the LenFunc(Len) into account
        # When a Str is defined, the length is considered dependent of the Str
        # the Str is dependent of the LenFunc(Len) only 
        # when mapping data into the Element
        return len(self.__str__())
    
    def bit_len(self):
        return len(self)*8
    
    def map_len(self):
        # need special length definition 
        # when mapping a string to the 'Str' element 
        # that has no fixed length
        #
        # uses LenFunc, applied to Len, when length is variable:
        # and TransFunc, applied to Trans, to managed potential transparency
        # (e.g. for optional element triggered by other element)
        #
        if self.Len is None:
            return None
            #return 0
        if self.LenFunc is None: 
            return self.Len
        else:
            if self.safe:
                assert( type(self.LenFunc(self.Len)) in (int, long) )
            return self.LenFunc(self.Len)
    
    def __int__(self):
        # big endian integer representation of the string buffer
        return shtr(self).left_val(len(self)*8)
    
    def __bin__(self):
        # does not use the standard python 'bin' function to keep 
        # the right number of prefixed 0 bits
        h = hex(self)
        binary = ''
        for i in xrange(0, len(h), 2):
            b = format( int(h[i:i+2], 16), 'b' )
            binary += ( 8-len(b) ) * '0' + b
        return binary
    
    def __hex__(self):
        return self().encode('hex')
    
    def __repr__(self):
        # check for simple representations
        if self.Pt is None and self.Val is None: 
            return repr(None)
        if self.Repr == 'ipv4':
            #if self.safe: assert( len(self) == 4 )
            if len(self) != 4:
                return '0x%s' % hex(self)
            return inet_ntoa( self.__str__() )
        elif self.Repr == 'hex': 
            ret = '0x%s' % hex(self)
        elif self.Repr == 'bin': 
            ret = '0b%s' % self.__bin__()
        # check for the best human-readable representation
        elif self.Repr == 'hum':
            # standard return
            ret = repr( self() )
            # complex return:
            # allow to assign a full Block or Layer to a Str...
            if self.__is_intern_inst(self.Pt):
                ret = repr(self.Pt)
            if self.__is_intern_inst(self.Val):
                ret = repr(self.Val)
            # allow to assign a list or tuple of Block or Layer...
            if isinstance(self.Pt, (list, tuple)) \
            and False not in map(self.__is_intern_inst, self.Pt):
                ret = '|'.join(map(repr, self.Pt))
            if isinstance(self.Val, (list, tuple)) \
            and False not in map(self.__is_intern_inst, self.Val):
                ret = '|'.join(map(repr, self.Val))
            # finally, self.Val can be a raw value... still
            if self.Val is not None and hasattr(self.Val, '__repr__'):
                ret = repr(self.Val)
        # truncate representation if string too long:
        # avoid terminal panic...
        if len(ret) <= self._repr_limit:
            return ret
        else:
            return ret[:self._repr_limit-3]+'...'
    
    # some more methods for checking Element's attributes:
    def getattr(self):
        return ['CallName', 'ReprName', 'Pt', 'PtFunc', 'Val', 'Len',
                'LenFunc', 'Type', 'Repr', 'Trans', 'TransFunc']
    
    def showattr(self):
        for a in self.getattr():
            print('%s : %s' % (a, repr(self.__getattribute__(a))) )
    
    # cloning an Element, useful for "duplicating" an Element 
    # without keeping any dependency
    # used in Layer with Element
    # However,
    #...
    # This is not that true, as an object pointed by .Pt or .Len or .Trans
    # will not be updated to its clone()
    # Conclusion:
    # use this with care
    def clone(self):
        clone = self.__class__(
                 self.CallName, self.ReprName,
                 self.Pt, self.PtFunc,
                 self.Val, 
                 self.Len, self.LenFunc,
                 self.Repr,
                 self.Trans, self.TransFunc )
        return clone
    
    # standard method map() to map a string to the Element
    def map(self, string=''):
        if not self.is_transparent():
            l = self.map_len()
            if l is not None:
                self.Val = string[:l]
            else:
                self.Val = string
            if self.dbg >= DBG:
                log(DBG, '(Element) mapping %s on %s, %s' \
                    % (repr(string), self.CallName, repr(self)))
    
    def map_ret(self, string=''):
        self.map(string)
        return string[len(self):]
    
    # shar manipulation interface
    def to_shar(self):
        ret = shar()
        ret.set_buf(self())
        return ret
    
    def map_shar(self, sh):
        if not self.is_transparent():
            l = self.map_len()
            if l is not None:
                self.Val = sh.get_buf(l*8)
            else:
                self.Val = sh.get_buf()
            if self.dbg >= DBG:
                log(DBG, '(Element) mapping %s on %s, %s' \
                    % (repr(string), self.CallName, repr(self)))

class Int(Element):
    '''
    class defining a standard element, managed like an integer.
    It can be signed (int) or unsigned (uint),
    and support arbitrary byte-length:
        int8, int16, int24, int32, int40, int48, int56, int64, int72, ...
        uint8, uint16, uint24, uint32, ..., uint128, ...
        and why not int65536 !
    It is always byte-aligned (in term of length, at least).
    
    attributes:
    Pt: to point to another object or direct integer value;
    PtFunc: when defined, PtFunc(Pt) is used to generate the integer value;
    Val: when defined, overwrites the Pt (and PtFunc) integer value, 
         used when mapping a string buffer to the element;
    Type: type of integer for encoding, 8,16,24,32,40,48,56,64 bits signed or
          unsigned integer;
    Dict: dictionnary to use for a look-up when representing 
          the element into python;
    Repr: representation style, binary, hexa or human: human uses Dict 
          if defined;
    Trans: to define transparent element which has empty str() and len() to 0,
           it "nullifies" its existence; can point to something for automation;
    TransFunc: when defined, TransFunc(Trans) is used to automate the 
               transparency aspect: used e.g. for conditional element;
    '''
    # endianness is 'little' / 'l' or 'big' / 'b'
    _endian = 'big'
    # types format for struct library
    # 24 (16+8), 40 (32+8), 48 (32+16), 56 (32+16+8)
    _types = { 'int8':'b', 'int16':'h', 'int32':'i', 'int64':'q',
               #'int24':None, 'int40':None, 'int48':None, 'int56':None,
               'uint8':'B', 'uint16':'H', 'uint32':'I', 'uint64':'Q',
               #'uint24':None, 'uint40':None, 'uint48':None, 'uint56':None,
               }
    #
    # for object representation
    _reprs = ['hex', 'bin', 'hum']
    
    def __init__(self, CallName='', ReprName=None,
                 Pt=None, PtFunc=None, Val=None,
                 Type='int32', Dict=None, DictFunc=None,
                 Repr='hum',
                 Trans=False, TransFunc=None):
        if CallName or not self.CallName:
            self.CallName = CallName
        if ReprName is None:
            self.ReprName = ''
        else:
            self.ReprName = ReprName
        self.Pt = Pt
        self.PtFunc = PtFunc
        self.Val = Val
        self.Type = Type
        self.Dict = Dict
        self.DictFunc = DictFunc
        self.Repr = Repr
        self.Trans = Trans
        self.TransFunc = TransFunc
        # automated attributes:
        self.Len = int(self.Type.lstrip('uint'))//8
    
    def __setattr__(self, attr, val):
        # ensures no bullshit is provided into element's attributes 
        # (however, it is not a complete test...)
        if self.safe:
            if attr == 'CallName':
                if type(val) is not str or len(val) == 0:
                    raise AttributeError('CallName must be a non-null string')
            elif attr == 'ReprName':
                if type(val) is not str:
                    raise AttributeError('ReprName must be a string')
            elif attr == 'PtFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('PtFunc must be a function')
            elif attr == 'Val':
                if val is not None and not isinstance(val, (int, long)):
                    raise AttributeError('Val must be an int or long')
            elif attr == 'Type':
                cur = 0
                if val[cur] == 'u':
                    cur = 1
                if val[cur:cur+3] != 'int' or int(val[cur+3:]) % 8 != 0:
                    raise AttributeError('Type must be intX / uintX with X '\
                    'multiple of 8 bits (e.g. int24, uint32, int264, ...)')
            elif attr == 'DictFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('DictFunc must be a function')
            elif attr == 'Repr':
                if val not in self._reprs:
                    raise AttributeError('Repr %s does not exist, use in: %s' \
                          % (val, self._reprs))
            elif attr == 'TransFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('TransFunc must be a function')
        if attr == 'Type':
            self.Len = int(val.lstrip('uint'))//8
        object.__setattr__(self, attr, val)
    
    def __call__(self):
        # when no values are defined at all, arbitrary returns None:
        if self.Val is None and self.Pt is None:
            # instead of "return None" 
            # that triggers error when calling __str__() method
            return 0
        # else, Val overrides Pt capabilities:
        # transparency are not taken into account in __call__, 
        # only for the __str__ representation
        elif self.Val is not None: 
            return self.__confine( self.Val )
        elif self.PtFunc is not None: 
            if self.safe: 
                assert( type(self.PtFunc(self.Pt)) in (int, long) )
            return self.__confine(self.PtFunc(self.Pt))
        else:
            return self.__confine(int(self.Pt))
    
    def __confine(self, value):
        # unsigned
        if self.Type[0] == 'u':
            return max(0, min(2**(8*self.Len-1), value))
        # signed
        else:
            return max(-2**(8*self.Len-1), min(2**(8*self.Len-1)-1, value))
    
    def __str__(self):
        # manages Element transparency
        if self.is_transparent():
                return ''
        # otherwise returns standard string values
        return self.__pack()
    
    def __len__(self):
        if self.is_transparent(): 
            return 0
        return self.Len
    
    def bit_len(self):
        return 8*self.__len__()
    
    # map_len() is a-priori not needed in "Int" element, 
    # but still kept for Element API uniformity
    def map_len(self):
        return self.__len__()
    
    # define integer value
    def __int__(self):
        return self()
    
    def __bin__(self):
        # unsigned or positive signed:
        val = self()
        if self.Type[0] == 'u' \
        or self.Type[0] == 'i' and val >= 0 : 
            binstr = bin(val)[2:]
            if self._endian[0] == 'l':
                # little endian
                bs = '0'*(8*self.__len__() - len(binstr)) + binstr
                bs = [bs[i:i+8] for i in range(0, len(bs), 8)]
                bs.reverse()
                return ''.join(bs)
            else:
                # big endian
                return '0'*(8*self.__len__() - len(binstr)) + binstr
        # negative signed
        else : 
            # takes 2' complement to the signed val
            binstr = bin(val + 2**(8*self.__len__()-1))[2:]
            if self._endian[0] == 'l':
                # little endian
                bs = '1' + '0'*(8*self.__len__() - len(binstr) - 1) + binstr
                bs = [bs[i:i+8] for i in range(0, len(bs), 8)]
                bs.reverse()
                return ''.join(bs)
            else:
                # big endian
                return '1' + '0'*(8*self.__len__() - len(binstr) - 1) + binstr
    
    def __hex__(self):
        return hexlify(self.__pack())
    
    def __repr__(self):
        if self.Pt is None and self.Val is None:
            return repr(None)
        if self.Repr == 'hex':
            return '0x%s' % self.__hex__()
        elif self.Repr == 'bin':
            return '0b%s' % self.__bin__()
        elif self.Repr == 'hum':
            value = self()
            if self.DictFunc:
                if self.safe:
                    assert(hasattr(self.DictFunc(self.Dict), '__getitem__'))
                try:
                    val = '%i : %s' % (value, self.DictFunc(self.Dict)[value])
                except KeyError:
                    val = value
            elif self.Dict:
                try:
                    val = '%i : %s' % (value, self.Dict[value])
                except KeyError:
                    val = value
            else:
                val = value
            rep = repr(val)
            if rep[-1] == 'L':
                return rep[:-1]
            return rep
    
    def getattr(self):
        return ['CallName', 'ReprName', 'Pt', 'PtFunc', 'Val', 'Len',
                'Type', 'Dict', 'DictFunc', 'Repr', 'Trans', 'TransFunc']
    
    def showattr(self):
        for a in self.getattr():
            if a == "Dict" and self.Dict is not None:
                print('%s : %s' % ( a, self.__getattribute__(a).__class__) )
            else:
                print('%s : %s' % ( a, repr(self.__getattribute__(a))) )
    
    def clone(self):
        clone = self.__class__(
                 self.CallName, self.ReprName,
                 self.Pt, self.PtFunc,
                 self.Val, self.Type,
                 self.Dict, self.DictFunc, self.Repr, 
                 self.Trans, self.TransFunc )
        #clone._endian = self._endian
        return clone
    
    def map(self, string=''):
        if not self.is_transparent():
            # error log will be done by the Layer().map() method
            # but do this not to throw exception
            if len(string) < self.Len:
                if self.dbg >= WNG:
                    log(WNG, '(%s) %s map(string) : string not long enough' \
                        % (self.__class__, self.CallName))
                return
            self.Val = self.__unpack(string[:self.Len])
    
    def map_ret(self, string=''):
        l = self.__len__()
        if 0 < l <= len(string):
            self.map(string)
            return string[l:]
        else:
            return string
    
    def __pack(self):
        # manage endianness (just in case...)
        if self._endian[0] == 'l':
            e = '<'
        else:
            e = '>'
        if self.Len == 0:
            return ''
        elif self.Len in (1, 2, 4, 8):
            # standard types for using Python struct
            return pack(e+self._types[self.Type], self())
        elif self.Type[0] == 'u':
            # non-standard unsigned int types
            return self.__pack_uX(e)
        else:
            # non-standard signed int types
            return self.__pack_iX(e)
    
    def __unpack(self, string):
        if self._endian[0] == 'l':
            e = '<'
        else:
            e = '>'
        if self.Len == 0:
            return
        elif self.Len in (1, 2, 4, 8):
            # standard types for using Python struct
            return unpack(e+self._types[self.Type], string[:self.Len])[0]
        elif self.Type[0] == 'u':
            # non-standard unsigned int types
            return self.__unpack_uX(string[:self.Len], e)
        else:
            # non-standard signed int types
            return self.__unpack_iX(string[:self.Len], e)
    
    def __pack_uX(self, e='>'):
        if e == '<':
            # little endian, support indefinite uint (e.g. uint3072)
            if self.Len <= 8:
                return pack('<Q', self())[:self.Len]
            else:
                #'''
                u8 = decompose(0x100, self())
                # pad with 0 until the right length
                if len(u8) < self.Len:
                    u8.extend( [0]*(self.Len-len(u8)) )
                return pack('<'+self.Len*'B', *u8)
        else:
            # big endian, support indefinite uint too
            if self.Len <= 8:
                return pack('>Q', self())[-self.Len:]
            else:
                u64 = decompose(0x10000000000000000, self())
                u64_len = 8*len(u64)
                u64_pad = 0
                if u64_len < self.Len:
                    rest_len = self.Len - u64_len
                    u64_pad = rest_len // 8
                    if rest_len % 8:
                        u64_pad += 1
                    u64.extend( [0]*u64_pad )
                u64.reverse()
                return pack('>'+len(u64)*'Q', *u64)[-self.Len:]
    
    def __pack_iX(self, e='>'):
        val = self()
        # positive values are encoded just like uint
        if val >= 0:
            return self.__pack_uX(e)
        #
        # negative values, 2's complement encoding
        if e == '<':
            # little endian
            if self.Len <= 8:
                return pack('<Q', 2**(self.Len*8) - abs(val))[:self.Len]
            else:
                i8 = decompose(0x100, 2**(self.Len*8) - abs(val))
                if len(i8) < self.Len:
                    i8.extend( [0]*(self.Len-len(i8)) )
                return pack('<'+self.Len*'B', *i8)
        else:
            # big endian
            if self.Len <= 8:
                return pack('>Q', 2**(self.Len*8) - abs(val))[-self.Len:]
            else:
                i8 = decompose(0x100, 2**(self.Len*8) - abs(val))
                if len(i8) < self.Len:
                    i8.extend( [0]*(self.Len-len(i8)) )
                i8.reverse()
                return pack('>'+self.Len*'B', *i8)
    
    def __unpack_uX(self, string, e='>'):
        if e == '<':
            # little endian, support indefinite uint (e.g. uint3072)
            if self.Len <= 8:
                return unpack('<Q', string + '\0'*(8 - self.Len))[0]
            else:
                u8 = unpack('<'+self.Len*'B', string)
                u8.reverse()
                return reduce(lambda x,y: (x<<8)+y, u8)
        else:
            # big endian, support indefinite uint (e.g. uint3072)
            if self.Len <= 8:
                return unpack('>Q', '\0'*(8 - self.Len) + string)[0]
            else:
                #'''
                u64_len, u64_pad = self.Len // 8, self.Len % 8
                if u64_pad:
                    u64_len += 1
                    string = '\0'*u64_pad + string
                u64 = unpack('>'+u64_len*'Q', string)
                return reduce(lambda x,y:(x<<64)+y, u64)
    
    def __unpack_iX(self, string, e='>'):
        if e == '<':
            # little endian
            if ord(string[-1]) & 0x80 == 0:
                # check if it is a positive value
                return self.__unpack_uX(string, e)
            elif self.Len <= 8:
                return unpack('<Q', string + '\0'*(8 - self.Len))[0] \
                       - 2**(self.Len*8)
            else:
                i8 = unpack('<'+self.Len*'B', string)
                i8.reverse()
                return reduce(lambda x,y:(x<<8)+y, i8) - 2**(self.Len*8)
        else:
            # big endian
            if ord(string[0]) & 0x80 == 0:
                # check if it is a positive value
                return self.__unpack_uX(string, e)
            elif self.Len <= 8:
                return unpack('>Q', '\0'*(8 - self.Len) + string)[0] \
                       - 2**(self.Len*8)
            else:
                i8 = unpack('>'+self.Len*'B', string)
                return reduce(lambda x,y:(x<<8)+y, i8) - 2**(self.Len*8)
    
    # shar manipulation interface
    def to_shar(self):
        ret = shar()
        ret.set_buf(self.__str__())
        return ret
    
    def map_shar(self, sh):
        if len(sh)*8 < self.Len:
            if self.dbg >= WNG:
                log(WNG, '(%s) %s map(string) : shar buffer not long enough' \
                    % (self.__class__, self.CallName))
            return
        # standard handling
        if not self.is_transparent():
            self.map(sh.get_buf(len(self)*8))
    
class Bit(Element):
    '''
    class defining a standard element, managed like a bit (e.g. a flag)
    or bit-stream of variable bit length
    Values are corresponding to unsigned integer: from 0 to pow(2, bit_len)-1.
    It does not require to be byte-aligned.
    
    attributes:
    Pt: to point to another object or direct integer value;
    PtFunc: when defined, PtFunc(Pt) is used to generate the integer value;
    Val: when defined, overwrites the Pt (and PtFunc) integer value, 
         used when mapping string to the element;
    BitLen: length in bits of the bit stream;
    BitLenFunc: to be used when mapping string with variable bit-length, 
                BitLenFunc(BitLen) is used;
    Dict: dictionnary to use for a look-up when representing 
          the element into python;
    Repr: representation style, binary, hexa or human: human uses Dict;
    Trans: to define transparent element which has empty str() and len() to 0,
           it "nullifies" its existence; can point to something for automation;
    TransFunc: when defined, TransFunc(Trans) is used to automate the 
               transparency aspect: used e.g. for conditional element;
    '''
    # for object representation
    _reprs = ['hex', 'bin', 'hum']
    
    def __init__(self, CallName='', ReprName=None, 
                 Pt=None, PtFunc=None, Val=None, 
                 BitLen=1, BitLenFunc=None,
                 Dict=None, DictFunc=None, Repr='bin', 
                 Trans=False, TransFunc=None):
        if CallName or not self.CallName:
            self.CallName = CallName
        if ReprName is None: 
            self.ReprName = ''
        else: 
            self.ReprName = ReprName
        self.Pt = Pt
        self.PtFunc = PtFunc
        self.Val = Val
        self.BitLen = BitLen
        self.BitLenFunc = BitLenFunc
        self.Dict = Dict
        self.DictFunc = DictFunc
        self.Repr = Repr
        self.Trans = Trans
        self.TransFunc = TransFunc
    
    def __setattr__(self, attr, val):
        # ensures no bullshit is provided into element's attributes 
        # (however, it is not a complete test...)
        if self.safe:
            if attr == 'CallName':
                if type(val) is not str or len(val) == 0:
                    raise AttributeError('CallName must be a non-null string')
            elif attr == 'ReprName':
                if type(val) is not str:
                    raise AttributeError('ReprName must be a string')
            elif attr == 'PtFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('PtFunc must be a function')
            elif attr == 'Val':
                if val is not None and not isinstance(val, (int, long)):
                    raise AttributeError('Val must be an int')
            elif attr == 'BitLenFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('BitLenFunc must be a function')
            elif attr == 'DictFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('DictFunc must be a function')
            elif attr == 'Repr':
                if val not in self._reprs:
                    raise AttributeError('Repr %s does not exist, use in: %s' \
                          % (val, self._reprs))
            elif attr == 'TransFunc':
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError('TransFunc must be a function')
        object.__setattr__(self, attr, val)
    
    def __call__(self):
        if self.Val is None and self.Pt is None: return 0
        if self.Val is not None: return self.__confine(self.Val) 
        elif self.PtFunc is not None:
            if self.safe:
                assert( type(self.PtFunc(self.Pt)) is int )
            return self.__confine(self.PtFunc(self.Pt))
        else: return self.__confine(int(self.Pt))
    
    def __confine(self, value):
        # makes sure value provided does not overflow bit length
        return max( 0, min( pow(2, self.bit_len())-1, value ))
    
    def __str__(self):
        # return the string representation of the integer value
        # big-endian encoded
        # left-aligned according to the bit length
        # -> last bits of the last byte are nullified
        # 
        # manages Element transparency
        if self.is_transparent():
            return ''
        # do it the dirty way:
        h = self.__hex__()
        if not h:
            return ''
        if len(h) % 2: h = ''.join(('0', h))
        return str(shtr(unhexlify(h)) << (8-(self.bit_len()%8))%8)
    
    def _shar__str__(self):
        bitlen = self.bit_len()
        if bitlen == 0:
            return ''
        ret = shar()
        ret.set_uint(self(), bitlen)
        return ret.to_buf()
    
    def __len__(self):
        # just for fun here, 
        # but do not use this in program...
        bitlen = self.bit_len()
        if bitlen % 8:
            return (bitlen//8) + 1
        return bitlen//8
    
    def bit_len(self):
        # manages Element transparency
        if self.is_transparent():
            return 0
        # and standard bit length processing
        if self.BitLenFunc is not None:
            if self.safe:
                assert( type(self.BitLenFunc(self.BitLen)) is int )
            return self.BitLenFunc(self.BitLen)
        else:
            if self.safe:
                assert( type(self.BitLen) is int )
            return self.BitLen
    
    def map_len(self):
        bitlen = self.bit_len()
        if bitlen % 8:
            return (bitlen//8)+1
        return bitlen//8
    
    def __hex__(self):
        bitlen = self.bit_len()
        if not bitlen:
            return ''
        hexa = hex(self())[2:]
        if hexa[-1] == 'L':
            # thx to Python to add 'L' for long on hex repr...
            hexa = hexa[:-1]
        if self.bit_len()%4: 
            return '0'*(self.bit_len()//4 + 1 - len(hexa)) + hexa
        else: 
            return '0'*(self.bit_len()//4 - len(hexa)) + hexa
    
    def __int__(self):
        return self()
        
    def __bin__(self):
        bitlen = self.bit_len()
        if not bitlen:
            return ''
        binary = format(self(), 'b')
        return (bitlen - len(binary))*'0' + binary
        
    def __repr__(self):
        if self.Repr == 'hex': return '0x%s' % self.__hex__()
        elif self.Repr == 'bin': return '0b%s' % self.__bin__()
        elif self.Repr == 'hum':
            value = self()
            if self.DictFunc:
                if self.safe:
                    assert(hasattr(self.DictFunc(self.Dict), '__getitem__'))
                try: val = '%i : %s' % (value, self.DictFunc(self.Dict)[value])
                except KeyError: val = value
            elif self.Dict:
                try: val = '%i : %s' % (value, self.Dict[value])
                except KeyError: val = value
            else:
                val = value
            #return repr(val)
            rep = repr(val)
            if rep[-1] == 'L':
                rep = rep[:-1]
            return rep
    
    def getattr(self):
        return ['CallName', 'ReprName', 'Pt', 'PtFunc', 'Val', 'BitLen',
                'BitLenFunc', 'Dict', 'DictFunc', 'Repr', 'Trans', 'TransFunc']
    
    def showattr(self):
        for a in self.getattr():
            if a == 'Dict' and self.Dict is not None: 
                print('%s : %s' % ( a, self.__getattribute__(a).__class__) )
            else: 
                print('%s : %s' % ( a, repr(self.__getattribute__(a))) )
    
    # cloning an element, used in set of elements
    def clone(self):
        clone = self.__class__(
                 self.CallName, self.ReprName,
                 self.Pt, self.PtFunc,
                 self.Val, 
                 self.BitLen, self.BitLenFunc,
                 self.Dict, self.DictFunc, self.Repr,
                 self.Trans, self.TransFunc )
        return clone
    
    def map(self, string=''):
        # map each bit of the string from left to right
        # using the shtr() class to shift the string
        # string must be ascii-encoded (see shtr)
        if not self.is_transparent():
            self.map_bit( shtr(string).left_val(self.bit_len()) )
    
    def map_bit(self, value=0):
        # map an int / long value
        if self.safe:
            assert( 0 <= value <= pow(2, self.bit_len()) )
        self.Val = value
    
    def map_ret(self, string=''):
        if self.is_transparent():
            return string
        else:
            shtring = shtr(string)
            bitlen = self.bit_len()
            self.map_bit( shtring.left_val(bitlen) )
            return shtring << bitlen
    
    # shar manipulation interface
    def to_shar(self):
        ret = shar()
        ret.set_uint(self(), self.bit_len())
        return ret
    
    def map_shar(self, sh):
        if not self.is_transparent():
            self.map_bit( sh.get_uint(self.bit_len()) )
    
#------------------------------------------------------------------------------#
# Layer definition
#------------------------------------------------------------------------------#
class Layer(object):
    '''
    class built from stack of "Str", "Int", "Bit" and "Layer" objects
    got from the initial constructorList.
    Layer object is recursive: it can contain other Layer() instances
    Layer does not require to be byte-aligned. This happens depending of the
    presence of Bit() instances.
    
    when instantiated:
    clones the list of "Str", "Int", "Bit" elements in the constructorList
    to build a dynamic elementList, that can be changed afterwards (adding /
    removing objects);
    A common hierarchy level for the whole Layer is defined, it is useful 
    when used into "Block" to create hierarchical relationships: 
        self.hierarchy (int), self.inBlock (bool)
        when .inBlock is True, provides: .get_payload(), .get_header(), 
             .has_next(), .get_next(), .get_previous(), and .Block
    It provides several methods for calling elements in the layer:
        by CallName / ReprName passed in attribute
        by index in the elementList
        can be iterated too
        and many other manipulations are defined
    It has also some common methods with "Str", "Int" and "Bit" to emulate 
    a common handling:
    __str__, __len__, __int__, bit_len, getattr, showattr, show, map
    '''
    #
    # debugging threshold for Layer:
    dbg = ERR
    # add some sanity checks
    #safe = True
    safe = False
    # define the type of str() and map() method
    _byte_aligned = True
    # reserved attributes:
    Reservd = ['CallName', 'ReprName', 'elementList', 'Len', 'BitLen',
               'hierarchy', 'inBlock', 'Trans', 'ConstructorList',
               'dbg', 'Reservd']
    #
    # represent transparent elements in __repr__()
    _repr_trans = True
    
    # structure description:
    constructorList = []
    
    def __init__(self, CallName='', ReprName='', Trans=False, **kwargs):
        if type(CallName) is not str:
            raise AttributeError('CallName must be a string')
        elif len(CallName) == 0:
            self.CallName = self.__class__.__name__
        else:
            self.CallName = CallName
        if type(ReprName) is str and len(ReprName) > 0: 
            self.ReprName = ReprName
        else: 
            self.ReprName = ''
        self.elementList = []
        self.set_hierarchy(0)
        self.inBlock = False
        self.Trans = Trans
        
        CallNames = []
        for e in self.constructorList:
            # This is for little players
            #if isinstance(e, Element):
            # OK, now let's put the balls on the table and
            # make Layer recursive (so will have Layer() into Layer())
            if isinstance(e, (Element, Layer)):
                if e.CallName in self.Reservd:
                    if self.safe or self.dbg >= ERR:
                        log(ERR, '(Layer - %s) using a reserved '
                            'attribute as CallName %s: aborting...' \
                          % (self.__class__, e.CallName))
                    return
                if e.CallName in CallNames:
                    if self.dbg >= WNG:
                        log(WNG, '(Layer - %s) different elements have ' \
                           'the same CallName %s' % (self.__class__, e.CallName))
                if isinstance(e, Element):
                    self.append(e.clone())
                # do not clone Layer() as it breaks dynamic element inside
                # i.e. element with PtFunc, LenFunc, DictFunc, TransFunc defined
                # TODO: patch Layer().clone() method to solve this...
                # lets try with deepcopy()
                elif isinstance(e, Layer):
                    self.append(e.clone())
            CallNames.append(e.CallName)
        
        # check for bit alignment until we lost information on the Layer length
        # also check if fixed length can be deduced
        self.BitLen = 0
        for e in self.elementList:
            if self.dbg >= DBG:
                log(DBG, '(Layer - %s) length verification for %s' \
                    % (self.__class__, e.CallName))
            if isinstance(e, Bit):
                self.BitLen += e.bit_len()
            elif hasattr(e, 'Len') and type(e.Len) is int:
                self.BitLen += (e.Len)*8
            else:
                self.BitLen, self.Len = 'var', 'var'
                break
        if type(self.BitLen) is int :
            if self.BitLen % 8:
                if self.dbg >= WNG and self._byte_aligned:
                    log(WNG, '(Layer - %s) Elements seem not to be '\
                        'byte-aligned: hope you expect it!' \
                        % self.__class__)
                # record length in bit (precise one) and in bytes (unprecised)
                self.Len = 1 + self.BitLen//8
            else:
                self.Len = self.BitLen//8
        #
        # check additional args that would correspond to contained Element
        args = kwargs.keys()
        if self.dbg >= DBG:
            log(DBG, '(Layer - %s) init kwargs: %s' % (self.__class__, args))
        for e in self:
            if hasattr(e, 'CallName') and hasattr(e, 'Pt') \
            and e.CallName in args:
                e.Pt = kwargs[e.CallName]
    
    # define some basic list facilities for managing elements into the Layer, 
    # through the "elementList" attribute:
    def __iter__(self):
        if 'elementList' in self.__dict__.keys():
            return self.__dict__['elementList'].__iter__()
        else: return [].__iter__()
    
    def __getitem__(self, num):
        return self.elementList[num]
    
    def __getslice__(self, i, j):
        l = Layer('_slice_')
        if not i or i < 0:
            i=0
        #maxj = len(self.elementList)-1
        maxj = len(self.elementList)
        if not j or j > maxj:
            j = maxj
        #
        for k in xrange(i, j):
            l.append( self[k] )
        return l
    
    def __setitem__(self, num, value):
        # special handling here: 
        # use to override the element value 
        # with its "Val" attribute (like when mapping a string)
        self.elementList[num].Val = value
    
    def append(self, element):
        #if isinstance(element, Element):
        # make Layer recursive:
        if isinstance(element, (Element, Layer)):
            if self.dbg >= WNG and element.CallName in self.getattr():
                log(WNG, '(Layer - %s) different elements have the same '\
                         'CallName %s' % (self.__class__, element.CallName))
            self.elementList.append(element)
    
    def __lshift__(self, element):
        self.append(element)
        if isinstance(element, Layer):
            element.inc_hierarchy(self.hierarchy)
    
    def insert(self, index, element):
        CallNames = self.getattr()
        #if isinstance(element, Element):
        # make Layer recursive:
        if isinstance(element, (Element, Layer)):
            if self.dbg >= WNG and element.CallName in CallNames:
                log(WNG, '(Layer - %s) different elements have the same '\
                         'CallName %s' % (self.__class__, element.CallName))
            self.elementList.insert(index, element)
    
    def __rshift__(self, element):
        self.insert(0, element)
        if isinstance(element, Layer):
            element.inc_hierarchy(self.hierarchy)
    
    def extend(self, newElementList):
        for e in newElementList:
            self.append(e)
    
    def remove(self, element):
        for e in self:
            if e == element:
                self.elementList.remove(element)
    
    def replace(self, current_element, new_element):
        # check index of the element ro replace
        index = 0
        for elt in self.elementList:
            if elt == current_element:
                self.remove(current_element)
                self.insert(index, new_element)
                return
            else:
                index += 1
    
    # define some attribute facilities for managing elements 
    # by their CallName into the Layer
    # warning: dangerous when parsing data into Layer, 
    # with elements which could have same CallName
    # 
    # list facilities can be preferred in this case
    def __getattr__(self, name):
        names = [x.CallName for x in self.elementList]
        if name in names:
            return self.elementList[ names.index(name) ]
        names = [x.ReprName for x in self.elementList]
        if name in names:
            return self.elementList[ names.index(name) ]
        #
        return object.__getattribute__(self, name)
        #return self.__getattribute__(name)
        #return getattr(self, name)
    
    def __setattr__(self, name, value):
        # special handling here: use to override the element value 
        # with its "Val" attribute (like when mapping a string)
        for e in self:
            if name == e.CallName or name == e.ReprName: 
                e.Val = value
                return
        return object.__setattr__(self, name, value)
        raise AttributeError( '"Layer" has no "%s" attribute: %s' \
              % (name, self.getattr()) )
    
    def __hasattr__(self, name):
        for e in self:
            if name == e.CallName or name == e.ReprName: 
                return True
        #return object.__hasattr__(self, name): 
        # not needed (does not work in the code... but works in python...)
        raise AttributeError( '"Layer" has no "%s" attribute: %s' \
              % (name, self.getattr()) )
    
    # method for managing the Layer hierarchy (easy):
    def set_hierarchy(self, hier=0):
        self.hierarchy = hier
        for e in self:
            if isinstance(e, Layer):
                e.set_hierarchy(hier)
        
    def inc_hierarchy(self, ref=None):
        if ref is None:
            self.set_hierarchy(self.hierarchy+1)
        else: 
            self.set_hierarchy(self.hierarchy+ref+1)
        #for l in self:
        #    if isinstance(l, Layer):
        #        l.hierarchy = self.hierarchy
    
    def dec_hierarchy(self, ref=None):
        if ref is None: 
            self.set_hierarchy(self.hierarchy-1)
        else: 
            self.set_hierarchy(self.hierarchy+ref-1)
        #for l in self:
        #    if isinstance(l, Layer):
        #        l.hierarchy = self.hierarchy
    
    # define same methods as "Element" type for being use the same way
    def __str__(self):
        if self.dbg >= DBG:
            log(DBG, '(Layer.__str__) entering str() for %s' % self.CallName)
        # First take care of transparent Layer (e.g. in L3Mobile)
        if hasattr(self, 'Trans') and self.Trans:
            return ''
        # dispatch to the right method depending of byte alignment
        if self._byte_aligned is True:
            return self.__str_aligned()
        else:
            return self.__str_unaligned()
    
    def __str_unaligned(self):
        # then init resulting string 
        # and bit offset needed to shift unaligned strings
        s = []
        off = 0
        # loop on each element into the Layer
        # also on Layer into Layer...
        for e in self:
            shtr_e, bitlen_e = e.shtr(), e.bit_len()
            rest_e = bitlen_e % 8
            if self.dbg >= DBG:
                log(DBG, '(Layer.__str__) %s: %s, %i, offset: %i' \
                    % (e.CallName, hexlify(shtr_e), bitlen_e, off))
            # if s is not byte-aligned and e is not transparent
            # update the last component of s
            if off and shtr_e:
                # 1st update last bits of s with MSB of e, 
                # before stacking with the rest of e
                # (8 - off) is the room left in the LSB of s
                s[-1] = ''.join((s[-1][:-1],
                                  chr(ord(s[-1][-1]) + shtr_e.left_val(8-off)),
                                  (shtr_e << (8-off))
                                ))
                # take care in case the shifting of e voids its last byte
                if rest_e and rest_e-(8-off) <= 0:
                    s[-1] = s[-1][:-1]
                # update offset
                if rest_e:
                    off += bitlen_e
                    off %= 8
            # in case s is already aligned, append a new component to s
            elif shtr_e:
                s.append(shtr_e)
                # update offset
                if rest_e:
                    off += rest_e
            if self.dbg >= DBG:
                log(DBG, '(Layer.__str__) %s' % hexlify(s))
        # well done!
        return ''.join(s)
    
    def __str_aligned(self):
        s = []
        BitStream = ''
        # loop on each element in the Layer
        # also on Layer into Layer...
        for e in self:
            # need special processing for stacking "Bit" element: 
            #   using "BitStream" variable
            #   works only with contiguous "Bit" elements 
            #   to avoid byte-misalignment of other element in the Layer 
            #   (and programming complexity with shifting everywhere...)
            if isinstance(e, Bit):
                # manage element transparency with (Trans, TranFunc)
                # and build a bitstream ('100110011...1101011') from Bit values
                if not e.is_transparent():
                    BitStream += str(e.__bin__())
                # when arriving on a byte boundary from bitstream, 
                # create bytes and put it into the s variable
                if len(BitStream) >= 8:
                    while 1:
                        s.append( pack('!B', int(BitStream[:8], 2)) )
                        BitStream = BitStream[8:]
                        if len(BitStream) < 8:
                            break
                if self.dbg >= DBG:
                    log(DBG, '(Element) %s: %s, %s\nBitstream: %s' \
                        % (e.CallName, e(), e.__bin__(), BitStream))
            # when going to standard Str or Int element, 
            # or directly end of __str__ function 
            # verify the full BitStream has been consumed
            # and continue to build the resulting string easily...
            else:
                # possible byte mis-alignment for Str / Int is not managed...
                self.__is_aligned(BitStream)
                BitStream = ''
                if isinstance(e, Layer) and not e.Trans \
                or isinstance(e, Element):
                    s.append( str(e) )
        self.__is_aligned(BitStream)
        return ''.join(s)
    
    def __is_aligned(self, BitStream):
        if BitStream and self.dbg >= ERR:
            log(ERR, '(Layer - %s) some of the Bit elements have not been ' \
                'stacked in the "str(Layer)"\nremaining bitstream: %s' \
                % (self.__class__, BitStream))
            if self.safe:
                assert(not BitStream)
    
    def __call__(self):
        return self.__str__()
    
    def __len__(self):
        return len(self.__str__())
    
    def shtr(self):
        return shtr(self.__str__())
    
    def bit_len(self):
        # just go over all internal elements to track their own bit length
        # updated attributes initialized when Layer was constructed
        self.BitLen = 0
        for e in self:
            if hasattr(e, 'bit_len'):
                self.BitLen += e.bit_len()
            elif hasattr(e, '__len__'):
                self.BitLen += len(e)*8
        self.Len = 1 + (self.BitLen // 8) if self.BitLen % 8 \
                   else (self.BitLen // 8)
        return self.BitLen
    
    def __hex__(self):
        bit_len = self.bit_len()
        hex_len = bit_len/4
        if bit_len%4:
            hex_len += 1
        #
        return self.__str__().encode('hex')[:hex_len]
    
    def __bin__(self):
        bits = []
        for e in self:
            bits.append( e.__bin__() )
        return ''.join(bits)
    
    def __int__(self):
        # big endian integer representation of the string buffer
        if self._byte_aligned:
            return shtr(self).left_val(len(self)*8)
        else:
            return shtr(self).left_val(self.bit_len())
    
    def __repr__(self):
        t = ''
        if self.Trans:
            t = ' - transparent '
        s = '<%s[%s]%s: ' % ( self.ReprName, self.CallName, t )
        for e in self:
            if self._repr_trans or not e.is_transparent():
                s += '%s(%s):%s, ' % ( e.CallName, e.ReprName, repr(e) )
        s = s[:-2] + '>'
        return s
    
    def map_len(self):
        return len(self)
    
    def getattr(self):
        return [e.CallName for e in self.elementList]
    
    def showattr(self):
        for a in self.getattr():
            print('%s : %s' % ( a, repr(self.__getattr__(a))) )
    
    def clone(self):
        return deepcopy(self)
    
    def is_transparent(self):
        if self.Trans:
            return True
        else:
            return False
    
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
        str_lst = [e.show().replace('\n', '\n ') for e in self]
        # insert spaces for nested layers and filter out empty content
        str_lst = [' %s\n' % s for s in str_lst if s]
        # insert layer's title
        str_lst.insert(0, '### %s[%s]%s ###\n' % (re, self.CallName, tr))
        # return full inline string without last CR
        return ''.join(str_lst)[:-1]
    
    def map(self, string=''):
        if self.dbg >= DBG:
            log(DBG, '(Layer.map) entering map() for %s' % self.CallName)
        # First take care of transparent Layer (e.g. in L3Mobile)
        if hasattr(self, 'Trans') and self.Trans:
            return
        # dispatch to the right method depending of byte alignment
        if self._byte_aligned is True:
            self.__map_aligned(string)
        else:
            self.__map_unaligned(string)
    
    def __map_unaligned(self, string=''):
        s = shtr(string)
        # otherwise go to map() over all elements
        for e in self:
            if self.dbg >= DBG:
                log(DBG, '(Layer.__map_unaligned) %s, bit length: %i' \
                    % (e.CallName, e.bit_len()))
                log(DBG, '(Layer.__map_unaligned) string: %s' % hexlify(s))
            # this is beautiful
            s = e.map_ret(s)
    
    def __map_aligned(self, string=''):
        # Bit() elements are processed intermediary: 
        # 1st placed into BitStack
        # and when BitStack is byte-aligned (check against BitStack_len)
        # string buffer is then mapped to it
        self.__BitStack = []
        self.__BitStack_len = 0
        # Furthermore, it manages only contiguous Bit elements 
        # for commodity... otherwise, all other elements should be shifted
        #
        for e in self:
            # special processing for Bit() element:
            if isinstance(e, Bit):
                self.__add_to_bitstack(e)
                # if BitStack is byte aligned, map string to it:
                if self.__BitStack_len % 8 == 0:
                    string = self.__map_to_bitstack(string)
            # for other elements (Str(), Int(), Layer()), standard processing:   
            else:
                if self.__BitStack_len > 0 and self.dbg >= ERR:
                    log(WNG, '(Layer - %s) some of the Bit elements have not ' \
                        'been mapped in the "Layer": not byte-aligned' \
                        % self.__class__)
                if isinstance(e, (Layer, Element)) and not e.is_transparent():
                    if len(string) < e.map_len() and self.dbg >= WNG:
                        log(WNG, '(Layer - %s) String buffer not long ' \
                            'enough for %s' % (self.__class__, e.CallName))
                        #if self.safe:
                        #    return
                    e.map(string)
                    string = string[e.map_len():]
        # delete .map() *internal* attributes
        del self.__BitStack
        del self.__BitStack_len
    
    def __add_to_bitstack(self, bit_elt):
        # check for Bit() element transparency
        if not bit_elt.is_transparent():
            self.__BitStack += [bit_elt]
            self.__BitStack_len += bit_elt.bit_len()
            
    def __map_to_bitstack(self, string):
        # 1st check if string is long enough for the prepared BitStack
        if len(string) < self.__BitStack_len//8 and self.dbg >= ERR:
            log(ERR, '(Layer - %s) String buffer not long enough for %s' \
                % (self.__class__, self.__BitStack[-1].CallName))
            #if self.safe:
            #    return
        # string buffer parsing is done through intermediary
        # string buffer "s_stack"
        s_stack = string[:self.__BitStack_len//8]
        # create a bitstream "s_bin" for getting the full BitStack
        s_bin = ''
        for char in s_stack:
            # convert to bitstream thanks to python native bit repr
            s_bin_tmp = bin(ord(char))[2:]
            # prepend 0 to align on byte (python does not do it)
            # and append to the bitstream "s_bin" (string of 0 and 1)
            s_bin = ''.join((s_bin, (8-len(s_bin_tmp))*'0', s_bin_tmp))
        # map the bitstream "s_bin" into each BitStack element
        for bit_elt in self.__BitStack:
            bitlen = bit_elt.bit_len()
            if bitlen:
                # convert the bitstream "s_bin" into integer 
                # according to the length in bit of bit_elt
                bit_elt.map_bit( int(s_bin[:bit_elt.bit_len()], 2) )
                # truncate the "s_bin" bitstream
                s_bin = s_bin[bit_elt.bit_len():]
        # consume the global string buffer that has been mapped 
        # (from s_stack internal variable)
        # and reinitialize self.__BitStack* attributes
        string = string[self.__BitStack_len//8:]
        self.__BitStack = []
        self.__BitStack_len = 0
        # finally return string to parent method .map()
        return string
    
    # map_ret() maps a buffer to a Layer, the unaligned way,
    # and returns the rest of the buffer that was not mapped
    def map_ret(self, string=''):
        if self.dbg >= DBG:
            log(DBG, '(Layer.map_ret) entering map_ret() for %s' % self.CallName)
        # First take care of transparent Layer (e.g. in L3Mobile)
        if hasattr(self, 'Trans') and self.Trans:
            return string
        if self._byte_aligned is True:
            self.__map_aligned(string)
            return string[len(self):]
        else:
            # actually, map_ret() is only interesting for unaligned layers
            s = shtr(string)
            for e in self:
                if self.dbg >= DBG:
                    log(DBG, '(Layer.map_ret) %s, bit length: %i' \
                        % (e.CallName, e.bit_len()))
                    log(DBG, '(Layer.map_ret) string: %s' % hexlify(s))
                # this is beautiful
                s = e.map_ret(s)
            return s
    
    # define methods when Layer is in a Block:
    # next, previous, header: return Layer object reference
    # payload: returns Block object reference
    def get_index(self):
        if self.inBlock is not True: 
            return 0
        i = 0
        for l in self.Block:
            if l == self: return i
            else:  i += 1
        # could happen if Layer is placed in several Block()
        # and the last Block used is deleted
        return False
    
    def has_next(self):
        if self.inBlock is not True: 
            return False
        return self.Block.has_index(self.get_index()+1)
    
    def get_next(self):
        if self.has_next():
            return self.Block[self.get_index()+1]
        return RawLayer()
    
    def has_previous(self):
        if self.inBlock is not True: 
            return False
        index = self.get_index()
        if index <= 0:
            return False
        return self.Block.has_index(index-1)
        
    def get_previous(self):
        if self.has_previous():
            return self.Block[self.get_index()-1]
        return RawLayer()
        
    def get_header(self):
        if self.has_previous():
            index = self.get_index()
            i = index - 1
            while i >= 0:
                if self.Block[i].hierarchy == self.hierarchy-1:
                    return self.Block[i]
                else:
                    i -= 1
        return RawLayer()
    
    def get_payload(self):
        # return a Block, not a Layer like other methods 
        # for management into a Block
        pay = Block('pay')
        if self.has_next():
            index = self.get_index()
            for l in self.Block[ index+1 : ]:
                if l.hierarchy > self.hierarchy:
                    #pay.append( l.clone() )
                    # not needed to append a clone
                    # better keep reference to original layer
                    pay.append( l )
                else:
                    break
            if pay.num() == 0:
                pay.append( RawLayer() )
            return pay
        pay.append( RawLayer() )
        return pay
    
    def num(self):
        return 1
    
    # this is to retrieve full Layer's dynamicity from a mapped layer
    def reautomatize(self):
        for e in self:
            if hasattr(e, 'reautomatize'):
                e.reautomatize()
    
    def parse(self, s=''):
        self.map(s)
    
    # shar manipulation interface
    def to_shar(self):
        if hasattr(self, 'Trans') and self.Trans:
            return shar()
        bits = []
        for e in self:
            bits.append( e.to_shar().get_bits() )
        s = shar()
        s.set_bits( bits )
        return s
    
    def map_shar(self, sh):
        if self.dbg >= DBG:
            log(DBG, '(Layer.map) entering map() for %s' % self.CallName)
        # First take care of transparent Layer (e.g. in L3Mobile)
        if hasattr(self, 'Trans') and self.Trans:
            return
        if not isinstance(sh, shar):
            sh = shar(sh)
        for e in self:
            e.map_shar(sh)


class RawLayer(Layer):
    constructorList = [
        Str(CallName='s', Pt='', Len=None),
        ]
    
    def __init__(self, s=''):
        Layer.__init__(self, CallName='raw')
        self.s.Pt = s

#------------------------------------------------------------------------------#
# Block definition
#------------------------------------------------------------------------------#
class Block(object):
    '''
    class to build a block composed of "Layer" objects
    define only methods, not content, which depends of the protocol or data model.
    
    when instantiated:
    defines a layerList;
    has methods to append, remove, extend, insert... layers into the block;
    provides several methods for calling layers in the block;
    to manage their hierarchy...;
    and use of signs such as >> << | to include layers into the block;
    
    have also same methods as "Layer": map, show, clone
    to emulate a common handling.
    '''
    # debugging thresholf for Block:
    dbg = 0
    
    def __init__(self, Name=''):
        if type(Name) is not str:
            raise AttributeError('CallName must be a string')
        self.CallName = Name
        self.layerList = []
        self.set_hierarchy(0)
        self.inBlock = False

    # define some basic list facilities for managing layers into the Block:
    def __iter__(self):
        if 'layerList' in self.__dict__.keys():
            return self.__dict__['layerList'].__iter__()
        else: return [].__iter__()
    
    def __getitem__(self, num):
        return self.layerList[num]
    
    def __getattr__(self, attr):
        for l in self:
            if attr == l.CallName: return l
        return object.__getattribute__(self, attr)
    
    def num(self):
        return len(self.layerList)
    
    def has_index(self, index):
        if index < self.num(): return True
        return False
    
    def append(self, obj):
        #if isinstance(obj, Layer):
        # and the following will be great !!!
        # this lib starts really to amaze me!
        if isinstance(obj, (Layer, Block)):
            obj.inBlock = True
            # do not re-assign Layer.Block when building a payload
            # referring to Layer.get_payload()
            if self.CallName != 'pay':
                obj.Block = self
            # better keep original Layer / Block hierarchy
            #obj.hierarchy = self.hierarchy
            self.layerList.append(obj)
    
    def extend(self, block):
    # would need some more intelligence...
        if isinstance(block, Block):
            self.layerList.extend(block.layerList)
    
    def insert(self, index, layer):
        if isinstance(layer, Layer):
            layer.inBlock = True
            layer.Block = self
            self.layerList.insert(index, layer)
    
    def remove(self, start, stop=None):
        if stop is None:
            self.layerList.remove( self.layerList[start] )
        else:
            for i in xrange(start, stop):
                self.layerList.remove( self.layerList[start] )
    
    # method for Block hierarchy setting
    def set_hierarchy(self, hier):
        self.hierarchy = hier
        for l in self:
            l.set_hierarchy(l.hierarchy + hier)
    
    # method for managing all the Layers hierarchy in the Block (easy):
    def inc_hierarchy(self, ref=0):
        #self.hierarchy += 1+ref
        #for l in self: l.hierarchy += 1+ref
        self.set_hierarchy(self.hierarchy+1+ref)
        
    def dec_hierarchy(self, ref=0):
        #self.hierarchy -= 1-ref
        #for l in self: l.hierarchy -= 1-ref
        self.set_hierarchy(self.hierarchy-1+ref)
    
    # define operations to insert layers into a block:
    # OR: block | new_layer, append the new_layer with the same hierarchy 
    # as last layer in the block
    def __or__(self, newLayer):
        self.append(newLayer)
        self[-1].set_hierarchy(self[-2].hierarchy)
        #for l in self[-1]:
        #    if isinstance(l, Layer):
        #        l.hierarchy = self[-1].hierarchy
    
    # LSHIFT: block << new_layer, append the new_layer with a higher hierarchy
    # than last layer in the block
    def __lshift__(self, newLayer):
        self.append(newLayer)
        if self.num() > 1:
            self[-1].inc_hierarchy( self[-2].hierarchy )
        else:
            self[-1].set_hierarchy(self.hierarchy)
    
    # RSHIFT: block >> new_layer, append the new_layer with a lower hierarchy
    # than last layer in the block
    def __rshift__(self, newLayer):
        self.append(newLayer)
        self[-1].dec_hierarchy( self[-2].hierarchy )
    
    # standard methods for common management with Layers
    def __str__(self):
        s = []
        for l in self:
            if not hasattr(self, 'Trans') or not l.Trans:
                s.append( str(l) )
        return ''.join(s)
    
    def shtr(self):
        return shtr(self.__str__())
    
    def __len__(self):
        return len(self.__str__())
    
    def __int__(self):
        # big endian integer representation of the string buffer
        if self._byte_aligned:
            return shtr(self).left_val(len(self)*8)
        else:
            return shtr(self).left_val(self.bit_len())
    
    def __repr__(self):
        s = '[[%s] ' % self.CallName
        for l in self:
            s += l.__repr__()
        s = s + ' [%s]]' % self.CallName
        return s
    
    def map_len(self):
        return len(self)
    
    def clone(self):
        clone = self.__class__()
        clone.CallName, clone.layerList = self.CallName, []
        for l in self:
            if isinstance(l, Layer): 
                clone.append( l.clone() )
            elif self.dbg >= ERR:
                log(ERR, '(Block - %s) cloning not implemented for: %s' \
                    % (self.__class__, l))
        return clone
    
    def show(self, with_trans=False):
        s = '%s[[[ %s ]]]\n' % (self.hierarchy*'\t', self.CallName)
        for l in self:
            s += '\t'*l.hierarchy + l.show(with_trans).replace('\n', '\n'+'\t'*l.hierarchy) + '\n'
        return s[:-1]
    
    def map(self, string=''):
        s = string
        for l in self:
            if not hasattr(l, 'Trans') or not l.Trans:
                if hasattr(l, 'parse'):
                    l.parse(s)
                else:
                    l.map(s)
                s = s[l.map_len():]
    
    # this is to retrieve full Block's dynamicity from a parsed or mapped one
    def reautomatize(self):
        for l in self:
            if hasattr(l, 'reautomatize'):
                l.reautomatize()


#------------------------------------------------------------------------------#
# testing routines 
#------------------------------------------------------------------------------#
class testTLV(Layer):
    _byte_aligned = True
    constructorList = [
        Int(CallName='T', ReprName='Tag', Type='uint8', \
            Dict={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
        Bit(CallName='F1', ReprName='Flag1', Pt=0, BitLen=1),
        Bit(CallName='F2', ReprName='Flag2', Pt=1, BitLen=2),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=13),
        # length in bytes (including header)
        Int(CallName='L', ReprName='Length', Type='uint8' ),
        Str(CallName='V', ReprName='Value', Pt='default value'),
        ]

    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.L.Pt = self.V
        self.L.PtFunc = lambda X: len(X)+3
        self.V.Len = self.L
        self.V.LenFunc = lambda X: int(X)-3

class testA(Layer):
    _byte_aligned = False
    constructorList = [
        Bit(CallName='T', ReprName='Tag', BitLen=6, Repr='hum',
            Dict={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
        Bit(CallName='F1', ReprName='Flag1', Pt=0, BitLen=4),
        Bit(CallName='F2', ReprName='Flag2', Pt=1, BitLen=2),
        # length in bytes
        Int(CallName='L', ReprName='Length', Type='uint8', Repr='hum'),
        Str(CallName='V', ReprName='Value', Pt='default value'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.L.Pt = self.V
        self.L.PtFunc = lambda X: len(X)
        self.V.Len = self.L
        self.V.LenFunc = lambda X: int(X)

class testB(Layer):
    _byte_aligned = False
    constructorList = [
        Bit(CallName='T', ReprName='Tag', BitLen=6, Repr='hum', \
            Dict={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
        Bit(CallName='F1', ReprName='Flag1', Pt=0, BitLen=4),
        Bit(CallName='F2', ReprName='Flag2', Pt=1, BitLen=2),
        # length in bits
        Int(CallName='L', Pt=0, ReprName='Length', Type='uint16', Repr='hum'),
        testA(T=1, V='super mega default value'),
        testA(T=2, V='ultra colored'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.L.PtFunc = lambda X: self[4].bit_len() + self[5].bit_len()

def test0():
    Int._endian = 'big'
    # aligned
    buf = '\x02\x22\xBB\x0Aabcdefg'
    T0 = testTLV()
    rest = T0.map_ret(buf)
    if str(T0) != buf:
        raise(Exception)
    T0.reautomatize()
    if str(T0) != buf:
        raise(Exception)

def test1():
    Int._endian = 'big'
    # non-aligned
    buf = '\xB0B\x07abcdefg'*4
    T1 = testA()
    rest = T1.map_ret(buf)
    if str(T1) != '\xb0B\x07abcdefg\xb0B\x07abcdefg\xb0B\x07abcdefg\xb0B\x07a`':
        raise(Exception)
    if str(rest)[:6] != '&6FVfp':
        raise(Exception)
    T1.reautomatize()
    if str(T1) != '\xb0B\x07abcdefg\xb0B\x07abcdefg\xb0B\x07abcdefg\xb0B\x07a`':
        raise(Exception)

def test2():
    Int._endian = 'big'
    # non-aligned
    T2 = testB()
    if str(T2) != '\x00\x10\x15\x00A\x18super mega default value\x08\x10\xd7'\
                  'V\xc7G&\x12\x066\xf6\xc6\xf7&V@':
        raise(Exception)
    buf = '\xc9\xd0B\x84v \xf2\x84\r*\xe0\xcc_\x8f\xfb\xc0\xcb\xc5\x8f\xdf\x88%\xb3'\
    'I\xc0\xe5*}]\xd7;R\x13\x87}\xa2E\xb1(\xb6\x03W`\x84&Z\x8a:eTv\xa6C\xb8\xd1'\
    '\xc48W\xa9\x82\xb1\xb89%\xc8\x18\x0b\x9e\xb7\xd6\x02\xb4\xaf\xc3J];k\x12\xf6'\
    '\xf9\x89\xb5\xdf\x92\xf8\xf0\xe7\t.0\xc2\x9c\xcd\xcb\xff1\xbd\x16K7\x1f\x95'\
    '\xbe\xbb\xda\xa8\xda\xb2\xe1x\x91U{\xf8\x06\xc1\x14\xc4%\xab\xe7S.\xac`[c'\
    '\xa8H/\x92\x8cRw\xfcpAAAA'
    rest = T2.map_ret(buf)
    if str(T2) != buf[:-4]:
        raise(Exception)
    if str(rest)[:5] != '\x04\x14\x14\x14\x10':
        raise(Exception)
    T2.reautomatize()
    if str(T2) != buf[:-4]:
        raise(Exception)

def test():
    test0()
    test1()
    test2()
#
#