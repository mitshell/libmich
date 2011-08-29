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
# * File Name : core/element.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

##############
# The Libmich#
##############
'''
# Python library, works with python 2.6 and over 
# not tested with older version, 
# neither with python 3.0 and higher (will not work anyway)
#
# version: 0.2
# author: Benoit Michau
#
# defines 3 kind of primary elements:
#   `Str': for byte stream
#   `Bit': for bit stream (actually assigned with integer value)
#   `Int': for integer value
#
# elements can be stacked into a layer: 
#   `Layer': stacks [Str, Bit, Byte, Layer]
#   allows to manage dependencies between elements in the layer 
#   and with surrounding layers (next, previous, header, payload),
#   when placed in a block,
#   
# layers can be stacked into a block:
#   `Block': stacks [Layer]
#   allows to manage intelligently dependencies between layers 
#   (next, previous, header, payload)
#   with a hierarchy attribute assigned to each layer.
#
# Particularly convinient for building / parsing complex and mixed data 
# structure like network protocols: IKEv2, SCTP, Diameter, EAP, UMA...
# or like file structure: zip, PNG, elf, MPEG4, ...
#
# TODO:
# + check how to manage a Layer self reference when computing the "len(Layer)" 
#   within a "Layer.Element" and still managing (Trans, TransFunc) transparency 
#       >>> with the current transparency handling, when mapping a string to a Layer, 
#           a "Layer.Element.Len" cannot point to "Layer" before the string has been mapped...
# + defines plenty of formats
'''

from struct import pack, unpack
from socket import inet_ntoa
from binascii import hexlify
from re import split, sub

# defines a tuple of function-like 
class Dummy(object):
    def __init__(self):
        pass
type_funcs = (type(lambda x:1), \
              type(Dummy().__init__), \
              type(inet_ntoa), \
             )
del Dummy

# defines debugging facility
debug_level = {1:'ERR', 2:'WNG', 3:'DBG'}
def debug(thres, level, string):
    if level<=thres:
        print '[%s] %s' %(debug_level[level], string)

# defines printing facility
def show(element):
    if hasattr(element, 'show'):
        print element.show()


# Now defines Elements: Str, Int, Bit 
class Element(object):
    '''
    encapsulating class for:
    Str, Bit, Int
    '''
    safe = True
    #safe = False
    # Element debugging threshold:
    dbg = 1
    
    # value assignment facilities
    def __lt__(self, Val):
        self.Val = Val
    
    def __gt__(self, Pt):
        self.Pt = Pt
    

class Str(Element):
    '''
    class defining a standard Element, 
    managed like a stream of byte(s) or string.
    
    attributes:
    Pt: to point to another stream object (can simply be a string);
    PtFunc: when defined, PtFunc(Pt) is used 
        to generate the string() / len() representation;
    Val: when defined, overwrites the Pt (and PtFunc) string value, 
        used when mapping string to the element;
    Len: can be set to a fixed int value or point to something;
    LenFunc: to be used when mapping string with variable length, 
        LenFunc(Len) is used;
    Repr: representation style, binary, hexa, human or ipv4;
    Trans: to define Transparent element, 
        which has empty string() and length() to 0 representation, 
        or point to something;
    TransFunc: when defined, TransFunc(Trans) is used 
        to automate the transparent aspect: 
        used e.g. for conditional element;
    '''
    
    # this is used when printing the object representation
    _repr_limit = 1024
    _reprs = ["hex", "bin", "hum", "ipv4"]
    
    # padding is used when .Pt and .Val are None, 
    # but Str instance has still a defined .Len attribute
    _padding_byte = '\0'
    
    def __init__(self, CallName='', ReprName=None, 
                 Pt=None, PtFunc=None, Val=None, 
                 Len=None, LenFunc=None,
                 Repr="hum",
                 Trans=False, TransFunc=None):
        
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
            if attr == "CallName" :
                if type(val) is not str or len(val) == 0 :
                    raise AttributeError("CallName must be a non-null string")
            elif attr == "ReprName" :
                if type(val) is not str:
                    raise AttributeError("ReprName must be a string")
            elif attr == "PtFunc" :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("PtFunc must be a function")
            elif attr == "Val" :
                if val is not None and not isinstance(val, str) :
                    raise AttributeError("Val must be a string")
            elif attr == "Len" :
                if val is not None and not isinstance(val, (int, tuple, Element)) :
                    raise AttributeError("Len must be an int or element")
            elif attr == "LenFunc" :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("LenFunc must be a function")
            elif attr == "Repr" :
                if val not in self._reprs :
                    raise AttributeError("Repr %s does not exist, only: %s" \
                          % (val, self._reprs))
            elif attr == "TransFunc" :
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("TransFunc must be a function")
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
    
    # building basic methods for manipulating easily the Element 
    # from its attributes
    def __call__(self):
        # when Len has fixed value:
        if type(self.Len) is int: 
            l = self.Len
        else: 
            l = None
        # when no values are defined at all:
        if self.Val is None and self.Pt is None: 
            if l: return l * self._padding_byte
            else: return ''
        # returning the right string:
        # if defined, self.Val overrides self.Pt capabilities
        elif self.Val is not None: 
            return str(self.Val)[:l]
        # else: use self.Pt capabilities to get the string
        elif self.PtFunc is not None: 
            if self.safe: 
                assert(hasattr(self.PtFunc(self.Pt), '__str__'))
            return str(self.PtFunc(self.Pt))[:l]
        else:
            if self.safe: 
                assert(hasattr(self.Pt, '__str__'))
            return str(self.Pt)[:l]
    
    def __str__(self):
        # when Element is Transparent:
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): 
                return ''
        elif self.Trans: 
            if self.safe: 
                assert( type(self.Trans) is bool )
            return ''
        #else: 
        return self()
    
    def __len__(self):
        # does not take the LenFunc(Len) into account
        # When a Str is defined, the length is considered dependent of the Str
        # the Str is dependent of the LenFunc(Len) only 
        # when mapping data into the Element
        return len( str(self) )
    
    def bit_len(self):
        return len(self)*8
    
    def map_len(self):
        # need special length definition 
        # when mapping a string to the "Str" element 
        # that has no fixed length
        #
        # uses LenFunc, applied to Len, when length is variable:
        # and TransFunc, applied to Trans, to managed potential transparency
        # (e.g. for optional element triggered by other element)
        #
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): 
                return 0
        elif self.Trans:
            if self.safe:
                assert( type(self.Trans) is bool )
            return 0
        if self.Len is None:
            #return None
            return 0
        if self.LenFunc is None: 
            return self.Len
        else:
            if self.safe:
                assert( type(self.LenFunc(self.Len)) in (int, long) )
            return self.LenFunc(self.Len)
    
    def __int__(self):
        # for convinience...
        return len(self)
    
    def __bin__(self):
        # does not use the standard python "bin" function to keep 
        # the right number of prefixed 0 bits
        h = hex(self)
        binary = ''
        for i in range(0, len(h), 2):
            b = format( int(h[i:i+2], 16), 'b' )
            binary += ( 8-len(b) ) * '0' + b
        return binary
    
    def __hex__(self):
        return self().encode("hex")
    
    def __repr__(self):
        if self.Pt is None and self.Val is None: 
            return repr(None)
        if self.Repr == "ipv4":
            if self.safe: assert( len(self) == 4 )
            return inet_ntoa( str(self) )
        elif self.Repr == "hex": 
            ret = "0x%s" % hex(self)
        elif self.Repr == "bin": 
            ret = "0b%s" % self.__bin__()
        elif self.Repr == "hum":
            # standard return
            ret = repr( self() )
            # complex return, allows to assign a full Block or Layer to a Str...
            # can be useful
            if isinstance( self.Pt, (Element, Layer, Block) ):
                ret = repr(self.Pt)
            if isinstance( self.Val, (Element, Layer, Block) ):
                ret = repr(self.Val)
        # truncate representation if string too long:
        # avoid terminal panic...
        if len(ret) <= self._repr_limit:
            return ret
        else:
            return ret[:self._repr_limit-3]+'...'
    
    # some more methods for checking Element's attributes:
    def getattr(self):
        return ["CallName", "ReprName", "Pt", "PtFunc", "Val", "Len", \
                "LenFunc", "Type", "Repr", "Trans", "TransFunc"]
    
    def showattr(self):
        for a in self.getattr():
            print "%s : %s" % ( a, repr(self.__getattribute__(a)) )
    
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
    
    # standard method show() to print in a beautiful format
    def show(self):
        tr, re = '', ''
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): tr = ' - transparent'
            else: tr = ''
        elif self.Trans is True: tr = ' - transparent'
        if self.ReprName != '':
            re = ''.join((self.ReprName, ' '))
        return '<%s[%s%s] : %s>' % ( re, self.CallName, tr, repr(self) )
        
    # standard method map() to map a string to the Element
    def map(self, string=''):
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if not self.TransFunc(self.Trans):
                self.Val = string[:self.map_len()]
        elif not self.Trans:
            self.Val = string[:self.map_len()]
            debug(self.dbg, 3, '(Element) %s, %s, %s' \
                  % (repr(string), self.CallName, repr(self)))
    

class Int(Element):
    '''
    class defining a standard element, managed like an integer.
    
    attributes:
    Pt: to point to another object or direct integer value;
    PtFunc: when defined, PtFunc(Pt) is used to generate the integer value;
    Val: when defined, overwrites the Pt (and PtFunc) integer value, 
         used when mapping string to the element;
    Type: type of integer for encoding, signed / unsigned 
          and 8/16/32/64 bits length;
    Dict: dictionnary to use when representing the integer value into python;
    Repr: representation style, binary, hexa or human: human uses Dict;
    Trans: to define Transparent element, which has empty string value 
           and length to 0.
    TransFunc: when defined, TransFunc(Trans) is used to command 
               the transparent aspect: used e.g. for conditional element;
    '''
    _endian = "big"
    _types = { "int8":"b", "int16":"h", "int32":"i", "int64":"q",
               "uint8":"B", "uint16":"H", "uint32":"I", "uint64":"Q",
               "uint24":None }
    _reprs = ["hex", "bin", "hum"]
    
    def __init__(self, CallName="", ReprName=None, 
                 Pt=None, PtFunc=None, Val=None, 
                 Type="int32", Dict=None, DictFunc=None,
                 Repr="hum", 
                 Trans=False, TransFunc=None):
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
        self.Len = int(self.Type.lstrip("uint"))//8
    
    def __setattr__(self, attr, val):
        # ensures no bullshit is provided into element's attributes 
        # (however, it is not a complete test...)
        if self.safe:
            if attr == "CallName":
                if type(val) is not str or len(val) == 0:
                    raise AttributeError("CallName must be a non-null string")
            elif attr == "ReprName":
                if type(val) is not str:
                    raise AttributeError("ReprName must be a string")
            elif attr == "PtFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("PtFunc must be a function")
            elif attr == "Val":
                if val is not None and not isinstance(val, (int, long)):
                    raise AttributeError("Val must be an int or long")
            elif attr == "Type":
                if val not in self._types.keys():
                    raise AttributeError("Type must be in: %s" % self._types)
            #elif attr == "Dict":
            #    if val is not None and hasattr(val, '__getitem__') is False:
            #        raise AttributeError('Dict must support the "__getitem__" method')
            elif attr == "DictFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("DictFunc must be a function")
            elif attr == "Repr":
                if val not in self._reprs:
                    raise AttributeError("Repr %s does not exist, use in: %s" \
                          % (val, self._reprs))
            elif attr == "TransFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("TransFunc must be a function")
        if attr == 'Type':
            self.Len = int(val.lstrip("uint"))//8
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
            return max(0, min(pow(2, self.Len*8)-1, value))
        # signed
        else:
            return max(-pow(2, self.Len*8-1), \
                       min(pow(2, self.Len*8-1)-1, value))
    
    def __str__(self):
        # manages Element transparency
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): 
                return ''
        elif self.Trans: 
            return ''
        # otherwise returns standard string values
        return self.__pack()
    
    def __len__(self):
        return len( str(self) )
    
    def bit_len(self):
        return len(self)*8
    
    # map_len() is a-priori not needed in "Int" element, 
    # but still kept for Element uniformity
    def map_len(self):
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): return 0
        elif self.Trans: return 0
        return self.Len
    
    # define integer value
    def __int__(self):
        return self()
    
    def __bin__(self):
        # unsigned or positive signed: 
        if self.Type[0] == 'u' or \
        self.Type[0] == 'i' and self() >= 0 : 
            binstr = format(self(), 'b')
            return (len(self)*8-len(binstr))*'0' + binstr
        # negative signed
        else : 
            #takes 2' complement to the signed val
            binstr = format(self()+pow(2, len(self)*8-1), 'b')
            return '1' + (len(self)*8-len(binstr)-1)*'0' + binstr
    
    def __hex__(self):
        return hexlify(self.__pack())
    
    def __repr__(self):
        if self.Pt is None and self.Val is None: return repr(None)
        if self.Repr == "hex": return "0x%s" % hex(self)
        elif self.Repr == "bin": return "0b%s" % self.__bin__()
        elif self.Repr == "hum":
            if self.DictFunc:
                if self.safe:
                    assert(hasattr(self.DictFunc(self.Dict), '__getitem__'))
                try: val = self.DictFunc(self.Dict)[self()]
                except KeyError: val = self()
            elif self.Dict:
                try: val = self.Dict[self()]
                except KeyError: val = self()
            else:
                val = self()
            return repr(val)
    
    def getattr(self):
        #return self.__dict__.keys()
        return ["CallName", "ReprName", "Pt", "PtFunc", "Val", "Len", \
                "Type", "Dict", "DictFunc", "Repr", "Trans", "TransFunc"]
    
    def showattr(self):
        for a in self.getattr():
            if a == "Dict" and self.Dict is not None: 
                print "%s : %s" % ( a, self.__getattribute__(a).__class__ )
            else: 
                print "%s : %s" % ( a, repr(self.__getattribute__(a)) )
    
    def clone(self):
        clone = self.__class__(
                 self.CallName, self.ReprName,
                 self.Pt, self.PtFunc,
                 self.Val, self.Type,
                 self.Dict, self.DictFunc, self.Repr, 
                 self.Trans, self.TransFunc )
        #clone._endian = self._endian
        return clone
    
    def show(self):
        tr, re = '', ''
        if self.TransFunc is not None:
            if self.safe:
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): tr = ' - transparent'
            else: tr = ''
        elif self.Trans is True: tr = ' - transparent'
        if self.ReprName != '':
            re = ''.join((self.ReprName, ' '))
        return '<%s[%s%s] : %s>' % ( re, self.CallName, tr, repr(self) )
    
    def map(self, string=''):
        if self.TransFunc is not None:
            if self.TransFunc(self.Trans) is False:
                self.Val = self.__unpack(string[:self.Len])
        elif self.Trans is False:
            self.Val = self.__unpack(string[:self.Len])
    
    def __pack(self):
        # manage endianness (just in case...)
        if self._endian == "little": e = "<"
        else: e = ">"
        if self.Type[-2:] != '24':
            return pack(e+self._types[self.Type], self())
        return self.__pack_u24()
    
    def __unpack(self, string=''):
        if self._endian == 'little': e = '<'
        else: e = '>'
        if self.Type[-2:] != '24':
            return unpack(e+self._types[self.Type], string[:self.Len])[0]
        return self.__unpack_u24(string)
    
    def __pack_u24(self):
        # does not support little endian
        # bit dirty ...
        return pack('>BH', self()//65536, self()%65536)
        
    def __unpack_u24(self, string='\0\0\0'):
        # does not support little endian
        msb, lsb = unpack('>BH', string)
        return msb*65536+lsb


class Bit(Element):
    '''
    class defining a standard element, managed like a bit or stream of bit. 
    Values are corresponding to unsigned integer: from 0 to pow(2, bit_len)-1
    
    attributes:
    Pt: to point to another object or direct integer value;
    PtFunc: when defined, function to apply to Pt to generate the integer value,
            PtFunc(Pt) is used;
    Val: when defined, overwrites the Pt (and PtFunc) integer value, 
         used when mapping string to the element;
    BitLen: length in bits of the bit stream;
    BitLenFunc: to be used when mapping string with variable bit-length, 
                BitLenFunc(BitLen) is used 
                (however, hope it's never going to be used anyway...);
    Dict: dictionnary to use when representing the integer value;
    Repr: representation style, binary, hexa or human: human uses Dict;
    Trans: to define Transparent element, 
           which has empty string value and length to 0.
    TransFunc: when defined, TransFunc(Trans) is used to command 
               the transparent aspect: used for conditional element;
    '''
    
    _reprs = ["hex", "bin", "hum"]
    
    def __init__(self, CallName="", ReprName=None, 
                 Pt=None, PtFunc=None, Val=None, 
                 BitLen=1, BitLenFunc=None,
                 Dict=None, DictFunc=None, Repr="bin", 
                 Trans=False, TransFunc=None):
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
            if attr == "CallName":
                if type(val) is not str or len(val) == 0:
                    raise AttributeError("CallName must be a non-null string")
            elif attr == "ReprName":
                if type(val) is not str:
                    raise AttributeError("ReprName must be a string")
            elif attr == "PtFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("PtFunc must be a function")
            elif attr == "Val":
                if val is not None and not isinstance(val, int):
                    raise AttributeError("Val must be an int")
            elif attr == "BitLenFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("BitLenFunc must be a function")
            #elif attr == "Dict":
            #    if val is not None and hasattr(val, '__getitem__') is False:
            #        raise AttributeError('Dict must support the "__getitem__" method')
            elif attr == "DictFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("DictFunc must be a function")
            elif attr == "Repr":
                if val not in self._reprs:
                    raise AttributeError("Repr %s does not exist, use in: %s" \
                          % (val, self._reprs))
            elif attr == "TransFunc":
                if val is not None and not isinstance(val, type_funcs) :
                    raise AttributeError("TransFunc must be a function")
        object.__setattr__(self, attr, val)
    
    def __call__(self):
        if self.Val is None and self.Pt is None: return 0
        if self.Val is not None: return self.__confine(self.Val) 
        elif self.PtFunc is not None:
            if self.safe: assert( type(self.PtFunc(self.Pt)) is int )
            return self.__confine(self.PtFunc(self.Pt))
        else: return self.__confine(self.Pt)
    
    def __confine(self, value):
        # makes sure value provided does not overflow bit length
        return max( 0, min( pow(2, self.bit_len())-1, value ))
    
    def __str__(self):
        # have a str existence only when used inside a "Layer" 
        # and correctly stacked with other "Bit" object 
        # to get a byte-aligned content... 
        # (do not think about 114 bit length of GSM burst... yet)
        return ''
    
    def __len__(self):
        # just for fun here, 
        # but do not use this in program...
        return self.bit_len()//8
    
    def bit_len(self):
        if self.BitLenFunc is not None:
            if self.safe: 
                assert( type(self.BitLenFunc(self.BitLen)) is int )
            return self.BitLenFunc(self.BitLen)
        else:
            if self.safe: 
                assert( type(self.BitLen) is int )
            return self.BitLen
    
    def map_len(self):
        # need special length definition when mapping a string to the Bit element 
        # that has no fixed length
        # uses BitLenFunc(BitLen), when length is variable:
        return self.bit_len()//8
    
    def __hex__(self):
        hexa = hex(self())[2:]
        if self.bit_len()%4: 
            return '0'*(self.bit_len()//4 + 1 - len(hexa)) + hexa
        else: 
            return '0'*(self.bit_len()//4 - len(hexa)) + hexa
    
    def __int__(self):
        return self()
        
    def __bin__(self):
        binary = format(self(), 'b')
        return (self.bit_len() - len(binary))*'0' + binary
        
    def __repr__(self):
        if self.Repr == "hex": return "0x%s" % self.__hex__()
        elif self.Repr == "bin": return "0b%s" % self.__bin__()
        elif self.Repr == "hum":
            if self.DictFunc:
                if self.safe:
                    assert(hasattr(self.DictFunc(self.Dict), '__getitem__'))
                try: val = self.DictFunc(self.Dict)[self()]
                except KeyError: val = self()
            elif self.Dict:
                try: val = self.Dict[self()]
                except KeyError: val = self()
            else: 
                val = self()
            return repr(val)
    
    def getattr(self):
        return ["CallName", "ReprName", "Pt", "PtFunc", "Val", "BitLen", \
                "BitLenFunc", "Dict", "DictFunc", "Repr", "Trans", "TransFunc"]
    
    def showattr(self):
        for a in self.getattr():
            if a == "Dict" and self.Dict is not None: 
                print "%s : %s" % ( a, self.__getattribute__(a).__class__ )
            else: 
                print "%s : %s" % ( a, repr(self.__getattribute__(a)) )
    
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
    
    def show(self):
        tr, re = '', ''
        if self.TransFunc is not None:
            if self.safe: 
                assert( type(self.TransFunc(self.Trans)) is bool )
            if self.TransFunc(self.Trans): tr = ' - transparent'
            else: tr = ''
        elif self.Trans is True: tr = ' - transparent'
        if self.ReprName != '':
            re = ''.join((self.ReprName, ' '))
        return '<%s[%s%s] : %s>' % ( re, self.CallName, tr, repr(self) )
    
    def map(self, string=''):
        # string mapping only works when Bit element is in a Layer
        pass
        # or self.map_bit( int(string) ) ???
    
    def map_bit(self, value=0):
        # this looks a bit like useless...
        # nevermind
        if self.safe: 
            assert( 0 <= value <= pow(2, self.bit_len()) )
        self.Val = value
    

class Layer(object):
    '''
    class to construct stack of "Str", "Int" and "Bit" objects
    got from the initial constructorList.
    
    when instantiated:
    clones the list of "Str", "Int", "Bit" elements in the constructorList: self.elementList;
    manages a common hierarchy level for the whole layer (for use into "Block"): 
        self.hierarchy (int), self.inBlock (bool)
        when .inBlock is True, provides: .get_payload(), .get_header(), 
             .has_next(), .get_next(), .get_previous(), and .Block
    provides several methods for calling elements in the layer:
        by CallName / ReprName passed in attribute
        by index in the elementList
        can be iterated
    also some common methods as "Str", "Int" and "Bit" to emulate a common handling:
        __str__, __len__, __int__, getattr, showattr, clone, show, map
    and last but not least: Layer itself can be stacked into Layer...
    '''
    # debugging threshold for Layer:
    dbg = 1
    # add some sanity checks
    safe = True
    # reserved attributes:
    Reserved = ['CallName', 'ReprName', 'elementList', \
                'hierarchy', 'inBlock', 'Trans', 'ConstructorList', \
                'dbg', 'Reserved']
    
    # structure description:
    constructorList = []
    
    def __init__(self, CallName='', ReprName='', Trans=False):
        if type(CallName) is not str:
            raise AttributeError('CallName must be a string')
        elif len(CallName) == 0:
            self.CallName = split('\.', str(self.__class__))[-1][:-2]
        else:
            self.CallName = CallName
        if type(ReprName) is str and len(ReprName) > 0: 
            self.ReprName = ReprName
        else: 
            self.ReprName = ''
        self.elementList = []
        self.hierarchy = 0
        self.inBlock = False
        self.Trans = Trans
        
        CallNames = []
        for e in self.constructorList:
            # This is for little players
            #if isinstance(e, Element):
            # OK, now let's put the balls on the table and
            # make Layer recursive (so will have Layer() into Layer())
            if isinstance(e, (Element, Layer)):
                if e.CallName in self.Reserved:
                    debug(self.dbg, 1,'(Layer) using a reserved attribute' \
                          'as CallName %s' % e.CallName)
                    return
                if e.CallName in CallNames:
                    debug(self.dbg, 2, '(Layer) different elements ' \
                          'have the same CallName %s' % e.CallName)
                if isinstance(e, Element):
                    self.append(e.clone())
                # do not clone Layer() as it breaks dynamic element inside
                # i.e. element with PtFunc, LenFunc, DictFunc, TransFunc defined
                # TODO: patch Layer().clone() method to solve this...
                # maybe some day
                elif isinstance(e, Layer):
                    self.append(e)
            CallNames.append(e.CallName)
        
        # check for bit alignment until we lost information on the Layer length
        # also check if fixed length can be deduced
        BitLen, Len = 0, 0
        for e in self.elementList:
            debug(self.dbg, 3, '(Layer) length verification for %s' \
                  % e.CallName)
            if isinstance(e, Bit):
                BitLen += e.bit_len()
            elif hasattr(e, 'Len') and type(e.Len) is int:
                Len += e.Len
            else:
                Len = "var"
                break
        if Len == "var": 
            self.Len = Len
        else:
            if self.safe:
                assert(BitLen % 8 == 0)
            self.Len = Len + BitLen//8
    
    # define some basic list facilities for managing elements into the Layer, 
    # through the "elementList" attribute:
    def __iter__(self):
        if self.__dict__.has_key('elementList'):
            return self.__dict__['elementList'].__iter__()
        else: return [].__iter__()
    
    def __getitem__(self, num):
        return self.elementList[num]
    
    def __setitem__(self, num, value):
        # special handling here: 
        # use to override the element value 
        # with its "Val" attribute (like when mapping a string)
        self.elementList[num].Val = value
    
    def append(self, element):
        CallNames = self.getattr()
        #if isinstance(element, Element):
        # make Layer recursive:
        if isinstance(element, (Element, Layer)):
            if element.CallName in CallNames:
                debug(self.dbg, 2, '(Element) different elements ' \
                      'have same CallName %s' \
                      % element.CallName)
            self.elementList.append(element)
    
    def insert(self, index, element):
        CallNames = self.getattr()
        #if isinstance(element, Element):
        # make Layer recursive:
        if isinstance(element, (Element, Layer)):
            if element.CallName in CallNames:
                debug(self.dbg, 2, '(Element) different elements ' \
                      'have same CallName %s' \
                      % element.CallName)
            self.elementList.insert(index, element)
    
    def extend(self, newElementList):
        for e in newElementList:
            self.append(e)
    
    def remove(self, element):
        for e in self:
            if e == element:
                self.elementList.remove(element)
    
    #def replace(self, current_element, new_element):    
    #    self.remove(current_element)
    #    self.letitforfutureimplementation()
    
    # define some attribute facilities for managing elements 
    # by their CallName into the Layer
    # warning: dangerous when parsing data into Layer, 
    # with elements which could have same CallName
    # 
    # list facilities can be preferred in this case
    def __getattr__(self, name):
        for e in self:
            if name == e.CallName or name == e.ReprName: 
                return e
        return object.__getattribute__(self, name)
        raise AttributeError( '"Layer" has no "%s" attribute: %s' \
              % (name, self.getattr()) )
    
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
    def inc_hierarchy(self, ref=None):
        if ref is None: 
            self.hierarchy += 1
        else: 
            self.hierarchy = ref + 1
    
    def dec_hierarchy(self, ref=None):
        if ref is None: 
            self.hierarchy -= 1
        else: 
            self.hierarchy = ref - 1
    
    # define same methods as "Element" type for being use the same way
    def __str__(self):
        s = ''
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
                if e.TransFunc is not None:
                    if self.safe:
                        assert(type(e.TransFunc(e.Trans)) is bool)
                    if not e.TransFunc(e.Trans):
                        BitStream += str(e.__bin__())
                elif not e.Trans:
                    if self.safe:
                        assert(type(e.Trans) is bool)
                    BitStream += str(e.__bin__())
                # when arriving on a byte boundary from bitstream, 
                # create bytes and put it into the s variable
                if len(BitStream) >= 8:
                    while True:
                        s += pack('!B', int(BitStream[:8], 2))
                        BitStream = BitStream[8:]
                        if len(BitStream) < 8:
                            break
                    #while BitStream:
                    #    s += pack('!B', int(BitStream[:8], 2))
                    #    BitStream = BitStream[8:]
                debug(self.dbg, 3, '(Element) %s: %s, %s\nBitstream: %s' \
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
                    s += str(e)
        self.__is_aligned(BitStream)
        return s
    
    def __is_aligned(self, BitStream):
        if BitStream:
            debug(self.dbg, 2, '(Layer) some of the Bit elements ' \
                  'have not been stacked in the "str(Layer)"\n' \
                  'remaining bitstream: %s' % BitStream)
            if self.safe:
                assert(not BitStream)
    
    def __call__(self):
        return str(self)
    
    def __len__(self):
        return len( str(self) )
    
    def __int__(self):
        # really silly... still can be convinient: how knows?
        return len( str(self) )
    
    def __repr__(self):
        t = ''
        if self.Trans:
            t = ' - transparent '
        s = '<%s[%s]%s: ' % ( self.ReprName, self.CallName, t )
        for e in self:
            s += '%s(%s):%s, ' % ( e.CallName, e.ReprName, repr(e) )
        s = s[:-2] + '>'
        return s
    
    def map_len(self):
        return len(self)
    
    def getattr(self):
        CallNames = []
        for e in self:
            CallNames.append(e.CallName)
        return CallNames
    
    def showattr(self):
        for a in self.getattr():
            print "%s : %s" % ( a, repr(self.__getattr__(a)) )
    
    def clone(self):
        clone = self.__class__()
        clone.CallName, clone.ReprName, clone.Len, clone.elementList = \
            self.CallName, self.ReprName, self.Len, []
        for e in self:
            # TODO:
            # when cloning dynamic elements (using PtFunc, LenFunc, 
            # DictFunc, TransFunc), the object pointed
            # is not updated in the clone...
            if isinstance(e, Element):
                debug(self.dbg, 2, '(Layer) cloning element does not ' \
                      'update dynamic elements')
                clone.append(e.clone())
            elif isinstance(e, Layer):
                debug(self.dbg, 2, '(Layer) cloning layer in layer ' \
                      'is actually only done by reference, no copy')
                clone.append(e)
        clone.hierarchy = self.hierarchy
        return clone
    
    def show(self):
        re, tr = '', ''
        if self.ReprName != '':
            re = '%s ' % self.ReprName
        if self.Trans:
            tr = ' - transparent'
        s = ''.join((self.hierarchy * '\t', \
                     '### %s[%s]%s ###\n' % (re, self.CallName, tr)))
        for e in self:
            s += ''.join((e.show(), '\n'))
        s = s[:-1]
        return sub('\n', ''.join(['\n']+self.hierarchy*['\t']), s)
    
    def map(self, string=''):
        BitStack, BitStack_len = [], 0
        for e in self:
            # need special processing for stacking and mapping "Bit" element
            # manage only contiguous Bit elements (for commodity, again)
            # need to take into account (Trans, TransFunc), and bit_len()
            if isinstance(e, Bit):
                if e.TransFunc is not None:
                    if self.safe: 
                        assert(type(e.TransFunc(e.Trans)) is bool)
                    if not e.TransFunc(e.Trans):
                        BitStack += [e]
                        BitStack_len += e.bit_len()
                elif not e.Trans:
                    if self.safe:
                        assert(type(e.Trans) is bool)
                    BitStack += [e]
                    BitStack_len += e.bit_len()
                #
                # TODO: instead of processing with "dummy" string
                # could be better with some integer / shift kung-fu ?
                #
                # This would need to store a shifting value with each Bit
                # element in the BitStack
                #
                # if BitStack is byte aligned, go and map it!
                if not BitStack_len % 8:
                    # create a bit stream "s_bin" for the full BitStack
                    if len(string) < BitStack_len//8:
                        debug(1, self.dbg, 'String buffer not long enough ' \
                              'for %s' % e.CallName)
                        return
                    s_stack = string[:BitStack_len//8]
                    s_bin = ''
                    while s_stack:
                        s_bin_temp = bin( ord(s_stack[0]) )[2:]
                        s_bin += ( 8 - len(s_bin_temp) )*'0' + s_bin_temp
                        s_stack = s_stack[1:]
                    # map the bit stream "s_bin" into each BitStack element
                    for B in BitStack:
                        B.map_bit( int(s_bin[:B.bit_len()], 2) )
                        s_bin = s_bin[B.bit_len():]
                    # consume the buffer to map and reinitialize Bit variables
                    string = string[BitStack_len//8:]
                    BitStack, BitStack_len = [], 0
            # for other element, standard processing (easier...)    
            else:
                if BitStack_len > 0:
                    debug(self.dbg, 2, '(Layer) some of the Bit elements ' \
                          'have not been mapped in the "Layer"')
                if isinstance(e, Layer) and not e.Trans \
                or isinstance(e, Element):
                    if len(string) < e.map_len():
                        debug(1, self.dbg, 'String buffer not long enough ' \
                              'for %s' % e.CallName)
                        return
                    e.map(string)
                    string = string[e.map_len():]
    
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
        #returns a Block, not a Layer like other methods for management into a Block
        pay = Block('pay')
        if self.has_next():
            index = self.get_index()
            for l in self.Block[ index+1 : ]:
                if l.hierarchy > self.hierarchy:
                    pay.append( l.clone() )
                else:
                    break
            if pay.num() == 0:
                pay.append( RawLayer() )
            return pay
        pay.append( RawLayer() )
        return pay
    
    def num(self):
        return 1

class RawLayer(Layer):
    constructorList = [
        Str(CallName="s", Pt=""),
        ]
    
    def __init__(self, s=""):
        Layer.__init__(self, CallName="raw")
        self.s.Pt = s


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
            raise AttributeError("CallName must be a string")
        self.CallName = Name
        self.layerList = []
        self.hierarchy = 0
        self.inBlock = False

    # define some basic list facilities for managing layers into the Block:
    def __iter__(self):
        if self.__dict__.has_key('layerList'):
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
            obj.Block = self
            obj.hierarchy = self.hierarchy
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
            for i in range(start, stop):
                self.layerList.remove( self.layerList[start] )
    
    # method for Block hierarchy setting
    def set_hierarchy(self, hier):
        self.hierarchy = hier
        for l in self:
            l.hierarchy += hier
    
    # method for managing all the Layers hierarchy in the Block (easy):
    def inc_hierarchy(self, ref=0):
        self.hierarchy += 1+ref
        for l in self: l.hierarchy += 1+ref
    
    def dec_hierarchy(self, ref=0):
        self.hierarchy -= 1-ref
        for l in self: l.hierarchy -= 1-ref
    
    # define operations to insert layers into a block:
    # OR: block | new_layer, append the new_layer with the same hierarchy as last layer in the block
    def __or__(self, newLayer):
        self.append(newLayer)
        self[-1].hierarchy = self[-2].hierarchy
    
    # LSHIFT: block << new_layer, append the new_layer with a higher hierarchy than last layer in the block
    def __lshift__(self, newLayer):
        self.append(newLayer)
        if self.num() > 1:
            self[-1].inc_hierarchy( self[-2].hierarchy )
        else:
            self[-1].hierarchy = self.hierarchy
    
    # RSHIFT: block >> new_layer, append the new_layer with a lower hierarchy than last layer in the block
    def __rshift__(self, newLayer):
        self.append(newLayer)
        self[-1].dec_hierarchy( self[-2].hierarchy )
    
    # standard methods for common management with Layers
    def __str__(self):
        s = ''
        for l in self:
            if not hasattr(self, 'Trans') or not l.Trans:
                s += str(l)
        return s
    
    def __len__(self):
        return len( str(self) )
    
    def __int__(self):
        return len( str(self) )
    
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
            else: 
                debug(self.dbg, 2, '(Block) cloning not implemented for: ' \
                      '%s' % l)
        return clone
    
    def show(self):
        s = '%s[[[ %s ]]]\n' % (self.hierarchy*'\t', self.CallName)
        for e in self: 
            s += e.show() + '\n'
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


##################
# test functions #
##################

class testTLV(Layer):
    constructorList = [
        Int(CallName="T", ReprName="Tag", Type="uint8", \
            Dict={0:"Reserved", 1:"Tag1", 2:"Tag2", 5:"Tag5"}),
        Bit(CallName='F1', ReprName="Flag1", Pt=0, BitLen=1),
        Bit(CallName='F2', ReprName="Flag2", Pt=1, BitLen=1),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=14),
        Int(CallName="L", ReprName="Length", Type="uint8" ),
        Str(CallName="V", ReprName="Value", Pt='default value'),
        ]

    def __init__(self, name='test', T=5, V='blablabla'):
        Layer.__init__(self, CallName=name)
        self.T.Pt = T
        self.L.Pt = self.V
        self.L.PtFunc = lambda X: len(X)+3
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda X: int(X)-3


