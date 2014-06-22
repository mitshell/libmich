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
# * File Name : asn1/ASN1_BER.py
# * Created : 2014-05-06
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python
from libmich.core.element import Bit, Int, Str, Layer, show, showattr, \
    log, DBG, WNG, ERR
from libmich.core.shtr import decomposer

###
# ASN.1 Basic Encoding Rules
###

TagClass_dict = {
    0 : 'Universal',
    1 : 'Application',
    2 : 'Context-specific',
    3 : 'Private'
    }
TagNumber_dict = {
    1 : 'BOOLEAN',
    2 : 'INTEGER',
    3 : 'BIT STRING',
    4 : 'OCTET STRING',
    5 : 'NULL',
    6 : 'OID'
    }

class ASN1_BER_T(Layer):
    _byte_aligned = True
    constructorList = [
        Bit('Class', Pt=0, BitLen=2, Repr='hum', Dict=TagClass_dict),
        Bit('PC', Pt=0, BitLen=1, Repr='hum', Dict={0:'Primitive', 1:'Constructed'}),
        Bit('Number', Pt=0, BitLen=5, Repr='hum')
        ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, **kwargs)
        if 'Number' in kwargs:
            self.encode(kwargs['Number'])
        elif args and isinstance(args[0], int):
            self.encode(args[0])
    
    def encode(self, number=0):
        # truncate to the basic representation 
        self.elementList = self.elementList[:3]
        if number < 31:
            self.Number > number
        else:
            # add as much as More 1-bit and Number 7-bit elements as required
            # to encode $number
            self.Number > 31
            self.Number.Repr = 'bin'
            # decompose it in 1<<7 factors
            facts = decomposer(128).decompose(number)
            facts.reverse()
            for f in facts:
                self.append( Bit('More', Pt=1, BitLen=1) )
                self.append( Bit('Number', Pt=f, BitLen=7) )
            # set last More bits to 0
            self[-2] > 0
    
    def __call__(self):
        # return the encoded Number value
        if self[2]() < 31:
            # if $Number < 31
            return self[2]()
        else:
            # otherwise, iterate...
            len_elist = len(self.elementList)
            index = 3
            number = 0
            # ... over each More / Number bits couple
            while index+2 <= len_elist:
                # and accumulate Number value
                number <<= 7
                number += self[index+1]()
                if not self[index]():
                    # if More bits not set
                    break
                else:
                    index += 2
            return number
    
    def map(self, s=''):
        # truncate to the basic representation 
        self.elementList = self.elementList[:3]
        # map initial octet
        Layer.map(self, s[:1])
        s = s[1:]
        if self.Number() == 31:
            # iterate over the string buffer if needed
            while s:
                val = ord(s[0])
                self.append( Bit('More', Pt=0, BitLen=1) )
                self[-1] < val>>7 
                self.append( Bit('Number', Pt=0, BitLen=7) )
                self[-1] < val&127
                s = s[1:]
                # if More bit not set, stop iteration
                if not self[-2]():
                    break

class ASN1_BER_L(Layer):
    # works for short and long form of length encoding
    _byte_aligned = True
    constructorList = [
        Bit('Form', Pt=0, BitLen=1, Repr='hum', Dict={0:'short', 1:'long'}),
        Bit('Length', Pt=0, BitLen=7)
        ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, **kwargs)
        if 'Length' in kwargs:
            self.encode(kwargs['Length'])
        elif args and isinstance(args[0], int):
            self.encode(args[0])
    
    def encode(self, length=0):
        # reinit to the basic representation 
        self.__init__()
        # always choose the most compact form
        if length < 128:
            self.Form > 0
            self.Length > length
        else:
            self.Form > 1
            #
            # decompose length in 1<<8 factors (maybe this is a bit extra work)
            facts = decomposer(256).decompose(length)
            facts.reverse()
            #
            self.remove(self.Length)
            self.append( Bit('N', Pt=0, BitLen=7, Repr='hum') )
            self.append( Bit('Length', Pt=length, BitLen=8*len(facts), Repr='hum') )
            self.N.PtFunc = lambda x: len(self.Length)
    
    def __call__(self):
        # return the encoded Length value
        return self.Length()
    
    def map(self, s=''):
        if not s:
            return
        # reinit to the basic representation 
        self.__init__()
        # get the Form bit
        F = ord(s[0])>>7
        # short form: do not change anything
        # long form (will also works for indefinite form):
        if F:
            self.remove(self.Length)
            self.append( Bit('N', Pt=0, BitLen=7, Repr='hum') )
            self.append( Bit('Length', Pt=0, Repr='hum') )
            #self.N.PtFunc = lambda x: len(self.Length) # infinite loop...
            self.Length.BitLen = self.N
            self.Length.BitLenFunc = lambda n: n()*8
        # map on the structure
        Layer.map(self, s)


class ASN1_BER_TLV(Layer):
    #
    # should have ASN1_BER_TAG, ASN1_BER_LEN, Value
    # Tag, Len and Value encoding will depend of the different ASN.1 types
    #
    _byte_aligned = True
    constructorList = [
        ASN1_BER_T(),
        ASN1_BER_L(),
        Str('V', Pt='')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        if 'T' in kwargs:
            self.ASN1_BER_T.encode(kwargs['T'])
        if 'L' in kwargs:
            self.ASN1_BER_L.encode(kwargs['L'])
        else:
            self.ASN1_BER_L.encode(len(self.V))
    
    def map(self, s=''):
        self.__init__()
        self[0].map(s)
        s = s[len(self[0]):]
        self[1].map(s)
        s = s[len(self[1]):]
        self[2].map(s[:self[1]()])
#