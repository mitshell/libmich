# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau.
# * Made in TGV Paris Grenoble
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
# * File Name : core/shtr.py
# * Created : 2012-04-09
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# export filter
__all__ = ['decomposer', 'shtr']

# Utility classes to :
# decompose and recompose integers
# and manipulate str like integers (shifting them)

class decomposer(object):
    '''
    little utility to decompose an integer into factors from an 
    exponential (self.MUL), and returns the list of remainders:
    
    example:
    decomposer(0x10).decompose(53) -> [5, 3]
    this means:
    53 = 5 + (3 << 4), with 0x10 = 1 << 4
    
    more generally:
    decomposer(1<<X).decompose(Y) -> [a, b, c, d ...]
    means:
    Y = a + (b << (1<<X)) + (c << (2<<X)) + (d << (3<<X)) ...
    '''
    def __init__(self, MUL=0x100):
        self.MUL = MUL
        self._val_dec = []
    
    def decompose(self, val):
        if val == self.MUL:
            self._val_dec.extend([0, 1])
        else:
            self._val_dec.append( val % self.MUL )
        if val > self.MUL:
            val = val / self.MUL
            self.decompose( val )
        return self._val_dec

class shtr(str):
    '''
    shtr are strings that can be shifted !
    
    When a shtr is shifted (<< X or >> X), it returns the resulting string.
    When right shifted (>> X), null bytes are appended left-side. 
    Methods .left_val(X) and .right_val(X) returns the integer value corresponding to 
    the X bits left or right side of the shtr.
    '''
    def __init__(self, s):
        #str.__init__(self, s)
        self._bitlen = len(s)*8
    
    def left_val(self, val):
        '''
        returns big endian integer value from the `val' left bits of the shtr
        '''
        if val > self._bitlen: val = self._bitlen
        acc = 0
        # 1) get value of full bytes
        for i in xrange(val/8):
            acc += ord(self[i]) << (val - ((i+1)*8))
        # 2) get value of last bits
        if val%8 and val/8 < len(self):
            acc += ord(self[val/8]) >> (8 - (val%8))
        return acc
    
    def right_val(self, val):
        '''
        return big endian integer value from the `val' right bits of the shtr
        '''
        if val > self._bitlen: val = self._bitlen
        acc = 0
        # 1) get value of full bytes
        for i in range(val/8):
            acc += ord(self[-1-i]) << (i*8)
        # 2) get value of last bits
        if val%8 and val/8 < len(self):
            acc += (ord(self[-1-(val/8)]) & ((1<<(val%8))-1)) << (8*(val/8))
        return acc
    
    # making an intermediate list of char that will be ''.join(map(chr, )) 
    # looks much faster in python
    # So I do so
    
    def __lshift__(self, val):
        '''
        return resulting shtr after shifting left of `val' bits
        '''
        # 1) handle full byte shifting
        Bsh = val/8
        buf = ''.join((self[Bsh:], Bsh*'\0'))
        # 2) then bit shifting
        bsh = val%8
        invbsh = 8-bsh
        #                LSB of byte i       plus    MSB of byte i+1
        strlist = [ ((ord(buf[i])<<bsh)%0x100) + (ord(buf[i+1])>>invbsh) \
                    for i in xrange(len(buf)-1) ]
        # and add last bits of the string
        strlist.append( (ord(buf[-1])<<bsh)%0x100 )
        #
        #return shtr(''.join(map(chr, strlist)))
        #
        ret = shtr(''.join(map(chr, strlist)))
        ret._bitlen = max(0, self._bitlen - val)
        return ret
    
    def __rshift__(self, val):
        '''
        returns resulting shtr after shifting right of `val' bits
        '''
        # 1) handle full byte shifting
        Bsh = val / 8
        buf = ''.join((Bsh*'\0', self[:len(self)-Bsh]))
        # 2) then bit shifting
        bsh = val % 8
        pbsh, invbsh = pow(2,bsh)-1, 8-bsh
        # go over the string, from last byte to the 1st one
        strlist = [ (ord(buf[i])>>bsh) + ((ord(buf[i-1])&pbsh)<<invbsh) \
                    for i in reversed(xrange(1, len(buf))) ]
        # add 1st bits of the string and reverse the list
        strlist.append( ord(buf[0])>>bsh )
        strlist.reverse()
        #
        #return shtr(''.join(map(chr, strlist)))
        ret = shtr(''.join(map(chr, strlist)))
        ret._bitlen = self._bitlen + val
        return ret
#
