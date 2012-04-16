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

# Utility class to decompose / recompose integer
# and manipulate str like integers (shifting them)

class decomposer(object):
    '''
    little utility to decompose an integer into factors from an 
    exponential (self.MUL), and returns the list or remainder:
    
    example:
    decomposer(0x100).decompose(53) -> [5, 6]
    this means:
    53 = 5 + (6 << 8)
    
    more generally:
    decomposer(1<<X).decompose(Y) -> [a, b, c, d ...]
    means:
    Y = a + (b << (1<<X)) + (c << (2<<X)) + (d << (3<<X)) ...
    '''
    def __init__(self, MUL=0x100):
        self.MUL = MUL
        self._val_deced = []
    
    def decompose(self, val):
        self._val_to_dec = val
        self._val_deced.append( self._val_to_dec % self.MUL )
        if self._val_to_dec > self.MUL: 
            self._val_to_dec = self._val_to_dec / self.MUL
            self.decompose( self._val_to_dec )
        return self._val_deced


class shtr(str):
    '''
    shtr are strings that can be shifted
    
    when a shtr is shifted, it returns:
    1) the resulting string
    2) the integer value corresponding to the bits that have been removed 
       from the string
    Integer value is computed given the following:
    the shtr is ascii encoded, each byte is taken as unsigned char
    MSB is left-side, LSB is right-side, in each byte
    '''
    
    def left_val(self, val):
        '''
        return big endian integer value from the `val' left bits of the shtr
        '''
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
        #
        #                LSB of byte i       plus    MSB of byte i+1
        strlist = [ ((ord(buf[i])<<bsh)%0x100) + (ord(buf[i+1])>>invbsh) \
                    for i in xrange(len(buf)-1) ]
        # and add last bits of the string
        strlist.append( (ord(buf[-1])<<bsh)%0x100 )
        #
        return shtr(''.join(map(chr, strlist)))
    
    def __rshift__(self, val):
        '''
        return resulting shtr after shifting right of `val' bits
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
        return shtr(''.join(map(chr, strlist)))


