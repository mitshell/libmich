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
        # get integer value from the `val' left bits of the str
        acc = 0
        for i in range(val/8):
            acc += ord(self[i]) << (val - ((i+1)*8))
        acc += ord(self[val/8]) >> (8 - (val%8))
        return acc
    
    def right_val(self, val):
        # get integer value from the `val' right bits of the str
        acc = 0
        for i in range(val/8):
            acc += ord(self[-1-i]) << (i*8)
        acc += (ord(self[-1-(val/8)]) & ((1<<(val%8))-1)) << (8*(val/8))
        return acc
    
    def __lshift__(self, val):
        # left shift the string from the given `val' bits
        # and return resulting shtring
        # handle full byte shifting
        Bsh = val / 8
        buf = self[Bsh:] + Bsh*'\0'
        # then bit shifting
        bsh = val % 8
        buf2 = ''
        for i in range(len(buf)-1):
            buf2 = ''.join((buf2, chr( ((ord(buf[i])<<bsh)%0x100) \
                                      + (ord(buf[i+1])>>(8-bsh)) )))
        buf2 = ''.join((buf2, chr((ord(buf[-1])<<bsh)%0x100)))
        return shtr(buf2)
    
    def __rshift__(self, val):
        # right shift the string from the given `val' bits
        # and return resulting shtring
        Bsh = val / 8
        buf = Bsh*'\0' + self[:len(self)-Bsh]
        # then bit shifting
        bsh = val % 8
        buf2 = ''
        for i in reversed(range(1, len(buf))):
            buf2 = ''.join((chr((ord(buf[i])>>bsh) + \
                                ((ord(buf[i-1])&(pow(2, bsh)-1))<<(8-bsh))), \
                            buf2))
        buf2 = ''.join(( chr(ord(buf[0])>>bsh), buf2))
        return shtr(buf2)


