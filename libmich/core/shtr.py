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

from struct import pack, unpack

# export filter
__all__ = ['decomposer', 'decompose', 'shtr']

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
        self._val_dec.append( int(val % self.MUL) )
        if val >= self.MUL:
            val = val // self.MUL
            void = self.decompose( val )
        return self._val_dec

def decompose(MUL=0x100, val=0):
    '''
    little utility to decompose an integer into factors from an 
    exponential (MUL), and returns the list of remainders:
    
    example:
    decompose(0x10, 53) -> [5, 3]
    this means:
    53 = 5 + (3 << 4), with 0x10 = 1 << 4
    
    more generally:
    decomposer(1<<X, Y) -> [a, b, c, d ...]
    means:
    Y = a + (b << (1<<X)) + (c << (2<<X)) + (d << (3<<X)) ...
    
    This is faster than the recursive decomposer().decompose() method
    '''
    if MUL == 2:
        dec = map(int, bin(val)[2:])
        dec.reverse()
        return dec
    elif MUL == 16 and val >= 10000000000:
        h = hex(val)[2:]
        if h[-1] == 'L': h = h[:-1]
        dec = map(int, h, len(h)*[16])
        dec.reverse()
        return dec
    else:
        dec = [ int(val % MUL) ]
        while val >= MUL:
            val //= MUL
            dec.append( int(val % MUL) )
        return dec

class shtr(str):
    '''
    shtr are strings that can be shifted !
    
    When a shtr is shifted (<< X or >> X), it returns the resulting string.
    When right shifted (>> X), null bytes are appended left-side. 
    Methods .left_val(X) and .right_val(X) returns the integer value corresponding to 
    the X bits left or right side of the shtr.
    '''
    
    def __init__(self, s):
        self._bitlen = len(s)*8
    
    def left_val(self, bitlen):
        '''
        returns big endian integer value from the `bitlen' left bits of the shtr
        '''
        if bitlen > self._bitlen:
            bitlen = self._bitlen
        # 0)
        reg64 =  bitlen//64
        reg8  = (bitlen%64)//8
        reg1  =  bitlen%8
        acc, start, stop = 0, 0, 0
        # 1)
        if reg64:
            stop = 8*reg64
            acc += reduce(lambda x,y: (x<<64)+y,
                          unpack('>'+reg64*'Q', self[:stop]))
        # 2)
        if reg8:
            acc <<= 8*reg8
            start = stop
            stop = start + reg8
            acc += reduce(lambda x,y: (x<<8)+y,
                          unpack('>'+reg8*'B', self[start:stop]))
        # 3)
        if reg1:
            acc <<= reg1
            acc += (ord(self[stop:stop+1]) >> (8-reg1))
        #
        return acc
    
    def right_val(self, val):
        '''
        returns big endian integer value from the `val' right bits of the shtr
        '''
        if val > self._bitlen: val = self._bitlen
        acc = 0
        # 1) get value of full bytes
        for i in xrange(val/8):
            acc += ord(self[-1-i]) << (i*8)
        # 2) get value of last bits
        if val%8 and val/8 < len(self):
            acc += (ord(self[-1-(val/8)]) & ((1<<(val%8))-1)) << (8*(val/8))
        return acc
    
    def __lshift__(self, bitlen):
        '''
        returns resulting shtr after shifting left of `bitlen' bits
        '''
        if bitlen > self._bitlen:
            bitlen = self._bitlen
        # 0) full byte shifting
        buf = self[bitlen//8:]
        # 1) bit shifting
        reg1  = bitlen%8
        if reg1:
            buflen = len(buf)
            reg64 = buflen//8
            reg8  = buflen%8
            reg1inv   = 8-reg1
            reg1inv64 = 64-reg1
            fmt = '>'+reg64*'Q'+reg8*'B'
            values = unpack(fmt, buf)
            #print values
            if reg64:
                #print('reg64')
                chars = map(lambda X: ((X[0]<<reg1)%0x10000000000000000)\
                                      +(X[1]>>reg1inv64),
                            zip(values[:reg64], values[1:reg64]))
                if reg8:
                    #print('reg8')
                    chars.append( ((values[reg64-1]<<reg1)%0x10000000000000000)\
                                  +(values[reg64]>>reg1inv) )
                    chars.extend( map(lambda X: ((X[0]<<reg1)%0x100)+(X[1]>>reg1inv),
                                      zip(values[reg64:], values[reg64+1:])) )
                    chars.append( (values[-1]<<reg1)%0x100 )
                else:
                    chars.append( (values[reg64-1]<<reg1)%0x10000000000000000 )
            elif reg8:
                #print('reg8')
                chars = map(lambda X: ((X[0]<<reg1)%0x100)+(X[1]>>reg1inv),
                            zip(values, values[1:]))
                chars.append( (values[-1]<<reg1)%0x100 )
            #
            #print chars
            ret = shtr(pack(fmt, *chars))
        else:
            ret = shtr(buf)
        ret._bitlen = self._bitlen-bitlen
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
#