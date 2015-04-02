# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.3
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
# * File Name : utils/IntEncoder.py
# * Created : 2014-06-17
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

###
# provides minimum encoding for signed integer
###
def minenc_int(val=0):
    '''
    for a given signed integer value, returns the minimum octet encoding.
    
    minenc_int(X) -> (Y, 'intZ')
        -2**(Y*8-1) <= Y < 2**(Y*8-1)
        'int8' -> 'intZ'
    '''
    if -128 <= val < 128:
        return (1, 'int8')
    elif -32768 <= val < 32768:
        return (2, 'int16')
    elif -8388608 <= val < 8388608:
        return (3, 'int24')
    elif -2147483648 <= val < 2147483648:
        return (4, 'int32')
    elif -549755813888 <= val < 549755813888:
        return (5, 'int40')
    elif -140737488355328 <= val < 140737488355328:
        return (6, 'int48')
    elif -36028797018963968 <= val < 36028797018963968:
        return (7, 'int56')
    elif -9223372036854775808 <= val < 9223372036854775808:
        return (8, 'int64')
    else:
        if val < 0:
            n = 9
            lim = -2**71
            while val < lim:
                n += 1
                lim <<= 8
            return (n, 'int{0}'.format(n*8))
        else:
            n = 9
            lim = 2**71
            while val >= lim:
                n += 1
                lim <<= 8
            return (n, 'int{0}'.format(n*8))

###
# provides minimum encoding for unsigned integer
###
def minenc_uint(val=0):
    '''
    for a given unsigned integer value, returns the minimum octet encoding.
    
    minenc_uint(X) -> (Y, 'uintZ')
        0 <= X < 2**(8*Y)
        'uint8' -> 'uintZ'
    '''
    if val < 0:
        return (0, 'uint0')
    elif val < 256:
        return (1, 'uint8')
    elif val < 65536:
        return (2, 'uint16')
    elif val < 16777216:
        return (3, 'uint24')
    elif val < 4294967296:
        return (4, 'uint32')
    elif val < 1099511627776:
        return (5, 'uint40')
    elif val < 281474976710656:
        return (6, 'uint48')
    elif val < 72057594037927936:
        return (7, 'uint56')
    elif val < 18446744073709551616:
        return (8, 'uint64')
    else:
        n = 9
        lim = 2**72
        while val >= lim:
            n += 1
            lim <<= 8
        return (n, 'uint{0}'.format(n*8))
