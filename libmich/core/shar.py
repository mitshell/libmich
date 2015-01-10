# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.3.0
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
# * File Name : core/shar.py
# * Created : 2014-12-11
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# if you want to make use of numpy (3 to 5 times faster),
# make it True
# test() with numpy: 23ms
# test() with Python stdlib array: 129ms
_WITH_NUMPY = True

from functools import reduce
from math import ceil
#
if _WITH_NUMPY:
    try:
        import numpy as np
        _with_numpy = True
    except ImportError:
        from array import array
        _with_numpy = False
else:
    from array import array
    _with_numpy = False


# numpy version
if _with_numpy:
    
    _BIT_INDEX = np.arange(7, -1, -1)
    _BYTE_TO_BIT = lambda byteval: [byteval >> i & 1 for i in _BIT_INDEX]
    _BIT_TO_BYTE = lambda bitvec: reduce(lambda x,y:(x<<1)+y, bitvec[:8])
    
    def byte_to_bit(ar_byte):
        '''
        convert a byte array (ubyte) to a a bit array (ubyte)
        
        Parameters
        ----------
        ar_byte : 1d-array, ubyte (from 0 to 255)
        
        Returns
        -------
        ar_bit : 1d-array, ubyte (only 0 and 1)
        '''
        return np.ravel( \
            np.fromfunction( \
                lambda i, j: np.ubyte(ar_byte[i] >> _BIT_INDEX[j] & 1), 
                (len(ar_byte), 8),
                dtype=np.int)
            )
    
    def bit_to_byte(ar_bit):
        '''
        convert a bit array (ubyte) to a byte array (ubyte)
        
        Parameters
        ----------
        ar_bit : 1d-array, ubyte (only 0 and 1)
        
        Returns
        -------
        ar_byte : 1d-array, ubyte (from 0 to 255)
            If ar_bit is not an 8-bit multiple, ar_byte is left-aligned
            and LSB of the last byte are zero padded
        '''
        # in case ar_bit is not an 8-bit multiple, take of copy of it
        # with zero-padding left-appended
        # TODO: making a copy of the whole ar_bit is a bit overkill...
        len_extra = len(ar_bit) % 8
        if len_extra:
            b_mat = np.append(ar_bit,
                              np.zeros((8-len_extra, ), np.ubyte))\
                           .reshape((ceil(len(ar_bit)/8.0), 8))
        else:
            b_mat = ar_bit.reshape((len(ar_bit)/8, 8))
        #
        return np.fromfunction( \
            lambda i: (b_mat[i,0]<<7) + (b_mat[i,1]<<6)+\
                      (b_mat[i,2]<<5) + (b_mat[i,3]<<4)+\
                      (b_mat[i,4]<<3) + (b_mat[i,5]<<2)+\
                      (b_mat[i,6]<<1) +  b_mat[i,7],
            (b_mat.shape[0], ),
            dtype=np.int)


# Python stdlib array version
else:
    
    _BIT_INDEX = array('B', [7, 6, 5, 4, 3, 2, 1, 0])
    _BYTE_TO_BIT = lambda byteval, BI=_BIT_INDEX: [byteval >> i & 1 for i in BI]
    _BIT_TO_BYTE = lambda bitvec: reduce(lambda x,y:(x<<1)+y, bitvec[:8])
    
    def byte_to_bit(ar_byte):
        '''
        convert a byte array (uchar) to a a bit array (uchar)
        
        Parameters
        ----------
        ar_byte : 1d-array, uchar (from 0 to 255)
        
        Returns
        -------
        ar_bit : 1d-array, uchar (only 0 and 1)
        '''
        ar_bit = array('B')
        for B in ar_byte:
            ar_bit.extend(_BYTE_TO_BIT(B))
        return ar_bit
    
    def bit_to_byte(ar_bit):
        '''
        convert a bit array (uchar) to a byte array (uchar)
        
        Parameters
        ----------
        ar_bit : 1d-array, uchar (only 0 and 1)
        
        Returns
        -------
        ar_byte : 1d-array, uchar (from 0 to 255)
            If ar_bit is not an 8-bit multiple, ar_byte is left-aligned
            and LSB of the last byte are zero padded
        '''
        # in case ar_bit is not an 8-bit multiple, take of copy of it
        # with zero-padding left-appended
        # TODO: making a copy of the whole ar_bit is a bit overkill...
        len_extra = len(ar_bit) % 8
        if len_extra:
            ar_bit = ar_bit[:]
            ar_bit.extend([0] * (8-len_extra))
        ar_byte = array('B')
        ar_byte.extend( [_BIT_TO_BYTE(ar_bit[i:i+8]) \
                            for i in range(0, len(ar_bit), 8)] )
        return ar_byte


# numpy version
if _with_numpy:
    
    class shar(object):
        '''
        shar object is an optimized bit-stream handler
        
        It has ways to work over aligned byte-stream or unaligned bit-stream,
        exposing methods to:
        - convert it to buffer, byte-array, bit-array, unsigned integer, 
          signed integer
        - consume it by buffer, byte-array, bit-array, unsigned integer, 
          signed integer, for a given length in bits
        '''
        
        _REPR_POS = ('buf', 'bytes', 'bits', 'uint', 'int', 'hex', 'bin')
        _REPR = 'buf'
        _REPR_MAX = 512
        
        
        def __init__(self, *args):
            '''
            Initialize the shar object
            
            Parameters
            ----------
            no arg: an empty shar object is initialized
            single string arg: a shar object is initialized by setting a string 
                buffer
            single list arg: a shar object is initialized by setting a list of 
                bytes, or bits if values in the list are only 0 or 1
            double uint arg: a shar object is initialiazed by setting an 
                unsigned integer with a given length in bits
            
            Returns
            -------
            None
            '''
            if len(args):
                if isinstance(args[0], (str, bytes)):
                    self.set_buf(args[0])
                elif isinstance(args[0], (tuple, list, np.ndarray)):
                    if isinstance(args[0], np.ndarray):
                        tmp = np.copy(args[0], np.ubyte)
                    else:
                        tmp = np.array(args[0], np.ubyte)
                    # if only 0 and 1 in arg, consider it as a bit array
                    if np.all( (tmp==0)|(tmp==1) ):
                        self._ar_bit = tmp
                        self._ar_byte = bit_to_byte(self._ar_bit)
                    else:
                        self._ar_byte = tmp
                        self._ar_bit = byte_to_bit(self._ar_byte)
                    self._buf = self._ar_byte.tostring()
                    self._len_bit = len(self._ar_bit)
                    self._cur = 0
                elif len(args) == 2 and isinstance(args[0], (int, long)) \
                and args[0] >= 0 and isinstance(args[1], (int, long)) \
                and args[1] >= 0:
                    self.set_uint(args[0], args[1])
                else:
                    raise(TypeError('%s: argument type cannot be inferred' \
                                    % list(args)))
            else:
                self._ar_bit = np.array([], np.ubyte)
                self._ar_byte = np.array([], np.ubyte)
                self._buf = b''
                self._len_bit = 0
                self._cur = 0
        
        def __len__(self):
            '''
            length in bits
            '''
            return self._len_bit - self._cur
        
        def __bin__(self):
            '''
            binary representation
            '''
            return (self._ar_bit[self._cur:] + 0x30).tostring()
        
        def __hex__(self):
            '''
            hexadecimal representation
            '''
            return ''.join(map(lambda i: hex(i)[2:], self.to_bytes()))
        
        def __str__(self):
            '''
            human-readable representation
            '''
            return self.to_buf()
        
        def __repr__(self):
            '''
            Python object printable representation
            '''
            if self._REPR not in self._REPR_POS or self._REPR == 'buf':
                r = repr(self.to_buf())
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-2:])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'bytes':
                r = self.to_bytes()
                if len(r) > self._REPR_MAX:
                    return 'shar([%s, ..., %s])' \
                           % (str(list(r[0:self._REPR_MAX]))[1:-1], r[-1])
                else:
                    return 'shar(%s)' % list(r)
            elif self._REPR == 'bits':
                r = self.to_bits()
                if len(r) > self._REPR_MAX:
                    return 'shar([%s, ..., %s])' \
                           % (str(list(r[0:self._REPR_MAX]))[1:-1], r[-1])
                else:
                    return 'shar(%s)' % list(r)
            elif self._REPR == 'uint':
                r = repr(self.to_uint())
                if r[-1] == 'L':
                    r = r[:-1]
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'int':
                r = repr(self.to_int())
                if r[-1] == 'L':
                    r = r[:-1]
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'bin':
                r = ''.join(('0b', self.__bin__()))
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'hex':
                r = ''.join(('0x', self.__hex__()))
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
        
        def rewind(self, bitlen=None):
            '''
            rewind the shar object's cursor
            
            Parameters
            ----------
            bitlen : None or unsigned integer
            
            Returns
            -------
            None
            '''
            if bitlen is None or bitlen > self._cur:
                self._cur = 0
            elif bitlen > 0:
                self._cur = self._cur - bitlen
        
        def set_buf(self, buf=b''):
            '''
            reinitialize the shar object and its cursor by setting a Python 
            string buffer into it
            
            Parameters
            ----------
            buf : string buffer
            
            Returns
            -------
            None
            '''
            self._buf = buf
            self._ar_byte = np.frombuffer(buf, np.ubyte)
            self._ar_bit = byte_to_bit(self._ar_byte)
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_buf(self, bitlen=None):
            '''
            return the Python string buffer of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested string buffer
            
            Returns
            -------
            A Python string
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                return self._buf[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                return bit_to_byte(self._ar_bit[self._cur:self._cur+bitlen])\
                       .tobytes()
        
        def get_buf(self, bitlen=None):
            '''
            return the Python string buffer of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested string buffer
            
            Returns
            -------
            A Python string buffer, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                self._cur += bitlen
                return self._ar_byte[off_byte:off_byte+len_byte].tostring()
            else:
                # unaligned access
                cur = self._cur
                self._cur += bitlen
                return bit_to_byte(self._ar_bit[cur:cur+bitlen]).tostring()
        
        def set_bytes(self, bytes=[]):
            '''
            reinitialize the shar object and its cursor by setting a Python list 
            of uint8 integral value into it
            
            Parameters
            ----------
            bytes : list or tuple or numpy array of uint8 values
            
            Returns
            -------
            None
            '''
            if isinstance(bytes, np.ndarray):
                self._ar_byte = np.copy(bytes)
            else:
                self._ar_byte = np.array(bytes, np.ubyte)
            self._ar_bit = byte_to_bit(self._ar_byte)
            self._buf = self._ar_byte.tobytes()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_bytes(self, bitlen=None):
            '''
            return the numpy byte array of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested numpy byte array
            
            Returns
            -------
            A numpy array of type ubyte, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0:
                # aligned access
                return self._ar_byte[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                return bit_to_byte(self._ar_bit[self._cur:self._cur+bitlen])
        
        def get_bytes(self, bitlen=None):
            '''
            return the numpy byte array of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested numpy byte array
            
            Returns
            -------
            A numpy array of type ubyte, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                self._cur += bitlen
                return self._ar_byte[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                cur = self._cur
                self._cur += bitlen
                return bit_to_byte(self._ar_bit[cur:cur+bitlen])
        
        def set_bits(self, bits=[]):
            '''
            reinitialize the shar object and its cursor by setting a Python list 
            of 0 or 1 integral value into it
            
            Parameters
            ----------
            bits : list or tuple or numpy array of 0 or 1 values
            
            Returns
            -------
            None
            '''
            if isinstance(bits, np.ndarray):
                self._ar_bit = np.copy(bits)
            else:
                self._ar_bit = np.array(bits, np.ubyte)
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tobytes()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_bits(self, bitlen=None):
            '''
            return the numpy bit array of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested numpy bit array
            
            Returns
            -------
            A numpy array of type ubyte, with only 0 and 1 values
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            return self._ar_bit[self._cur:self._cur+bitlen]
        
        def get_bits(self, bitlen=None):
            '''
            return the numpy bit array of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested numpy bit array
            
            Returns
            -------
            A numpy array of type ubyte, with only 0 and 1 values
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            cur = self._cur
            self._cur += bitlen
            return self._ar_bit[cur:cur+bitlen]
        
        def set_uint(self, val=0, bitlen=None):
            '''
            reinitialize the shar object and its cursor by setting an arbitrary 
            unsigned integral value into it
            
            big endian representation is used (MSB on the most left, LSB on the 
            most right)
            
            Parameters
            ----------
            val : unsigned integer (can be long)
            bitlen : number of bits to be used to store the value; if less than 
                required by the value, value is majored to the maximum value 
                according to bitlen; if bitlen is None, encoding is done in the
                minimum number of bits
            
            Returns
            -------
            None
            '''
            val = bin(val)[2:]
            if bitlen is None:
                self._ar_bit = np.fromiter(val, np.ubyte)
            elif bitlen > len(val):
                # padding val
                self._ar_bit = np.array( (0,)*(bitlen-len(val)) + tuple(val),
                                         np.ubyte)
            else:
                # majoring to maximum bitlen value
                self._ar_bit = np.array( (1,)*bitlen, np.ubyte )
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tobytes()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_uint(self, bitlen=None):
            '''
            return the unsigned integral value of the shar object, starting at 
            the cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested unsigned integer
            
            Returns
            -------
            An unsigned integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur == self._len_bit or bitlen == 0:
                return None
            return int((self._ar_bit[self._cur:self._cur+bitlen] + 0x30)\
                       .tostring(), 2)
        
        def get_uint(self, bitlen=None):
            '''
            return the unsigned integral value of the shar object, starting at 
            the cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested unsigned integer
            
            Returns
            -------
            An unsigned integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur == self._len_bit or bitlen == 0:
                return None
            cur = self._cur
            self._cur += bitlen
            return int((self._ar_bit[cur:cur+bitlen] + 0x30).tostring(), 2)
        
        def set_int(self, val=0, bitlen=32):
            '''
            reinitialize the shar object and its cursor by setting an arbitrary 
            signed integral value into it (2's complement representation is 
            used)
            
            big endian representation is used (MSB on the most left, LSB on the 
            most right)
            
            Parameters
            ----------
            val : signed integer (can be long)
            bitlen : number of bits to be used to store the value (minus 1 bit
                to store the sign); if less than required by the value, absolute 
                value is majored by the max value according to bitlen
            
            Returns
            -------
            None
            '''
            if val < 0:
                val = abs(val)
                valmax = pow(2, bitlen-1)
                if val <= valmax:
                    # padding val
                    val = bin(valmax-val)[2:]
                    self._ar_bit = np.array( (1,) \
                                           + (0,)*(bitlen-1-len(val)) \
                                           + tuple(val),
                                             np.ubyte )
                else:
                    # majoring to maximum bitlen value
                    self._ar_bit = np.array( (1,) + (0,)*(bitlen-1),
                                             np.ubyte )
            else:
                valmax = pow(2, bitlen-1) - 1
                if val <= valmax:
                    # padding val
                    val_bin = bin(val)[2:]
                    self._ar_bit = np.array( (0,)*(bitlen-len(val_bin)) \
                                           + tuple(val_bin),
                                             np.ubyte )
                else:
                    # majoring to maximum bitlen value
                    self._ar_bit = np.array( (0,) + (1,)*bitlen-1, np.ubyte )
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tobytes()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_int(self, bitlen=None):
            '''
            return the signed integral value of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested signed integer
            
            Returns
            -------
            A signed integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur >= self._len_bit-1 or bitlen <= 1:
                return None
            val = int((self._ar_bit[self._cur+1:self._cur+bitlen] + 0x30)\
                      .tostring(), 2)
            if self._ar_bit[self._cur] == 1:
                # negative integer
                valmax = pow(2, bitlen-1)
                return val - valmax
            else:
                # positive integer
                return val
        
        def get_int(self, bitlen=None):
            '''
            return the signed integral value of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            The shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested signed integer
            
            Returns
            -------
            A signed integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur >= self._len_bit - 1 or bitlen < 2:
                return None
            val = int((self._ar_bit[self._cur+1:self._cur+bitlen] \
                       + 0x30).tostring(), 2)
            if self._ar_bit[self._cur] == 1:
                # negative integer
                self._cur += bitlen
                valmax = pow(2, bitlen-1)
                return val - valmax
            else:
                # positive integer
                self._cur += bitlen
                return val


# Python stdlib array version
else:
    
    class shar(object):
        '''
        shar object is an optimized bit-stream handler
        
        It has ways to work over aligned byte-stream or unaligned bit-stream,
        exposing methods to:
        - convert it to buffer, byte-array, bit-array, unsigned integer, 
          signed integer
        - consume it by buffer, byte-array, bit-array, unsigned integer, 
          signed integer, for a given length in bits
        '''
        
        _REPR_POS = ('buf', 'bytes', 'bits', 'uint', 'int', 'hex', 'bin')
        _REPR = 'buf'
        _REPR_MAX = 512
        
        
        def __init__(self, *args):
            '''
            Initialize the shar object
            
            Parameters
            ----------
            no arg: an empty shar object is initialized
            single string arg: a shar object is initialized by setting a string 
                buffer
            single list arg: a shar object is initialized by setting a list of 
                bytes, or bits if values in the list are only 0 or 1
            double uint arg: a shar object is initialiazed by setting an 
                unsigned integer with a given length in bits
            
            Returns
            -------
            None
            '''
            if len(args):
                if isinstance(args[0], (str, bytes)):
                    self.set_buf(args[0])
                elif isinstance(args[0], (tuple, list)):
                    tmp = array('B', args[0])
                    # if only 0 and 1 in arg, consider it as a bit array
                    if all(map(lambda i: i in (0,1), tmp)):
                        self._ar_bit = tmp
                        self._ar_byte = bit_to_byte(self._ar_bit)
                    else:
                        self._ar_byte = tmp
                        self._ar_bit = byte_to_bit(self._ar_byte)
                    self._buf = self._ar_byte.tostring()
                    self._len_bit = len(self._ar_bit)
                    self._cur = 0
                elif len(args) == 2 and isinstance(args[0], (int, long)) \
                and args[0] >= 0 and isinstance(args[1], (int, long)) \
                and args[1] >= 0:
                    self.set_uint(args[0], args[1])
                else:
                    raise(TypeError('%s: argument type cannot be inferred' \
                                    % list(args)))
            else:
                self._ar_bit = array('B', [])
                self._ar_byte = array('B', [])
                self._buf = b''
                self._len_bit = 0
                self._cur = 0
        
        def __len__(self):
            '''
            length in bits
            '''
            return self._len_bit - self._cur
        
        def __bin__(self):
            '''
            binary representation
            '''
            return ''.join(map(lambda i: chr(i+0x30), self._ar_bit[self._cur:]))
        
        def __hex__(self):
            '''
            hexadecimal representation
            '''
            return ''.join(map(lambda i: hex(i)[2:], self.to_bytes()))
        
        def __str__(self):
            '''
            human-readable representation
            '''
            return self.to_buf()
        
        def __repr__(self):
            '''
            Python object printable representation
            '''
            if self._REPR not in self._REPR_POS or self._REPR == 'buf':
                r = repr(self.to_buf())
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-2:])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'bytes':
                r = self.to_bytes()
                if len(r) > self._REPR_MAX:
                    return 'shar([%s, ..., %s])' \
                           % (str(list(r[0:self._REPR_MAX]))[1:-1], r[-1])
                else:
                    return 'shar(%s)' % list(r)
            elif self._REPR == 'bits':
                r = self.to_bits()
                if len(r) > self._REPR_MAX:
                    return 'shar([%s, ..., %s])' \
                           % (str(list(r[0:self._REPR_MAX]))[1:-1], r[-1])
                else:
                    return 'shar(%s)' % list(r)
            elif self._REPR == 'uint':
                r = str(self.to_uint())
                if r[-1] == 'L':
                    r = r[:-1]
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'int':
                r = repr(self.to_int())
                if r[-1] == 'L':
                    r = r[:-1]
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'bin':
                r = ''.join(('0b', self.__bin__()))
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
            elif self._REPR == 'hex':
                r = ''.join(('0x', self.__hex__()))
                if len(r) > self._REPR_MAX:
                    return 'shar(%s...%s)' % (r[0:self._REPR_MAX], r[-1])
                else:
                    return 'shar(%s)' % r
        
        def rewind(self, bitlen=None):
            '''
            rewind the shar object's cursor
            
            Parameters
            ----------
            bitlen : None or unsigned integer
            
            Returns
            -------
            None
            '''
            if bitlen is None or bitlen > self._cur:
                self._cur = 0
            elif bitlen > 0:
                self._cur = self._cur - bitlen
        
        def set_buf(self, buf=b''):
            '''
            reinitialize the shar object and its cursor by setting a Python 
            string buffer into it
            
            Parameters
            ----------
            buf : string buffer
            
            Returns
            -------
            None
            '''
            self._buf = buf
            self._ar_byte = array('B')
            self._ar_byte.fromstring(buf)
            self._ar_bit = byte_to_bit(self._ar_byte)
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_buf(self, bitlen=None):
            '''
            return the Python string buffer of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested string buffer
            
            Returns
            -------
            A Python string
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                return self._buf[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                return bit_to_byte(self._ar_bit[self._cur:]).tostring()
        
        def get_buf(self, bitlen=None):
            '''
            return the Python string buffer of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested string buffer
            
            Returns
            -------
            A Python string buffer, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                self._cur += bitlen
                return self._buf[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                cur = self._cur
                self._cur += bitlen
                return bit_to_byte(self._ar_bit[cur:cur+bitlen]).tostring()
        
        def set_bytes(self, bytes=[]):
            '''
            reinitialize the shar object and its cursor by setting a Python list 
            of uint8 integral value into it
            
            Parameters
            ----------
            bytes : list or tuple or array of uint8 values
            
            Returns
            -------
            None
            '''
            if isinstance(bytes, array):
                self._ar_byte = bytes[:]
            else:
                if isinstance(bytes, tuple):
                    bytes = list(bytes)
                self._ar_byte = array('B')
                self._ar_byte.fromlist(bytes)
            self._ar_bit = byte_to_bit(self._ar_byte)
            self._buf = self._ar_byte.tostring()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_bytes(self, bitlen=None):
            '''
            return the byte array of the shar object, starting at the cursor 
            position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested byte array
            
            Returns
            -------
            An array of type uchar, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                return self._ar_byte[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                return bit_to_byte(self._ar_bit[self._cur:self._cur+bitlen])
        
        def get_bytes(self, bitlen=None):
            '''
            return the byte array of the shar object, starting at the cursor 
            position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested byte array
            
            Returns
            -------
            An array of type uchar, zero-padded at the end if required
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            off_byte, off_bit = self._cur // 8, self._cur % 8
            len_byte, len_bit = bitlen // 8, bitlen % 8
            if off_bit == 0 and len_bit == 0:
                # aligned access
                self._cur += bitlen
                return self._ar_byte[off_byte:off_byte+len_byte]
            else:
                # unaligned access
                cur = self._cur
                self._cur += bitlen
                return bit_to_byte(self._ar_bit[cur:cur+bitlen])
        
        def set_bits(self, bits=[]):
            '''
            reinitialize the shar object and its cursor by setting a Python list 
            of 0 or 1 integral value into it
            
            Parameters
            ----------
            bits : list or tuple or array of 0 or 1 values
            
            Returns
            -------
            None
            '''
            if isinstance(bits, array):
                self._ar_bit = bits[:]
            else:
                if isinstance(bits, tuple):
                    bits = list(bits)
                self._ar_bit = array('B')
                self._ar_bit.fromlist(bits)
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tostring()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_bits(self, bitlen=None):
            '''
            return the bit array of the shar object, starting at the cursor 
            position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested bit array
            
            Returns
            -------
            An array of type uchar, with only 0 and 1 values
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            return self._ar_bit[self._cur:self._cur+bitlen]
        
        def get_bits(self, bitlen=None):
            '''
            return the bit array of the shar object, starting at the cursor 
            position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested bit array
            
            Returns
            -------
            An array of type uchar, with only 0 and 1 values
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            cur = self._cur
            self._cur += bitlen
            return self._ar_bit[cur:cur+bitlen]
        
        def set_uint(self, val=0, bitlen=None):
            '''
            reinitialize the shar object and its cursor by setting an arbitrary 
            unsigned integral value into it
            
            big endian representation is used (MSB on the most left, LSB on the 
            most right)
            
            Parameters
            ----------
            val : unsigned integer (can be long)
            bitlen : number of bits to be used to store the value; if less than 
                required by the value, value is majored to the maximum value 
                according to bitlen; if bitlen is None, encoding is done in the
                minimum number of bits
            
            Returns
            -------
            None
            '''
            val = list(map(int, bin(val)[2:]))
            if bitlen is None:
                self._ar_bit = array('B', val)
            elif bitlen > len(val):
                # padding val
                self._ar_bit = array('B', [0]*(bitlen-len(val)) + val)
            else:
                # majoring to maximum bitlen value
                self._ar_bit = array('B', (1,)*bitlen )
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tostring()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_uint(self, bitlen=None):
            '''
            return the unsigned integral value of the shar object, starting at 
            the cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested unsigned integer
            
            Returns
            -------
            An unsigned integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur == self._len_bit or bitlen == 0:
                return None
            return int(''.join(map(lambda i: chr(i+0x30), 
                               self._ar_bit[self._cur:self._cur+bitlen])), 2)
        
        def get_uint(self, bitlen=None):
            '''
            return the unsigned integral value of the shar object, starting at 
            the cursor position and ending after the given bitlen
            
            the shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested unsigned integer
            
            Returns
            -------
            An unsigned integral value
            '''
            if self._cur == self._len_bit:
                return None
            if self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            cur = self._cur
            self._cur += bitlen
            return int(''.join(map(lambda i: chr(i+0x30), 
                               self._ar_bit[cur:cur+bitlen])), 2)
        
        def set_int(self, val=0, bitlen=32):
            '''
            reinitialize the shar object and its cursor by setting an arbitrary 
            signed integral value into it (2's complement representation is 
            used)
            
            big endian representation is used (MSB on the most left, LSB on the 
            most right)
            
            Parameters
            ----------
            val : signed integer (can be long)
            bitlen : number of bits to be used to store the value (minus 1 bit
                to store the sign); if less than required by the value, absolute 
                value is majored by the max value according to bitlen
            
            Returns
            -------
            None
            '''
            if val < 0:
                val = abs(val)
                valmax = pow(2, bitlen-1)
                if val < valmax:
                    # padding val
                    val = list(map(int, bin(valmax-val)[2:]))
                    self._ar_bit = array('B', [1] \
                                            + [0]*(bitlen-1-len(val)) \
                                            + val)
                else:
                    # majoring to maximum bitlen value
                    self._ar_bit = array('B', (1,) + (0,)*(bitlen-1))
            else:
                valmax = pow(2, bitlen-1) - 1
                if val <= valmax:
                    # padding val
                    val_bin = list(map(int, bin(val)[2:]))
                    self._ar_bit = array('B', [0]*(bitlen-len(val_bin)) \
                                            + val_bin)
                else:
                    # majoring to maximum bitlen value
                    self._ar_bit = array('B', (0,) + (1,)*(bitlen-1))
            self._ar_byte = bit_to_byte(self._ar_bit)
            self._buf = self._ar_byte.tostring()
            self._len_bit = len(self._ar_bit)
            self._cur = 0
        
        def to_int(self, bitlen=None):
            '''
            return the signed integral value of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested signed integer
            
            Returns
            -------
            A signed integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur >= self._len_bit-1 or bitlen <= 1:
                return None
            val = int(''.join(map(lambda i: chr(i+0x30), 
                              self._ar_bit[self._cur+1:self._cur+bitlen])), 2)
            if self._ar_bit[self._cur] == 1:
                # negative integer
                valmax = pow(2, bitlen-1)
                return val - valmax
            else:
                # positive integer
                return val
        
        def get_int(self, bitlen=None):
            '''
            return the signed integral value of the shar object, starting at the
            cursor position and ending after the given bitlen
            
            The shar object's cursor is incremented according to bitlen
            
            Parameters
            ----------
            bitlen : length in bits for the requested signed integer
            
            Returns
            -------
            A signed integral value
            '''
            if bitlen is None:
                bitlen = self._len_bit - self._cur
            elif self._cur + bitlen > self._len_bit:
                bitlen = self._len_bit - self._cur
            if self._cur >= self._len_bit-1 or bitlen <= 1:
                return None
            val = int(''.join(map(lambda i: chr(i+0x30), 
                              self._ar_bit[self._cur+1:self._cur+bitlen])), 2)
            if self._ar_bit[self._cur] == 1:
                # negative integer
                self._cur +=  bitlen
                valmax = pow(2, bitlen-1)
                return val - valmax
            else:
                # positive integer
                self._cur += bitlen
                return val

def test():
    err = 0
    buf = b'\xC0aAbBcC1234\x81\x92\xB3\xF4' * 300
    A = shar(buf)
    B = shar()
    # aligned accesses
    B.set_buf( A.to_buf() )
    if B.to_buf() != buf: raise(Exception)
    B.set_bytes( A.to_bytes() )
    if B.to_buf() != buf: raise(Exception)
    B.set_bits( A.to_bits() )
    if B.to_buf() != buf: raise(Exception)
    B.set_uint( A.to_uint() )
    if B.to_buf() != buf: raise(Exception)
    B.set_int( A.get_int(4096), 4096 )
    A.rewind()
    if B.to_buf() != buf[:512]: raise(Exception)
    # unaligned accesses
    if list(A.get_bits(7)) != [1, 1, 0, 0, 0, 0, 0]: raise(Exception)
    if A.get_buf(3) != b'\x20': raise(Exception)
    if list(A.get_bytes(22)) != [133, 5, 136]: raise(Exception)
    B.set_buf( A.to_buf() )
    if B.to_buf() != buf[4:]: err += 1
    if list(A.get_bits(13)) != [0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0]:
        raise(Exception)
    if A.get_uint(18) != 106904: raise(Exception)
    if A.get_int(17) != -52685: raise(Exception)
    if list(A.get_bits(3)) != [0, 0, 1]: raise(Exception)
    B.set_buf( A.to_buf() )
    if B.to_buf()[:4200] != b'\xa4\x0c\x95\x9f\xa6\x03\n\x0b\x12\x13'\
                            b'\x1a\x19\x89\x91\x99' * 280: raise(Exception)
    # some more assignment
    B.set_bits((1,0,1,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1))
    if tuple(B.to_bits()) != (1,0,1,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,1,0,1,1,
                               0,1,0,0,1,0,1): raise(Exception)
    B.set_bytes((12,32,95,78,65,152,158,254,32,12,65,95,123,198,231,97,65,37))
    if tuple(B.to_bytes()) != (12,32,95,78,65,152,158,254,32,12,65,95,123,198,
                                231,97,65,37): raise(Exception)
    B.set_uint(124165464763213543504504635046341)
    if B.to_uint() != 124165464763213543504504635046341: raise(Exception)
    B.set_uint(124165464763213543504504635046341, 32)
    if B.to_uint() != 4294967295: raise(Exception)
    B.set_uint(124165464763213543504504635046341, 1024)
    if B.to_uint() != 124165464763213543504504635046341: raise(Exception)
    B.set_int(-1241654647632135435045046350463410, 32)
    if B.to_int() != -2147483648: raise(Exception)
    B.set_int(-1241654647632135435045046350463410, 1024)
    if B.to_int() != -1241654647632135435045046350463410: raise(Exception)
#
#