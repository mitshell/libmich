# −*− coding: UTF−8 −*−
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
# * File Name : formats/BMP.py
# * Created : 2012-02-14 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Element, Str, Int,  Layer, Block, \
    RawLayer, show, debug
from zlib import crc32
from struct import pack #, unpack

# fastest large image processing:
Element.safe = False
Str.dbg = 0
Str._repr_limit = 64
Layer.dbg = 0

# all uint fields are little endian
Int._endian = 'little'

class BMP(Block):
    
    def __init__(self):
        Block.__init__(self, Name="BMP")
        hdr = FileHeader()
        self.append(hdr)
    
    def parse(self, s):
        # get File and DIB header
        if not isinstance(self[0], FileHeader):
            self.__init__()
        self << DIBHeader()
        self.map(s)
        s = s[len(self):]
        # check if color table is present
        if hasattr(self.DIBHeader, 'ColorsInColorTable'):
            c = self.DIBHeader.ColorsInColorTable()
            if c > 0:
                self | ColorTable(c)
                self[-1].map(s)
                s=s[len(self[-1]):]
        # check if some padding exist to the pixel array
        cur_length = len(self)
        offset = self.FileHeader.Offset()
        if cur_length < offset:
            self | RawLayer()
            self.map(s[:offset-cur_length])
            s=s[offset-cur_length:]
        # map the pixel array
        self | PixelArray(self.DIBHeader.Height(), self.DIBHeader.Width(),\
                          self.DIBHeader.BitsPerPixel())
        self[-1].map(s[:self.DIBHeader.ImageSize()])
        s = s[len(self[-1]):]
        # if still some data stream, could go to color profile
        if len(s) > 0:
            self | RawLayer()
            self[-1].map(s)
        

class FileHeader(Layer):
    constructorList = [
        Str('Signature', Pt='BM', Len=2),
        Int('Size', Type='uint32'),
        Str('Reserved', Pt='\0\0\0\0', Len=4, Repr='hex'),
        Int('Offset', Type='uint32'),
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.Size.Pt = self.get_payload
        self.Size.PtFunc = lambda pay: len(pay())+14
        self.Offset.Pt = self.get_payload
        self.Offset.PtFunc = self._calc_offset
    
    def _calc_offset(self, pay):
        p = pay()
        o = 14
        for l in p:
            if isinstance(l, PixelArray):
                return o
            o += len(l)
        return o
    

class DIBHeader(Layer):
    constructorList = [
        Int('DIBHeaderSize', Type='uint32'),
        Int('Width', Pt=0, Type='uint32'),
        Int('Height', Pt=0, Type='uint32'),
        Int('Planes', Pt=0, Type='uint16'),
        Int('BitsPerPixel', Pt=0, Type='uint16'),
        Int('Comp', Pt=0, Type='uint32'),
        Int('ImageSize', Pt=0, Type='uint32'),
        Int('XPixelsPerMeter', Pt=0, Type='uint32'),
        Int('YPixelsPerMeter', Pt=0, Type='uint32'),
        Int('ColorsInColorTable', Type='uint32'),
        Int('ImportantColorCount', Pt=0, Type='uint32'),
        Int('RedChannelBitmask', Pt=0, Type='uint32', Repr='hex'),
        Int('GreenChannelBitmask', Pt=0, Type='uint32', Repr='hex'),
        Int('BlueChannelBitmask', Pt=0, Type='uint32', Repr='hex'),
        Int('AlphaChannelBitmask', Pt=0, Type='uint32', Repr='hex'),
        Int('ColorSpaceType', Pt=0, Type='uint32'),
        Int('ColorSpaceEndpoints', Pt=0, Type='uint32'),
        Int('GammaRed', Pt=0, Type='uint32'),
        Int('GammaGreen', Pt=0, Type='uint32'),
        Int('GammaBlue', Pt=0, Type='uint32'),
        Int('Intent', Pt=0, Type='uint32'),
        Int('ICCProfileData', Pt=0, Type='uint32'),
        Int('ICCProfileSize', Pt=0, Type='uint32'),
        Int('Reserved', Pt=0, Type='uint32', Repr='hex'),
        ]
    
    def __init__(self):
        Layer.__init__(self)
        self.DIBHeaderSize.Pt = self
        self.DIBHeaderSize.PtFunc = lambda dib: sum(map(len, dib[1:]))+4
        self.ColorsInColorTable.Pt = 0
        self.ColorsInColorTable.PtFunc = self._count_colors
    
    def _count_colors(self, count):
        if self.inBlock and hasattr(self.Block, 'ColorTable'):
            count = len(block.ColorTable.elementList)
        return count
    
    def map(self, s=''):
        # this is to adapt DIB header size to common most applications
        self.DIBHeaderSize
        expected_size = self.DIBHeaderSize()
        self[0].map(s[:4])
        real_size = self.DIBHeaderSize()
        # remove last values from the header structure
        if real_size < expected_size:
            to_remove = (expected_size-real_size)/4
            for i in range(to_remove):
                self.remove(self[-1])
        elif real_size > expected_size:
            debug(self.dbg, 2, 'DIB header not long enough: not standard')
        Layer.map(self, s)
    

class ColorTable(Layer):
    
    def __init__(self, num=1):
        Layer.__init__(self)
        for i in range(num):
            self.add_color()
        
    def add_color(self):
        c = Int('Color_%i' % len(self.elementLen)+1, Pt=0, Type='uint32')
        self.append(c)
    

class PixelArray(Layer):
    
    def __init__(self, height=1, width=1, bits_per_pixel=8):
        Layer.__init__(self)
        for i in range(height):
            self.add_row(width, bits_per_pixel)
        
    def add_row(self, width=1, bits_per_pixel=8):
        # TODO: handle padding correctly
        r = Str('Pixel_row_%i' % len(self.elementList), \
                Len=((width*bits_per_pixel)/8), Repr='hex')
        self.append(r)
        
    def _pad_row(self):
        pass
    

class ColorProfile(Layer):
    constructorList = [ ]


