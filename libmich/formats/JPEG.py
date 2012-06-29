# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.1 
# *
# * Copyright © 2012. Benoit Michau.
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
# * File Name : formats/JPEG.py
# * Created : 2012-04-16
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Bit, Layer, Block, log, \
    DBG, WNG, ERR, show, showattr
from libmich.core.IANA_dict import IANA_dict

Seg_dict = IANA_dict({
    
    # reserved markers
    0x01 : ('Temporary private use in arithmetic coding', 'TEM'),
    0x02 : ('reserved', 'RES'),
    0xBF : ('reserved', 'RES'),
    
    # non-differential Huffman coding
    0xC0 : ('Start Of Frame (Baseline DCT)', 'SOF0'),
    0xC1 : ('Start Of Frame (Extended Sequential DCT)', 'S0F1'),
    0xC2 : ('Start Of Frame (Progressive DCT)', 'SOF2'),
    0xC3 : ('Start Of Frame (Lossless Sequential)', 'S0F3'),
    
    # differential Huffman coding
    0xC5 : ('Start Of Frame (Differential Sequential DCT)', 'SOF5'),
    0xC6 : ('Start Of Frame (Differential Progressive DCT)', 'S0F6'),
    0xC7 : ('Start Of Frame (Differential Lossless Sequential)', 'SOF7'),
    
    # non-differential arithmetic coding
    0xC8 : ('Start Of Frame (Reserved for JPEG extensions', 'JPG'),
    0xC9 : ('Start Of Frame (Extended Sequential DCT)', 'S0F9'),
    0xCA : ('Start Of Frame (Progressive DCT)', 'SOF10'),
    0xCB : ('Start Of Frame (Lossless Sequential)', 'S0F11'),
    
    # differential arithmetic coding
    0xCD : ('Start Of Frame (Differential Sequential DCT)', 'SOF12'),
    0xCE : ('Start Of Frame (Differential Progressive DCT)', 'S0F13'),
    0xCF : ('Start Of Frame (Differential Lossless Sequential)', 'SOF14'),
    
    # huffman table spec
    0xC4 : ('Define Huffman Table(s)', 'DHT'),
    # arithmetic coding conditioning spec
    0xCC : ('Define Arithmetic Coding Conditioning(s)', 'DAC'),
    
    # restart interval termination
    0xD0 : ('RST0'),
    0xD1 : ('RST1'),
    0xD2 : ('RST2'),
    0xD3 : ('RST3'),
    0xD4 : ('RST4'),
    0xD5 : ('RST5'),
    0xD6 : ('RST6'),
    0xD7 : ('RST7'),
    
    # other markers
    0xD8 : ('Start Of Image', 'SOI'),
    0xD9 : ('End Of Image', 'EOI'),
    0xDA : ('Start Of Scan', 'SOS'),
    0xDB : ('Define Quantization Table(s)', 'DQT'),
    0xDD : ('Define Restart Interval', 'DRI'),
    0xDE : ('Define Hierarchichal Progression', 'DHP'),
    0xDF : ('Expand Reference Component(s)', 'EXP'),
    
    # reserved for application segments
    0xE0 : ('APP0'),
    0xE1 : ('APP1'),
    0xE2 : ('APP2'),
    0xE3 : ('APP3'),
    0xE4 : ('APP4'),
    0xE5 : ('APP5'),
    0xE6 : ('APP6'),
    0xE7 : ('APP7'),
    0xE8 : ('APP8'),
    0xE9 : ('APP9'),
    0xEA : ('APPA'),
    0xEB : ('APPB'),
    0xEC : ('APPC'),
    0xED : ('APPD'),
    0xEE : ('APPE'),
    0xEF : ('APPF'),
    
    # reserved for JPEG extensions
    0xF0 : ('JPG0'),
    0xF1 : ('JPG1'),
    0xF2 : ('JPG2'),
    0xF3 : ('JPG3'),
    0xF4 : ('JPG4'),
    0xF5 : ('JPG5'),
    0xF6 : ('JPG6'),
    0xF7 : ('JPG7'),
    0xF8 : ('JPG8'),
    0xF9 : ('JPG9'),
    0xFA : ('JPGA'),
    0xFB : ('JPGB'),
    0xFC : ('JPGC'),
    0xFD : ('JPGD'),
    
    # comment
    0xFE : ('Comment', 'COM'),
    })

class segment(Layer):
    constructorList = [
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xFE, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Str('pay', Pt=''),
        ]
    
    # these are segment types that have a variable length payload
    var_len = (0xC0, 0xC2, 0xC4, 0xDA, 0xDB, 0xDD, 224, 225, 226, 227, 228, \
               229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 0xFE)
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.len.Trans = self.type
        self.len.TransFunc = lambda t: False if t() in self.var_len else True
        self.pay.Len = self.len
        self.pay.LenFunc = lambda l: l()-2
        self.len.Pt = self.pay
        self.len.PtFunc = lambda p: len(p)+2

    
