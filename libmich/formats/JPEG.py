# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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

# Segment containing JPEG meta-data
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
    0xC8 : ('Start Of Frame (Reserved for JPEG extensions)', 'JPG'),
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
    #_var_len = (0xC0, 0xC2, 0xC4, 0xDA, 0xDB, 0xDD, 224, 225, 226, 227, 228, \
    #            229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 0xFE)
    # these are segment types without length / payload
    _no_pay = (0xD8, 0xD9)
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.len.Trans = self.type
        #self.len.TransFunc = lambda t: False if t() in self._var_len else True
        self.len.TransFunc = lambda t: True if t() in self._no_pay else False
        self.pay.Len = self.len
        self.pay.LenFunc = lambda l: l()-2
        self.len.Pt = self.pay
        self.len.PtFunc = lambda p: len(p)+2
#
# Start Of Frame specificities
class SOF(segment):
    constructorList = [
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xC0, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Int('P', ReprName='Sample Precision', Pt=0, Type='uint8'),
        Int('Y', ReprName='Number of lines', Pt=0, Type='uint16'),
        Int('X', ReprName='Number of sample per line', Pt=0, Type='uint16'),
        Int('Nf', ReprName='Number of image components in frame', Pt=0, \
            Type='uint8'),
        Str('components', Pt=''),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.components.Len = self.len
        self.components.LenFunc = lambda l: l()-8
        self.len.Pt = self.components
        self.len.PtFunc = lambda p: len(p)+8
    
    def map(self, s=''):
        Layer.map(self, s)
        if len(self.components) / 3.0 == self.Nf():
            cpn_s = self.components()
            self.remove(self.components)
            while len(cpn_s) > 0:
                self.append(SOFComponent())
                self[-1].map(cpn_s)
                cpn_s = cpn_s[3:]

class SOFComponent(Layer):
    constructorList = [
        Int('C', ReprName='Component identifier', Pt=0, Type='uint8'),
        Bit('H', ReprName='Horizontal sampling factor', Pt=0, BitLen=4, \
            Repr='hum'),
        Bit('V', ReprName='Vertical sampling factor', Pt=0, BitLen=4, \
            Repr='hum'),
        Int('Tq', ReprName='Quantization table destination selector', Pt=0, \
            Type='uint8'),
        ]
#
# Start Of Scan specificities
class SOS(segment):
    constructorList = [
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xDA, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Int('Nf', ReprName='Number of image components in frame', Pt=0, \
            Type='uint8'),
        Str('components', Pt=''),
        Int('Ss', ReprName='Start of spectral or predictor selection', Pt=0, \
            Type='uint8'),
        Int('Se', ReprName='End of spectral selection', Pt=0, Type='uint8'),
        Bit('Ah', ReprName='Successive approximation bit position high', \
            Pt=0, BitLen=4, Repr='hum'),
        Bit('Al', ReprName='Successive approximation bit position low', \
            Pt=0, BitLen=4, Repr='hum'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.components.Len = self.len
        self.components.LenFunc = lambda l: l()-6
        self.len.Pt = self.components
        self.len.PtFunc = lambda p: len(p)+6
    
    def map(self, s=''):
        Layer.map(self, s)
        if len(self.components) / 2.0 == self.Nf():
            cpn_s = self.components()
            self.remove(self.components)
            pos = 4
            while len(cpn_s) > 0:
                self.insert(pos, SOSComponent())
                self[pos].map(cpn_s)
                cpn_s = cpn_s[2:]
                pos += 1

class SOSComponent(Layer):
    constructorList = [
        Int('Cs', ReprName='Scan component selector', Pt=0, Type='uint8'),
        Bit('Td', ReprName='DC entropy coding table destination selector', \
            Pt=0, BitLen=4, Repr='hum'),
        Bit('Ta', ReprName='AC entropy coding table destination selector', \
            Pt=0, BitLen=4, Repr='hum'),
        ]

class DQT(segment):
    constructorList = [
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xDB, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Bit('Pq', ReprName='Quantization table element precision', \
            Pt=0, BitLen=4, Repr='hum'),
        Bit('Tq', ReprName='Quantization table destination identifier', \
            Pt=0, BitLen=4, Repr='hum')] + [ \
        Bit('Q%i'%k, ReprName='Quantization table element %i'%k, \
            Pt=1, Repr='hum') for k in range(64) ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # length automation
        self.len.Pt = self.Pq
        self.len.PtFunc = lambda x: sum(map(len, self[5:]))+3
        # Qk length automation: Pq = 0 -> 8 bits, 1 -> 16 bits
        for k in range(64):
            getattr(self, 'Q%i'%k).BitLen = self.Pq
            getattr(self, 'Q%i'%k).BitLenFunc = self._Qlen
    
    def _Qlen(self, pq):
        return 16 if pq() else 8

class DHT(segment):
    constructorList = [ 
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xC4, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Bit('Tc', ReprName='Huffman table class', Pt=0, BitLen=4, Repr='hum'),
        Bit('Th', ReprName='Huffman table destination identifier', Pt=0, \
            BitLen=4, Repr='hum')] + [ \
        Int('L%i'%i, ReprName='Number of huffman codes of length %i'%i, \
            Pt=0, Type='uint8') for i in range(1, 17)] + \
        [Str('V', ReprName='Values for huffman codes of given length', Pt='')]
        # this is a shortcut for huffman Values
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # length automation
        self.len.Pt = self.L1
        self.len.PtFunc = lambda x: sum(map(len, self[21:]))+19
        # huffman values length automation
        self.V.Len = self.L1
        self.V.LenFunc = lambda x: sum(map(int, self[5:21]))
    
    def map(self, s=''):
        Layer.map(self, s)
        values, pos = self.V(), 0
        self.remove(self[-1])
        for i in self[5:21]:
            for j in range(1, i()+1):
                ith = int(i.CallName[1:])
                self.append(\
                Int('V%i%i'%(ith,j), \
                    ReprName='Value %i for huffman code of length %i'%(j,ith), \
                    Val=ord(values[pos]), Type='uint8'))
                pos += 1

class DAC(segment):
    constructorList = [ 
        Int('mark', Pt=0xFF, Type='uint8', Repr='hex'),
        Int('type', Pt=0xCC, Type='uint8', Repr='hum', Dict=Seg_dict),
        Int('len', Pt=0, Type='uint16'),
        Str('pay', Pt='\0\0'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # length automation
        self.pay.Len = self.len
        self.pay.LenFunc = lambda l: l()-2
        self.len.Pt = self.pay
        self.len.PtFunc = lambda p: len(p)+2
    
    def map(self, s=''):
        Layer.map(self, s)
        if len(self.pay) % 2 == 0:
            pay = str(self.pay)
            self.remove(self[-1])
            while len(pay) > 0:
                self.append(DACComponent())
                self[-1].map(pay)
                pay = pay[2:]

class DACComponent(Layer):
    constructorList = [
        Bit('Tc', ReprName='Table class', Pt=0, BitLen=4, Repr='hum'),
        Bit('Tb', ReprName='Arithmetic coding conditioning table destination identifier', \
            Pt=0, BitLen=4, Repr='hum'),
        Int('CS', ReprName='Conditioning table value', Pt=0, Type='uint8'),
        ]

class data(Layer):
    constructorList = [ Str('data', Pt='') ]

#
# JPEG Block, to parse entire JPEG image
class JPEG(Block):
    # segment specific processing
    SEG_SPECIFICS = {
        # Start Of Frame
        0xC0 : SOF, 
        0xC1 : SOF, 
        0xC2 : SOF, 
        0xC3 : SOF,
        0xC5 : SOF, 
        0xC6 : SOF, 
        0xC7 : SOF,
        0xC8 : SOF, 
        0xC9 : SOF, 
        0xCA : SOF, 
        0xCB : SOF, 
        0xCD : SOF, 
        0xCE : SOF, 
        0xCF : SOF,
        # Start Of Scan
        0xDA : SOS,
        # Tables
        0xDB : DQT,
        0xC4 : DHT,
        }
    
    def __init__(self, ):
        Block.__init__(self, Name="JPEG")
        self << segment(type=Seg_dict['SOI'])
    
    def parse(self, im=''):
        self.__init__()
        self[-1].map(im)
        im = im[2:]
        # start by scanning header segments
        while len(im) > 0:
            self.append( segment() )
            self[-1].map(im)
            # check for segment specific processing
            # e.g. SOF, SOS...
            self._chk_segment()
            #
            self[-1].set_hierarchy(1)
            im = im[len(self[-1]):]
            #
            # if Start of Scan segment, stop parsing header segment
            # scan the (compressed) raw data, interleaved marker
            # and finish with EOI:
            # 0xFF data byte is always stuffed with a NULL byte
            # so it shouldn't clash with a segment marker
            if self[-1].type() == 0xDA:
                break
        #
        m = self._scan_for_marker(im)
        while m >= 0:
            # real marker found
            # get compressed data before the marker
            if m > 0:
                self.append( data() )
                self[-1].map( im[:m] )
                self[-1].set_hierarchy(1)
                im = im[m:]
            # get corresponding marker segment
            self.append( segment() )
            self[-1].map(im)
            self._chk_segment()
            self[-1].set_hierarchy(1)
            im = im[len(self[-1]):]
            # check for more marker
            m = self._scan_for_marker(im)
        # finalize
        if self[-1].type() == Seg_dict['EOI']:
            self[-1].set_hierarchy(0)
    
    def _chk_segment(self):
        if self.SEG_SPECIFICS.has_key(self[-1].type()):
            seg_type = self[-1].type()
            seg_buf = str(self[-1])
            #seg_hier = self[-1].hierarchy
            # remove current segment from the JPEG Block
            self.remove(self.num()-1)
            # and add an instance of the one more specifics
            self.append( self.SEG_SPECIFICS[seg_type]() )
            self[-1].map(seg_buf)
            #self[-1].set_hierarchy(seg_hier)
    
    def _scan_for_marker(self, im=''):
        offset = 0
        while True:
            m = im[offset:].find('\xFF')
            if m >= 0 and im[offset+m+1] != '\0':
                # found a real marker
                return offset+m
            elif m == -1:
                # in case no marker is found
                return -1
            else:
                # continue scanning
                offset += m+2
