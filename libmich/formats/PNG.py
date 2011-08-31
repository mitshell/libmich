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
# * File Name : formats/PNG.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, \
     Layer, Block, RawLayer
from zlib import crc32
from struct import pack #, unpack

class PNG(Block):
    
    def __init__(self):
        Block.__init__(self, Name="PNG")
        self.append( PNG_sig() )
    
    def parse(self, s):
        if s[:8] != str(self[0]):
            print '[WNG] Bad file signature: probably not a PNG'
        self[0].map( s )
        s = s[ len(self[0]) : ]
        # Then iteratively, map each png chunk
        while len(s) > 0:
            self.append( PNG_chunk() )
            self[-1].map( s )
            self[-1].hierarchy += 1
            #check for CRC correctness
            crc = self[-1].crc()
            self[-1].crc.Val = None
            if crc != self[-1].crc():
                print '[WNG] Bad CRC checksum for layer:\n%s\n' % self[-1]
            self[-1].crc.Val = crc
            s = s[ len(self[-1]) : ]
    

class PNG_sig(Layer):
    constructorList = [
        Str(CallName='sig', ReprName='Signature', Pt='\x89PNG\r\n\x1a\n', Len=8),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='sig', ReprName='PNG signature')
    

class PNG_chunk(Layer):
    constructorList = [
        Int(CallName='len', ReprName='Length', Type='uint32'),
        Str(CallName='type', ReprName='Chunk Type', Len=4),
        Str(CallName='data', ReprName='Chunk Data'),
        Int(CallName='crc', ReprName='CRC32 Checksum', Type='int32', Repr='hex'),
        ]
    
    def __init__(self, type='tEXt', data='' ):
        Layer.__init__(self, CallName='chk', ReprName='PNG chunk')
        self.type.Pt = type
        self.data.Pt = data
        self.data.Len = self.len
        self.data.LenFunc = lambda len: int(len)
        self.len.Pt = self.data
        self.len.PtFunc = lambda data: len(data)
        self.crc.Pt = self.data
        self.crc.PtFunc = lambda data: crc32(str(self.type)+str(data))
    

