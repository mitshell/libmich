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
# * File Name : formats/RTP.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show, debug

class RTP(Layer):
    constructorList = [
        Bit('ver', Pt=2,BitLen=2, Repr='hum'),
        Bit('pad', Pt=0, BitLen=1),
        Bit('ext', Pt=0, BitLen=1),
        Bit('src', ReprName='Contributing source identifiers', Pt=0, \
            BitLen=4, Repr='hum'),
        Bit('mark', Pt=0, BitLen=1),
        Bit('type', Pt=0, BitLen=7, Repr='hum'),
        Int('seqn', Pt=0, Type='uint16'), # need a dict
        Int('time', Pt=0, Type='uint32'),
        Str('synch_src', Pt='\0\0\0\0', Len=4, Repr='hex')]
        
# RFC 4867: RTP for AMR and AMR-WB
# timestamp unit is in sample
# AMR freq = 8 KHz (160 samples / frame / chan)
# (-> each RTP packet: timestamp += 160)
# AMR-WB freq = 16 KHz (320 samples / frame / chan)
# 1 frame block = 20ms

# TS 26.101
codecs_dict = {
0 : 'AMR 4,75 kbit/s',
1 : 'AMR 5,15 kbit/s',
2 : 'AMR 5,90 kbit/s',
3 : 'AMR 6,70 kbit/s (PDC-EFR)',
4 : 'AMR 7,40 kbit/s (TDMA-EFR)',
5 : 'AMR 7,95 kbit/s',
6 : 'AMR 10,2 kbit/s',
7 : 'AMR 12,2 kbit/s (GSM-EFR)',
8 : 'AMR SID',
9 : 'GSM-EFR SID',
10 : 'TDMA-EFR SID',
11 : 'PDC-EFR SID',
15 : 'No Data',
}

# AMR bandwidth-efficient mode
# payload is constitued of:
#   - 1 CMR header
#   - several ToC (1 ToC per channel * 20ms frames in the packet)
#   - channel.frame data: can be byte-misaligned
#   - padding (\0) to align the payload on byte
#
class AMReff(Layer):
    constructorList = [
        Bit('CMR', ReprName='Codec Mode Request', Pt=0, BitLen=4, \
            Dict=codecs_dict, Repr='hum')]
    
    def add_ToC(self, ToC):
        if isinstance(ToC, ToCeff):
            self.extend(ToCeff)

class ToCeff(Layer):
    constructorList = [
        Bit('F', ReprName='Frame following', Pt=0, BitLen=1),
        Bit('FT', ReprName='Frame Type index', Pt=0, BitLen=4, \
            Dict=codecs_dict, Repr='hum'),
        Bit('Q', ReprName='Frame Quality indicator', Pt=1, BitLen=1)]
#

# AMR byte-aligned (ouf...)
# CMR | res: fixed header (8 bits)
# Interleaving info (8 bits): optional, signalled out-of-band
#
class AMRalign(Layer):
    constructorList = [
        Bit('CMR', ReprName='Codec Mode Request', Pt=0, BitLen=4, \
            Dict=codecs_dict, Repr='hum'),
        Bit('res', Pt=0, BitLen=4),
        Bit('ILL', ReprName='Interleaving length', BitLen=4, Trans=True),
        Bit('ILP', ReprName='Interleaving index', BitLen=4, Trans=True)]

class ToC(Layer):
    constructorList = [
        Bit('F', ReprName='Frame following', Pt=0, BitLen=1),
        Bit('FT', ReprName='Frame Type index', Pt=0, BitLen=4, \
            Dict=codecs_dict, Repr='hum'),
        Bit('Q', ReprName='Frame Quality indicator', Pt=1, BitLen=1),
        Bit('P', ReprName='Padding', Pt=0, BitLen=2)]


