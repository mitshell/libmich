# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau. ANSSI.
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
# * File Name : formats/IEEE802154.py
# * Created : 2012-01-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python


# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show, debug, \
    log, ERR, WNG, DBG
from libmich.utils.CRC16 import CRC16
from binascii import unhexlify, hexlify

def unh(buf):
    return unhexlify(buf.replace('\n', '').replace(' ', ''))

###
#
# IEEE 802.15.4 PHY and MAC format
# PHY is the one at 2.4 GHz
#
# These are from IEEE 802.15.4 spec
Bool_dict = {0:'False', 1:'True'}
Type_dict = {0:'Beacon', 1:'Data', 2:'Ack', 3:'MAC command'}
Addr_dict = {0:'Not present', 1:'Reserved', \
             2:'16-bit address', 3:'64-bit address'}
Addr_len = {0:0, 1:0, 2:2, 3:8}
#
class IEEE802154(Block):
    # debugging level:
    dbg=1
    # global format parameters
    PHY_INCL = False
    FCS_INCL = False
    
    def __init__(self):
        Block.__init__(self, Name='IEEE 802.15.4')
        self.append(PHY())
    
    def parse(self, s='', phy_included=True, fcs_included=True):
        #
        if self.PHY_INCL:
            # insert PHY() preamble and map the buffer to it
            if len(self.layerList) > 0 :
                self.layerList = []
                self << PHY()
            self[0].map(s)
            #
            # verify preamble
            if self[0].Preamble() != '\0\0\0\0' and self.dbg >= ERR:    
                log(ERR, 'bad 802.15.4 preamble in PHY')
            if len(s) != self.PHY.Length()+6 and self.dbg >= ERR:
                log(ERR, 'buffer longer than indicated in PHY header')
            # truncate string buffer
            s=s[6:6+self.PHY.Length()]
        else:
            if len(self.layerList) > 0:
                self.layerList = []
        #
        # standard 802.15.4 MAC header
        # insert MAC and map the buffer to it
        self << MAC()
        self[-1].map(s)
        s = s[len(self[-1]):]
        # insert DATA layer
        if len(s) > 2:
            self << Data()
            if self.FCS_INCL: self[-1].map(s[:-2])
            else: self[-1].map(s)
        # insert error detection code (CRC)
        if self.FCS_INCL:
            self >> FCS()
            self[-1].map(s[-2:])
            #
            # verify CRC
            crc = self.FCS.FCS()
            self.FCS.FCS < None
            if self.FCS.FCS() != crc and self.dbg >= ERR:
                log(ERR, 'bad 802.15.4 CRC16 in MAC suffix')
            # refill with the original value
            self.FCS.FCS < crc

class PHY(Layer):
    constructorList = [
        Str('Preamble', Pt='\0\0\0\0', Len=4, Repr='hex'),
        Str('SFD', Pt='\xA7', Len=1, Repr='hex'),
        Bit('Res', Pt=0, BitLen=1),
        Bit('Length', BitLen=7, Repr='hum')]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.get_payload
        self.Length.PtFunc = lambda pay: len(pay())

# class Str() with LE representation
class StrLE(Str):
    def __repr__(self):
        # for hex representation, revert byte
        # 802.15.4 addresses are actually little endian integers
        if self.Repr == "hex": 
            h = hex(self)
            return '0x%s' % h[-2:] + \
                   ''.join([h[-i-2:-i] for i in range(2, len(h), 2)])
        else:
            return Str.__repr__(self)
    
class MAC(Layer):
    constructorList = [
        # frame ctrl, 1st byte, LE
        Bit('Res', Pt=0, BitLen=1),
        Bit('IntraPAN', Pt=0, BitLen=1, Repr='hum', Dict=Bool_dict),
        Bit('AckReq', Pt=0, BitLen=1, Repr='hum', Dict=Bool_dict),
        Bit('FramePending', Pt=0, BitLen=1, Repr='hum', Dict=Bool_dict),
        Bit('Security', Pt=0, BitLen=1, Repr='hum', Dict=Bool_dict),
        Bit('Type', Pt=0, BitLen=3, Repr='hum', Dict=Type_dict),
        # frame ctrl, 2nd byte, LE
        Bit('SrcAddrMode', Pt=0, BitLen=2, Repr='hum', Dict=Addr_dict),
        Bit('FrameVers', Pt=0, BitLen=2),
        Bit('DstAddrMode', Pt=0, BitLen=2, Repr='hum', Dict=Addr_dict),
        Bit('Res', Pt=0, BitLen=2),
        # addressing fields
        Int('SeqNum', Pt=0, Type='uint8', Repr='hum'),
        StrLE('DstPANID', Len=2, Repr='hex'),
        StrLE('DstAddr', Len=8, Repr='hex'),
        StrLE('SrcPANID', Len=2, Repr='hex'),
        StrLE('SrcAddr', Len=8, Repr='hex'),
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # if IntraPAN=1 and Src&Dst addr present, only dst PANID
        # if Src||DstAddrMode=0, no field
        # = 2, short addr
        # = 3, full 8 bytes long addr
        self.DstPANID.Len = self.DstAddrMode
        self.DstPANID.LenFunc = lambda mode: 2 if mode()!=0 else 0 
        self.DstAddr.Len = self.DstAddrMode
        self.DstAddr.LenFunc = lambda mode: Addr_len[mode()]
        self.SrcPANID.Len = self.SrcAddrMode
        self.SrcPANID.LenFunc = \
            lambda mode: 2 if mode()!=0 and self.IntraPAN()==0 else 0
        self.SrcAddr.Len = self.SrcAddrMode
        self.SrcAddr.LenFunc = lambda mode: Addr_len[mode()]
    
    def __mac_len(self, hdr):
        if hasattr(hdr, 'Length'):
            return max(0, hdr.Length()-\
                            (5+len(self.DstPANID)+len(self.DstAddr)+\
                            len(self.SrcPANID)+len(self.SrcAddr)))
        return None

class Data(Layer):
    constructorList = [
        Str('RawData', Pt='', Repr='hex')
        ]

class FCS(Layer):
    constructorList = [
        Str('FCS', Len=2, Repr='hex')
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # CRC is computed over the whole MAC + Data
        self.FCS.Pt = 0
        self.FCS.PtFunc = self.__crc
    
    def __crc(self, _unused):
        if hasattr(self, 'Block'):
            if isinstance(self.Block, PHY):
                start=1
            else:
                start=0
            buf = ''.join([str(l) for l in self.Block[start:-1]])
            cs = CRC16(buf).checksum()
            return ''.join((cs[1], cs[0]))
        else:
            return '\0\0'

###
# Texas Instrument PSD format
# Used (AFAIK) by the CC25XY (e.g. CC2531) product line
# explained in the product documentation from TI: 
# SmartRF Packet Sniffer User Manual (section 5), freely available
#
# 802.15.4 MAC and data are in .Data() Str element
# PHY is not present, FCS is also not present (in general)
# buf the boolean FCS indicates FCS verification done by the dongle
#
class TI_PSD(Layer):
    constructorList = [
        Bit('unused', Pt=0, BitLen=5, Repr='bin'),
        Bit('Incomp', ReprName='Incomplete packet', Pt=0, BitLen=1, \
            Repr='hum', Dict=Bool_dict),
        Bit('Corrinc', ReprName='Correlation used', Pt=0, BitLen=1, \
            Repr='hum', Dict=Bool_dict),
        Bit('FCSinc', ReprName='FCS included', Pt=0, BitLen=1, \
            Repr='hum', Dict=Bool_dict),
        Int('Pnbr', ReprName='Packet number', Pt=0, Type='uint32'),
        Int('Ts', ReprName='Timestamp', Pt=0, Type='uint64'),
        Int('Length', Pt=0, Type='uint8'),
        Str('Data', Pt='', Repr='hex'),
        Int('RSSI', Pt=0, Type='int8'),
        Bit('FCS', ReprName='FCS OK', Pt=0, BitLen=1, Repr='hum', \
            Dict=Bool_dict),
        Bit('Corr', ReprName='Correlation value', Pt=0, BitLen=7, \
            Repr='hum', Trans=True),
        Bit('LQI', Pt=0, BitLen=7, Repr='hum')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Pnbr._endian = 'little'
        self.Ts._endian = 'little'
        # Raw data length automation
        self.Data.Len = self.Length
        self.Data.LenFunc = lambda l: l()-2 if self.FCSinc() else l()
        # Corr / LQI selection
        self.Corr.Trans = self.Corrinc
        self.Corr.TransFunc = lambda c: False if c() else True
        self.LQI.Trans = self.Corrinc
        self.LQI.TransFunc = lambda c: True if c() else False