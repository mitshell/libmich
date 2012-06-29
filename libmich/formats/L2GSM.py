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
# * File Name : formats/L2GSM.py
# * Created : 2012-06-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#
#!/usr/bin/env python
#
from libmich.core.element import Element, Str, Int, Bit, Layer, \
    RawLayer, Block, show, log, ERR, WNG, DBG

# GSM link frame format, as described in TS 44.006
# 44006, section 6.2 & 6.3, address field
LAPLPD_dict = {
    0 : 'GSM',
    1 : 'SMSCB',
    }
SAPI_dict = {
    0 : 'CC/MM/RR',
    3 : 'SMS',
    }
LAPEA_dict = {
    0 : 'extended address field',
    1 : 'final octet',
    }
# LPD: should always be 0
# CR: when sending a Command CR = 0 when sent by the MS, = 1 when sent by the net
# when sending a Response: CR is the opposite
class LAPDm_addr(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('LPD', ReprName='Link Protocol Discriminator', Pt=0, BitLen=2, \
            Repr='hum', Dict=LAPLPD_dict),
        Bit('SAPI', ReprName='Service Access Point Identifier', Pt=0, \
            BitLen=3, Repr='hum', Dict=SAPI_dict),
        Bit('CR', ReprName='Command Response bit', Pt=0, Repr='hum'),
        Bit('EA', ReprName='Extended Address bit', Pt=1, Repr='hum', \
            Dict=LAPEA_dict)
        ]

# 44006, section 6.4
LAPFmtExt_dict = {
    0 : 'Supervisory',
    1 : 'Unnumbered',
    }
LAPFmt_dict = {
    0 : 'Information',
    1 : 'see fmt_ext',
    }
class LAPDm_ctrl(Layer):
    # byte unalignment is needed to compute correctly
    # transparency bit per bit
    _byte_aligned = False
    # msb_data can be: recv() seq number
    # lsb_data can be: send() seq number
    constructorList = [
        Bit('msb_data', Pt=0, BitLen=3, Repr='hum'),
        Bit('PF', ReprName='Poll / Final bit', Pt=0, BitLen=1, Repr='hum'),
        Bit('lsb_data', Pt=0, Repr='hum'),
        Bit('fmt_ext', Pt=1, Repr='hum', Dict=LAPFmtExt_dict),
        Bit('fmt', Pt=1, Repr='hum', Dict=LAPFmt_dict)
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # fmt, fmt_ext and lsb_data: length automation
        self.fmt_ext.Trans = self.fmt
        self.fmt_ext.TransFunc = lambda f: False if f() else True
        self.lsb_data.BitLen = self.fmt
        self.lsb_data.BitLenFunc = lambda f: 2 if f() else 3
    # this map() is needed, cause lsb_data and fmt_ext
    # depends on fmt, which comes after them...
    def map(self, string=''):
        if len(string) > 0:
            self.fmt < ord(string[0])&0b1
        Layer.map(self, string)

# 44006, section 6.6, length field
# LengthRR is kept for backward compatibility
# (was provided in L3GSM_RR initially)
# LAPDm_len is just a "name wrapper" for it
class LengthRR(Layer):
    constructorList = [
        Bit('len', ReprName='L2 pseudo length', Pt=0, BitLen=6, Repr='hum'),
        Bit('M', ReprName='More data bit', Pt=0, BitLen=1),
        Bit('EL', ReprName='Length field not extended', Pt=1, BitLen=1)]
class LAPDm_len(LengthRR):
    pass
    # len should give the length of the payload

# a complete LAPDm header
class LAPDm(Layer):
    # byte unalignment: see LAPDm_ctrl
    _byte_aligned = False
    constructorList = [e for e in LAPDm_addr()] + \
                      [e for e in LAPDm_ctrl()] + \
                      [e for e in LAPDm_len()]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # fmt, fmt_ext and lsb_data: length automation
        self.fmt_ext.Trans = self.fmt
        self.fmt_ext.TransFunc = lambda f: False if f() else True
        self.lsb_data.BitLen = self.fmt
        self.lsb_data.BitLenFunc = lambda f: 2 if f() else 3
    # see LAPDm_ctrl for why we have a specific map()
    def map(self, string=''):
        if len(string) > 1:
            self.fmt < ord(string[1])&0b1
        Layer.map(self, string)
