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
# * File Name : formats/PPP.py
# * Created : 2012-11-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer, show, debug
from libmich.core.IANA_dict import IANA_dict

###
# this is from RFC 1331 and 1332 on PPP
###

# RFC 1331

LCPCode_dict = IANA_dict({
    1 : 'Configure-Request',
    2 : 'Configure-Ack',
    3 : 'Configure-Nak',
    4 : 'Configure-Reject',
    5 : 'Terminate-Request',
    6 : 'Terminate-Ack',
    7 : 'Code-Reject',
    8 : 'Protocol-Reject',
    9 : 'Echo-Request',
    10 : 'Echo-Reply',
    11 : 'Discard-Request',
    12 : 'RESERVED',
    })

class LCP(Layer):
    constructorList = [
        Int('Code', Pt=0, Type='uint8', Dict=LCPCode_dict),
        Int('Identifier', Pt=0, Type='uint8'),
        Int('Length', Type='uint16'),
        Str('Data', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Data
        self.Length.PtFunc = lambda d: len(d)+4
        self.Data.Len = self.Length
        self.Data.LenFunc = lambda l: l()-4

LCPType_dict = IANA_dict({
    1 : 'Maximum-Receive-Unit',
    2 : 'Async-Control-Character-Map',
    3 : 'Authentication-Protocol',
    4 : 'Quality-Protocol',
    5 : 'Magic-Number',
    6 : 'RESERVED',
    7 : 'Protocol-Field-Compression',
    8 : 'Address-and-Control-Field-Compression',
    })

class LCPopt(Layer):
    constructorList = [
        Int('Type', Pt=0, Type='uint8', Dict=LCPType_dict),
        Int('Length', Type='uint8'),
        Str('Data', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Data
        self.Length.PtFunc = lambda d: len(d)+2
        self.Data.Len = self.Length
        self.Data.LenFunc = lambda l: l()-2

#
# RFC 1332

NCPCode_dict = IANA_dict({
    1 : 'Configure-Request',
    2 : 'Configure-Ack',
    3 : 'Configure-Nak',
    4 : 'Configure-Reject',
    5 : 'Terminate-Request',
    6 : 'Terminate-Ack',
    7 : 'Code-Reject',
    })

class NCP(Layer):
    constructorList = [
        Int('Code', Pt=0, Type='uint8', Dict=LCPCode_dict),
        Int('Identifier', Pt=0, Type='uint8'),
        Int('Length', Type='uint16'),
        Str('Data', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Data
        self.Length.PtFunc = lambda d: len(d)+4
        self.Data.Len = self.Length
        self.Data.LenFunc = lambda l: l()-4

IPCPType_dict = IANA_dict({
    1 : 'IP-Addresses',
    2 : 'IP-Compression-Protocol',
    3 : 'IP-Address',
    4 : 'Mobile-IPv4',
    5 : 'unassigned',
    129 : 'Primary DNS Server Address',
    130 : 'Primary NBNS Server Address',
    131 : 'Secondary DNS Server Address',
    132 : 'Secondary NBNS Server Address',
    })

class IPCP(Layer):
    constructorList = [
        Int('Type', Pt=0, Type='uint8', Dict=IPCPType_dict),
        Int('Length', Type='uint8'),
        Str('Data', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Length.Pt = self.Data
        self.Length.PtFunc = lambda d: len(d)+2
        self.Data.Len = self.Length
        self.Data.LenFunc = lambda l: l()-2
#