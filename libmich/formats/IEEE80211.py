# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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
# * File Name : formats/IEEE80211.py
# * Created : 2014-04-29
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show, debug, \
    log, ERR, WNG, DBG
from zlib import crc32
#
from binascii import unhexlify, hexlify


Type_dict = {
    0 : 'Management',
    1 : 'Control',
    2 : 'Data',
    3 : 'Reserved'
    }
SubtypeMgt_dict = {
    0 : 'Association request',
    1 : 'Association response',
    2 : 'Reassociation request',
    3 : 'Reassociation response',
    4 : 'Probe request',
    5 : 'Probe response',
    8 : 'Beacon',
    9 : 'ATIM',
    10 : 'Disassociation',
    11 : 'Authentication',
    12 : 'Deauthentication',
    13 : 'Action',
    }
SubtypeCtrl_dict = {
    8 : 'Block Ack Request',
    9 : 'Block Ack',
    10 : 'PS-Poll',
    11 : 'RTS',
    12 : 'CTS',
    13 : 'ACK',
    14 : 'CF-End',
    15 : 'CF-End + CF-Ack'
    }
SubtypeData_dict = {
    0 : 'Data',
    1 : 'Data + CF-Ack',
    2 : 'Data + CF-Poll',
    3 : 'Data + CF-Ack + CF-Poll',
    4 : 'Null',
    5 : 'CF-Ack',
    6 : 'CF-Poll',
    7 : 'CF-Ack + CF-Poll',
    8 : 'QoS Data',
    9 : 'QoS Data + CF-Ack',
    10 : 'QoS Data + CF-Poll',
    11 : 'QoS Data + CF-Ack + CF-Poll',
    12 : 'Qos Null',
    14 : 'QoS CF-Poll',
    15 : 'QoS CF-Ack + CF-Poll',
    }
PwrMgt_dict = {
    0 : 'Active mode',
    1 : 'PS mode',
    }
class FrameCtrl(Layer):
    constructorList = [
        Bit('ProtVers', Pt=0, BitLen=2, Repr='hum'),
        Bit('Type', Pt=0, BitLen=2, Repr='hum', Dict=Type_dict),
        Bit('Subtype', Pt=0, BitLen=4, Repr='hum'),
        Bit('ToDS', Pt=0, BitLen=1, Repr='hum'),
        Bit('FromDS', Pt=0, BitLen=1, Repr='hum'),
        Bit('MoreFrag', Pt=0, BitLen=1, Repr='hum'),
        Bit('Retry', Pt=0, BitLen=1, Repr='hum'),
        Bit('PwrMgt', Pt=0, BitLen=1, Repr='hum', Dict=PwrMgt_dict),
        Bit('MoreData', Pt=0, BitLen=1, Repr='hum'),
        Bit('ProtFrame', Pt=0, BitLen=1, Repr='hum'),
        Bit('Order', Pt=0, BitLen=1, Repr='hum')
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Subtype.Dict = self.Type
        self.Subtype.DictFunc = self._get_subtype
    
    def _get_subtype(self, Type):
        t = Type()
        if t == 0: return SubtypeMgt_dict
        elif t == 1: return SubtypeCtrl_dict
        elif t == 3: return SubtypeData_dict
        else: return {}


class MAC(Layer):
    constructorList = [
        FrameCtrl(),
        Int('Duration', Pt=0, Type='uint16'),
        Str('Addr1', Pt=6*'\0', Len=6, Repr='hex'),
        Str('Addr2', Pt=6*'\0', Len=6, Repr='hex'),
        Str('Addr3', Pt=6*'\0', Len=6, Repr='hex'),
        Bit('FragNum', Pt=0, BitLen=4, Repr='hum'), # sequence ctrl
        Bit('SeqNum', Pt=0, BitLen=12, Repr='hum'), # sequence ctrl 
        Str('Addr4', Pt=6*'\0', Len=6, Repr='hex'),
        Int('QoSCtrl', Pt=0, Type='uint16'),
        Str('Body', Pt=''),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]
    '''
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # sequence ctrl not present for control frames
        self.FragNum.TransFunc = lambda x: True if self.FrameCtrl.Type()==1 else False
        self.SeqNum.TransFunc = lambda x: True if self.FrameCtrl.Type()==1 else False
        # QoSCtrl present in data frames with QoS subfield
        self.QoSCtrl.TransFunc = lambda x: False if \
            (self.FrameCtrl.Type()==2 and self.FrameCtrl.Subtype()&8==1) else True
        #
    '''

class MAC_RTS(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=11),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Str('TA', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_CTS(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=12),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_ACK(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=13),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]
 
class MAC_PSPoll(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=10),
        Int('AID', Pt=0, Type='uint16'),
        Str('BSSID', Pt=6*'\0', Len=6, Repr='hex'),
        Str('TA', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_CFEnd(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=14),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Str('BSSID', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_CFEndCFAck(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=15),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Str('BSSID', Pt=6*'\0', Len=6, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_BlockAckReq(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=8),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Str('TA', Pt=6*'\0', Len=6, Repr='hex'),
        Bit('Reserved', Pt=0, BitLen=12),
        Bit('TID', Pt=0, BitLen=4),
        Bit('FragNum', Pt=0, BitLen=4),
        Bit('StartSeqNum', Pt=0, BitLen=12),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_BlockAck(MAC):
    constructorList = [
        FrameCtrl(Type=1, Subtype=9),
        Int('Duration', Pt=0, Type='uint16'),
        Str('RA', Pt=6*'\0', Len=6, Repr='hex'),
        Str('TA', Pt=6*'\0', Len=6, Repr='hex'),
        Bit('Reserved', Pt=0, BitLen=12),
        Bit('TID', Pt=0, BitLen=4),
        Bit('FragNum', Pt=0, BitLen=4),
        Bit('StartSeqNum', Pt=0, BitLen=12),
        Str('BlockAckBitmap', Pt=128*'\0', Len=128, Repr='hex'),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]

class MAC_DATA(MAC):
    def __init__(self, **kwargs):
        MAC.__init__(self, **kwargs)
        self.FrameCtrl.Type > 0
        self.Addr4.TransFunc = lambda x: True if (not self.FrameCtrl.ToDS() \
            or not self.FrameCtrl.FromDS()) else False

class MAC_MGT(MAC):
    constructorList = [
        FrameCtrl(Type=2),
        Int('Duration', Pt=0, Type='uint16'),
        Str('Addr1', Pt=6*'\0', Len=6, Repr='hex'),
        Str('Addr2', Pt=6*'\0', Len=6, Repr='hex'),
        Str('Addr3', Pt=6*'\0', Len=6, Repr='hex'),
        Bit('FragNum', Pt=0, BitLen=4, Repr='hum'), # sequence ctrl
        Bit('SeqNum', Pt=0, BitLen=12, Repr='hum'), # sequence ctrl
        Str('Body', Pt=''),
        Int('FCS', Pt=0, Type='uint32', Repr='hex')
        ]
    def __init__(self, **kwargs):
        MAC.__init__(self, **kwargs)
        
#

