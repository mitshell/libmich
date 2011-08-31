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
# * File Name : formats/GTP.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer
from libmich.core.IANA_dict import IANA_dict


# GTP version 1 is defined in TS 29.060 for CP
# and TS 29.281 for UP
ProtType = IANA_dict({
    0 : 'GTP prime',
    1 : 'GTP',
    })

MsgTypeV1 = IANA_dict({
    0 : "undefined",
    1 : "Echo Request",
    2 : "Echo Response",
    3 : "Version Not Supported",
    4 : "Node Alive Request",
    5 : "Node Alive Response",
    6 : "Redirection Request",
    7 : "Redirection Response",
    8 : "undefined",
    16 : "Create PDP Context Request",
    17 : "Create PDP Context Response",
    18 : "Update PDP Context Request",
    19 : "Update PDP Context Response",
    20 : "Delete PDP Context Request",
    21 : "Delete PDP Context Response",
    22 : "Initiate PDP Context Activation Request",
    23 : "Initiate PDP Context Activation Response",
    24 : "undefined",
    26 : "Error Indication",
    27 : "PDU Notification Request",
    28 : "PDU Notification Response",
    29 : "PDU Notification Reject Request",
    30 : "PDU Notification Reject Response",
    31 : "Supported Extension Headers Notification",
    32 : "Send Routeing Information for GPRS Request",
    33 : "Send Routeing Information for GPRS Response",
    34 : "Failure Report Request",
    35 : "Failure Report Response",
    36 : "Note MS GPRS Present Request",
    37 : "Note MS GPRS Present Response",
    38 : "undefined",
    48 : "Identification Request",
    49 : "Identification Response",
    50 : "SGSN Context Request",
    51 : "SGSN Context Response",
    52 : "SGSN Context Acknowledge",
    53 : "Forward Relocation Request",
    54 : "Forward Relocation Response",
    55 : "Forward Relocation Complete",
    56 : "Relocation Cancel Request",
    57 : "Relocation Cancel Response",
    58 : "Forward SRNS Context",
    59 : "Forward Relocation Complete Acknowledge",
    60 : "Forward SRNS Context Acknowledge",
    61 : "undefined",
    70 : "RAN Information Relay",
    71 : "undefined",
    96 : "MBMS Notification Request",
    97 : "MBMS Notification Response",
    98 : "MBMS Notification Reject Request",
    99 : "MBMS Notification Reject Response",
    100 : "Create MBMS Context Request",
    101 : "Create MBMS Context Response",
    102 : "Update MBMS Context Request",
    103 : "Update MBMS Context Response",
    104 : "Delete MBMS Context Request",
    105 : "Delete MBMS Context Response",
    106 : "undefined",
    112 : "MBMS Registration Request",
    113 : "MBMS Registration Response",
    114 : "MBMS De-Registration Request",
    115 : "MBMS De-Registration Response",
    116 : "MBMS Session Start Request",
    117 : "MBMS Session Start Response",
    118 : "MBMS Session Stop Request",
    119 : "MBMS Session Stop Response",
    120 : "MBMS Session Update Request",
    121 : "MBMS Session Update Response",
    122 : "undefined",
    128 : "MS Info Change Notification Request",
    129 : "MS Info Change Notification Response",
    130 : "undefined",
    240 : "Data Record Transfer Request",
    241 : "Data Record Transfer Response",
    242 : "undefined",
    255 : "G-PDU",
    })

ExtHdr = IANA_dict({
    0 : "No more",
    1 : "MBMS support",
    2 : "MS Info Change Reporting support",
    3 : "undefined",
    192 : "PDCP PDU number",
    193 : "Suspend Request",
    194 : "Suspend  Response",
    195 : "undefined",
    })


class GTPv1(Layer):
    constructorList = [
        Bit(CallName='vers', ReprName='version', Pt=1, BitLen=3, Repr='hum'),
        Bit(CallName='type', ReprName='protocol type', BitLen=1, \
            Repr='hum', Dict=ProtType),
        Bit(CallName='res', ReprName='reserved', Pt=0, BitLen=1),
        Bit(CallName='ext', ReprName='extension header flag', Pt=0, BitLen=1),
        Bit(CallName='seq', ReprName='sequence number flag', Pt=0, BitLen=1),
        Bit(CallName='pn', ReprName='N-PDU number flag', Pt=0, BitLen=1),
        Int(CallName='msg', ReprName='message type', Type='uint8', \
            Dict=MsgTypeV1),
        Int(CallName='len', ReprName='total length', Type='uint16'),
        Int(CallName='teid', ReprName='tunnel end-point id', \
            Pt=0, Type='uint32'),
        Int(CallName='seqn', ReprName='sequence number', Pt=0, Type='uint16'),
        Int(CallName='npdu', ReprName='N-PDU number', Pt=0, Type='uint8'),
        Int(CallName='nh', ReprName='next extension header', Pt=0, \
            Type='uint8', Dict=ExtHdr),
        ]
    
    def __init__(self, type=1, msg=1):
        Layer.__init__(self, CallName='gtpv1', ReprName='GPRS Tunneling Protocol v1')
        self.type.Pt = type
        self.msg.Pt = msg
        # handles length automatically
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: self._opt_len(pay())
        # handles optional field depending of the flag value
        self.nh.TransFunc = lambda ext: self._check_flag()
        self.seqn.TransFunc = lambda seq: self._check_flag()
        self.npdu.TransFunc = lambda pn: self._check_flag()
    
    def _opt_len(self, pay):
        l = 0
        if self.ext() or self.seq() or self.pn(): l+= 4
        return l + len(pay)
    
    def _check_flag(self):
        if self.ext() or self.seq() or self.pn(): return False
        else: return True

# GTPv1 extension header must be used as payload of the GTPv1 header
class GTPv1_ext(Layer):
    constructorList = [
        Int(CallName='len', ReprName='extension length', Type='uint8'),
        Str(CallName='cont', ReprName='extension content'),
        Int(CallName='nh', ReprName='next extension header', Pt=0, Type='uint8'),
        ]
    
    def __init__(self, data='\xFF\xFF'):
        Layer.__init__(CallName='gtpv1_ext', ReprName='GTPv1 extension header'),
        self.len.Pt = self.cont
        self.len.PtFunc = lambda cont: (len(cont)+2)//4
        self.cont.Pt = data
        self.cont.Len = self.len
        self.cont.LenFunc = lambda len: len()*4-2
    


# GTP version 2 (for LTE / EPC) is defined in TS 29.274 for CP
# GTP-U is still the same as in TS 29.281
MsgTypeV2 = IANA_dict({
    0 : 'Reserved',
    1 : 'Echo Request',
    2 : 'Echo Response',
    3 : 'Version Not Supported Indication',
    4 : 'Reserved for S101 interface',
    25 : 'Reserved for Sv interface',
    32 : 'Create Session Request',
    33 : 'Create Session Response',
    34 : 'Modify Bearer Request',
    35 : 'Modify Bearer Response',
    36 : 'Delete Session Request',
    37 : 'Delete Session Response',
    38 : 'Change Notification Request',
    39 : 'Change Notification Response',
    40 : 'FFU',
    64 : 'Modify Bearer Command ',
    65 : 'Modify Bearer Failure Indication ',
    66 : 'Delete Bearer Command ',
    67 : 'Delete Bearer Failure Indication',
    68 : 'Bearer Resource Command ',
    69 : 'Bearer Resource Failure Indication ',
    70 : 'Downlink Data Notification Failure Indication',
    71 : 'Trace Session Activation',
    72 : 'Trace Session Deactivation',
    73 : 'Stop Paging Indication',
    74 : 'FFU',
    95 : 'Create Bearer Request',
    96 : 'Create Bearer Response',
    97 : 'Update Bearer Request',
    98 : 'Update Bearer Response',
    99 : 'Delete Bearer Request',
    100 : 'Delete Bearer Response',
    101 : 'Delete PDN Connection Set Request',
    102 : 'Delete PDN Connection Set Response',
    103 : 'FFU',
    128 : 'Identification Request',
    129 : 'Identification Response',
    130 : 'Context Request',
    131 : 'Context Response',
    132 : 'Context Acknowledge',
    133 : 'Forward Relocation Request',
    134 : 'Forward Relocation Response',
    135 : 'Forward Relocation Complete Notification',
    136 : 'Forward Relocation Complete Acknowledge',
    137 : 'Forward Access Context Notification',
    138 : 'Forward Access Context Acknowledge',
    139 : 'Relocation Cancel Request',
    140 : 'Relocation Cancel Response',
    141 : 'Configuration Transfer Tunnel',
    142 : 'FFU',
    149 : 'Detach Notification',
    150 : 'Detach Acknowledge',
    151 : 'CS Paging Indication',
    152 : 'RAN Information Relay',
    153 : 'Alert MME Notification',
    154 : 'Alert MME Acknowledge',
    155 : 'UE Activity Notification',
    156 : 'UE Activity Acknowledge',
    157 : 'FFU',
    160 : 'Create Forwarding Tunnel Request',
    161 : 'Create Forwarding Tunnel Response',
    162 : 'Suspend Notification',
    163 : 'Suspend Acknowledge',
    164 : 'Resume Notification',
    165 : 'Resume Acknowledge',
    166 : 'Create Indirect Data Forwarding Tunnel Request',
    167 : 'Create Indirect Data Forwarding Tunnel Response',
    168 : 'Delete Indirect Data Forwarding Tunnel Request',
    169 : 'Delete Indirect Data Forwarding Tunnel Response',
    170 : 'Release Access Bearers Request',
    171 : 'Release Access Bearers Response',
    172 : 'FFU',
    176 : 'Downlink Data Notification',
    177 : 'Downlink Data Notification Acknowledge',
    178 : 'Reserved. Allocated in earlier version of the specification.',
    179 : 'PGW Restart Notification',
    180 : 'PGW Restart Notification Acknowledge',
    181 : 'FFU',
    200 : 'Update PDN Connection Set Request',
    201 : 'Update PDN Connection Set Response',
    202 : 'FFU',
    211 : 'Modify Access Bearers Request',
    212 : 'Modify Access Bearers Response',
    213 : 'FFU',
    231 : 'MBMS Session Start Request',
    232 : 'MBMS Session Start Response',
    233 : 'MBMS Session Update Request',
    234 : 'MBMS Session Update Response',
    235 : 'MBMS Session Stop Request',
    236 : 'MBMS Session Stop Response',
    237 : 'FFU',
    })


class GTPv2(Layer):
    constructorList = [
        Bit(CallName='ver', ReprName='version', Pt=2, BitLen=3, Repr='hum'),
        Bit(CallName='P', ReprName='piggybacking flag', Pt=0, BitLen=1, \
            Dict=ProtType),
        Bit(CallName='T', ReprName='TEID flag', Pt=0, BitLen=1),
        Bit(CallName='spa', ReprName='spare bits', Pt=0, BitLen=3),
        Int(CallName='msg', ReprName='message type', Pt=1, Type='uint8', \
            Dict=MsgTypeV2),
        Int(CallName='len', ReprName='message length', Type='uint16'),
        Int(CallName='teid', ReprName='tunnel end-point id', Type='uint32'),
        Int(CallName='seqn', ReprName='sequence number', Type='uint24'),
        Str(CallName='pad', ReprName='padding', Pt='\0', Len=1, Repr='hex'),
        ]
    padding_bytes = '\0'
    
    def __init__(self, msg=1, teid=None, seqn=0):
        Layer.__init__(self, CallName='gtpv2', ReprName='GPRS Tunneling Protocol v2')
        self.msg.Pt = msg
        self.seqn.Pt = seqn
        # handles length automatically
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: self._opt_len(pay())
        # handles TEID for msg other than ECHO REQ / RESP and VERS NOT SUPPORTED 
        if teid != None and isinstance(teid, int):
            self.T.Pt = 1
            self.teid.Pt = teid
        self.teid.Trans = self.T
        self.teid.TransFunc = lambda T: self._check_flag(T())
        # pad the header to have length multiple of 4 bytes
        # actually, current GTPv2 header does not require dynamic length padding
    
    def _check_flag(self, flag=0):
        if flag == 1: return False
        else: return True
    
    def _opt_len(self, pay):
        l = 2
        if self.T() == 1: l+= 4
        return l + len(pay)
    

