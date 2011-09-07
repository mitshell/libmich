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
# * File Name : formats/SIGTRAN.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

#from struct import unpack
from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show
from libmich.core.IANA_dict import IANA_dict


test_val1 = '\x01\x00\x07\x01\x00\x00\x00\xd4\x00\x06\x00\x08\x00\x00\x00\x0c\x01\x15\x00\x08\x00\x00\x00\x01\x01\x02\x00\x18\x00\x02\x00\x00\x80\x02\x00\x08\x00\x00\x00\x01\x80\x03\x00\x08\x00\x00\x00\x01\x01\x16\x00\x08\x00\x00\x00\x01\x01\x01\x00\x08\x00\x00\x00\x01\x01\x13\x00\x08\x00\x00\x00\x01\x01\x14\x00\x08\x00\x00\x00\x01\x00\x13\x00\x08\x00\x00\x00\x01\x01\x17\x00\x08\x00\x00\x00\x0c\x01\x0b\x00rbjH\x04\x00\x00\x00\x10lb\xa1`\x02\x01\x01\x02\x01.0X\x84\x07\x91\x19\x89\x96\x90\x99I\x82\x07\x91\x19\x89\x96\x00\x003\x04D\x113\n\x81\x89\x96\x10\x83\x991\x00\xa7>\xe82\x9b\xfdf\x81\xe8\xe8\xf4\x1c\x94\x9e\x83\xd4\xf59\x1d\x14\x06\xb1\xdf\xeesY\x0e\xa2\x97\xe7t\xd0=MG\x83\xe2\xf54\xbd\x0c\n\x83\xcc\xe5;\xe8\xfe\x96\x93\xe7\xa0\xb4\x1b\x94\xa6\x03\x00\x00\x00\x00'
test_val2 = '\x01\x00\x01\x01\x00\x00\x00t\x02\x10\x00j\x00\x00\x01-\x00\x00\x016\x03\x02\x00\n\x01\x00\x005\x02\x02\x06\x04\xc36\x01\x8e\x0fK\x00\x13@G\x00\x00\x06\x00\x03@\x01\x00\x00\x0f@\x06\x00b\xf2W\x00\x01\x00:@\x08\x00b\xf2W\x00\x01\x00\x01\x00\x10@\x15\x14\x05\x08\x11b\xf2W\x00\x010\x05\xf4\x12\xf0\x00\x003\x030\x18!\x00O@\x035\x00\x00\x00V@\x05b\xf2W\x00\x01\x00\x00\x00'

# M2UA: http://tools.ietf.org/html//rfc3331
# M3UA: http://tools.ietf.org/html//rfc4666
# SUA: http://wiki.tools.ietf.org/html/rfc3868

# http://www.iana.org/assignments/sigtran-adapt
# (almost) automatic parsing and generation
# -> see michau.benoit.free.fr for the script
# Registry Name: Message Classes
Classes = IANA_dict({
    0 : ('Management Message', 'MGMT'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    1 : 'Transfer Messages', # [RFC4666]
    2 : ('SS7 Signalling Network Management Messages', 'SSNM'), # [RFC4666] [RFC3868]
    3 : ('ASP State Maintenance Messages', 'ASPSM'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    4 : ('ASP Traffic Maintenance Messages', 'ASPTM'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    5 : ('Q.921/Q.931 Boundary Primitives Transport Messages', 'QPTM'), # [RFC4233]
    6 : ('MTP2 User Adaptation Messages', 'MAUP'), # [RFC3331]
    7 : 'Connectionless Messages', # [RFC3868]
    8 : 'Connection-Oriented Messages', # [RFC3868]
    9 : ('Routing Key Management Messages', 'RKM'), # [RFC4666]
    10 : ('Interface Identifier Management Messages', 'IIM'), # [RFC3331]
    11 : 'M2PA Messages', # [RFC4165]
    12 : 'Security Messages', # [RFC3788]
    13 : 'DPNSS/DASS2 Boundary Primitives Transport Messages', # [RFC4129]
    14 : 'V5 Boundary Primitives Transport Messages', # [RFC3807]
    15 : 'Unassigned',
    128 : 'Reserved for IETF-Defined Message Class extensions',
})

# Registry Name: Message Types - Management (MGMT) Message (Value 0)
MGMT = IANA_dict({
    0 : ('Error', 'ERR'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    1 : ('Notify', 'NTFY'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    2 : 'TEI Status Request', # [RFC4233] [RFC3057]
    3 : 'TEI Status Confirm', # [RFC4233] [RFC3057]
    4 : 'TEI Status Indication', # [RFC4233] [RFC3057]
    5 : 'DLC Status Request', # [RFC4129]
    6 : 'DLC Status Confirm', # [RFC4129]
    7 : 'DLC Status Indication', # [RFC4129]
    8 : 'TEI Query Request', # [RFC5133] [RFC4233]
    9 : 'Unassigned',
    128 : 'Reserved for IETF-Defined MGMT extensions',
})

# Registry Name: Message Types - Transfer Messages (Value 1)
Transfer = IANA_dict({
    0 : 'Reserved', # [RFC4666]
    1 : ('Payload Data', 'DATA'), # [RFC4666]
    2 : 'Unassigned',
    128 : 'Reserved for IETF-Defined Transfer extensions',
})

# Registry Name: Message Types - SS7 Signalling Network Management (SSNM) Messages (Value 2)
SSNM = IANA_dict({
    0 : 'Reserved', # [RFC4666] [RFC3868]
    1 : ('Destination Unavailable', 'DUNA'), # [RFC4666] [RFC3868]
    2 : ('Destination Available', 'DAVA'), # [RFC4666] [RFC3868]
    3 : ('Destination State Audit', 'DAUD'), # [RFC4666] [RFC3868]
    4 : ('Signalling Congestion', 'SCON'), # [RFC4666] [RFC3868]
    5 : ('Destination User Part Unavailable', 'DPU'), # [RFC4666] [RFC3868]
    6 : ('Destination Restricted', 'DRST'), # [RFC4666] [RFC3868]
    7 : 'Reserved by the IETF',
    128 : 'Reserved for IETF-Defined SSNM extension',
})

# Registry Name: Message Types - ASP State Maintenance (ASPSM) Messages (Value 3)
ASPSM = IANA_dict({
    0 : 'Reserved', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    1 : ('ASP Up', 'UP'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    2 : ('ASP Down', 'DOWN'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    3 : ('Heartbeat', 'BEAT'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    4 : ('ASP Up Ack', 'UP ACK'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    5 : ('ASP Down Ack', 'DOWN ACK'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    6 : ('Heartbeat Ack', 'BEAT ACK'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    7 : 'Unassigned',
    128 : 'Reserved for IETF-Defined ASPSM extensions',
})

# Registry Name: Message Types - ASP Traffic Maintenance (ASPTM) Messages (Value 4)
ASPTM = IANA_dict({
    0 : 'Reserved', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    1 : ('ASP Active', 'ACTIVE'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    2 : ('ASP Inactive', 'INACTIVE'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    3 : ('ASP Active Ack', 'ACTIVE ACK'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    4 : ('ASP Inactive Ack', 'INACTIVE ACK'), # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3057]
    5 : 'Unassigned',
    128 : 'Reserved for IETF-Defined ASPTM extensions',
})

# Registry Name: Message Types - Q.921/Q.931 Boundary Primitives Transport (QPTM) Messages (Value 5)
QPTM = IANA_dict({
    0 : 'Reserved', # [RFC4233]
    1 : 'Data Request Message', # [RFC4233]
    2 : 'Data Indication Message', # [RFC4233]
    3 : 'Unit Data Request Message', # [RFC4233]
    4 : 'Unit Data Indication Message', # [RFC4233]
    5 : 'Establish Request', # [RFC4233]
    6 : 'Establish Confirm', # [RFC4233]
    7 : 'Establish Indication', # [RFC4233]
    8 : 'Release Request', # [RFC4233]
    9 : 'Release Confirm', # [RFC4233]
    10 : 'Release Indication', # [RFC4233]
    11 : 'Unassigned',
    128 : 'Reserved for IETF-Defined QPTM extensions',
})

# Registry Name: Message Types - MTP2 User Adaptation (MAUP) Messages (Value 6)
MAUP = IANA_dict({
    0 : 'Reserved', # [RFC3331]
    1 : 'Data', # [RFC3331]
    2 : 'Establish Request', # [RFC3331]
    3 : 'Establish Confirm', # [RFC3331]
    4 : 'Release Request', # [RFC3331]
    5 : 'Release Confirm', # [RFC3331]
    6 : 'Release Indication', # [RFC3331]
    7 : 'State Request', # [RFC3331]
    8 : 'State Confirm', # [RFC3331]
    9 : 'State Indication', # [RFC3331]
    10 : 'Data Retrieval Request', # [RFC3331]
    11 : 'Data Retrieval Confirm', # [RFC3331]
    12 : 'Data Retrieval Indication', # [RFC3331]
    13 : 'Data Retrieval Complete Indication', # [RFC3331]
    14 : 'Congestion Indication', # [RFC3331]
    15 : 'Data Acknowledge', # [RFC3331]
    16 : 'Unassigned',
    128 : 'Reserved for IETF-Defined MAUP extensions',
})

# Registry Name: Message Types - Connectionless Messages (Value 7)
ConLess = IANA_dict({
    0 : 'Reserved', # [RFC3868]
    1 : ('Connectionless Data Transfer', 'CLDT'), # [RFC3868]
    2 : ('Connectionless Data Response', 'CLDR'), # [RFC3868]
    3 : 'Unassigned',
    128 : 'Reserved for IETF-Defined Message Class Extensions',
})

# Registry Name: Message Types - Connection-Oriented Messages (Value 8)
ConOriented = IANA_dict({
    0 : 'Reserved', # [RFC3868]
    1 : ('Connection Request', 'CORE'), # [RFC3868]
    2 : ('Connection Acknowledge', 'COAK'), # [RFC3868]
    3 : ('Connection Refused', 'COREF'), # [RFC3868]
    4 : ('Release Request', 'RELRE'), # [RFC3868]
    5 : ('Release Complete', 'RELCO'), # [RFC3868]
    6 : ('Reset Confirm', 'RESCO'), # [RFC3868]
    7 : ('Reset Request', 'RESRE'), # [RFC3868]
    8 : ('Connection Oriented Data Transfer', 'CODT'), # [RFC3868]
    9 : ('Connection Oriented Data Acknowledge', 'CODA'), # [RFC3868]
    10 : ('Connection Oriented Error', 'COERR'), # [RFC3868]
    11 : ('Inactivity Test', 'COIT'), # [RFC3868]
    12 : 'Unassigned',
    128 : 'Reserved for IETF-Defined Message Class Extensions',
})

# Registry Name: Message Types - Routing Key Management (RKM) Messages (Value 9)
RKM = IANA_dict({
    0 : 'Reserved', # [RFC4666]
    1 : ('Registration Request', 'REG REQ'), # [RFC4666]
    2 : ('Registration Response', 'REG RSP'), # [RFC4666]
    3 : ('Deregistration Request', 'DEREG REQ'), # [RFC4666]
    4 : ('Deregistration Response', 'DEREG RSP'), # [RFC4666]
    5 : 'Unassigned',
    128 : 'Reserved for IETF-Defined RKM extensions',
})

# Registry Name: Message Types - Interface Identifier Management (IIM) Messages (Value 10)
IIM = IANA_dict({
    0 : 'Reserved',
    1 : ('Registration Request', 'REG REQ'),
    2 : ('Registration Response', 'REG RSP'),
    3 : ('Deregistration Request', 'DEREG REQ'),
    4 : ('Deregistration Response', 'DEREG RSP'),
    5 : 'Unassigned',
    128 : 'Reserved for IETF-Defined IIM extensions',
})

# Registry Name: Message Types - M2PA Messages (Value 11)
M2PA = IANA_dict({
    1 : 'User Data', # [RFC4165]
    2 : 'Link Status', # [RFC4165]
})

# Registry Name: Message Types - Security Messages (Value 12)
Security = IANA_dict({
    1 : 'STARTTLS message', # [RFC3788]
    2 : 'STARTTLS_ACK message', # [RFC3788]
})

# Registry Name: Message Types - DPNSS/DASS2 Boundary Primitives Transport Messages (Value 13)
DPNSSBound = IANA_dict({
    0 : 'Reserved', # [RFC4129]
    1 : 'Data Request Message', # [RFC4129]
    2 : 'Data Indication Message', # [RFC4129]
    3 : 'Unit Data Request Message', # [RFC4129]
    4 : 'Unit Data Indication Message', # [RFC4129]
    5 : 'Establish Request', # [RFC4129]
    6 : 'Establish Confirm', # [RFC4129]
    7 : 'Establish Indication', # [RFC4129]
    8 : 'Release Request', # [RFC4129]
    9 : 'Release Confirm', # [RFC4129]
    10 : 'Release Indication', # [RFC4129]
})

# Registry Name: Message Types - V5 Boundary Primitives Transport (V5PTM) Messages (Value 14)
V5Bound = IANA_dict({
    1 : 'Data Request Message',
    2 : 'Data Indication Message',
    3 : 'Unit Data Request Message',
    4 : 'Unit Data Indication Message',
    5 : 'Establish Request',
    6 : 'Establish Confirm',
    7 : 'Establish Indication',
    8 : 'Release Request',
    9 : 'Release Confirm',
    10 : 'Release Indication',
    11 : 'Link Status Start Reporting',
    12 : 'Link Status Stop Reporting',
    13 : 'Link Status Indication',
    14 : 'Sa-Bit Set Request',
    15 : 'Sa-Bit Set Confirm',
    16 : 'Sa-Bit Status Request',
    17 : 'Sa-Bit Status Indication',
    18 : 'Error Indication',
})

# Registry Name: Message Parameters
Params = IANA_dict({
    0 : 'Reserved', # [RFC4233] [RFC3868] [RFC3331]
    1 : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    2 : 'Reserved', # [RFC4233]
    3 : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    4 : 'Info String', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    5 : 'DLCI', # [RFC4233] [RFC4129]
    6 : 'Routing Context', # [RFC4666] [RFC3868]
    7 : 'Diagnostic Information', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    8 : 'Interface Identifier', # [RFC4233] [RFC3331] [RFC4129] [RFC3807]
    9 : 'Heartbeat Data', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    10 : 'Reason', # [RFC4129] [RFC3807]
    11 : 'Traffic Mode Type', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    12 : 'Error Code', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    13 : 'Status Type/Information', # [RFC4233] [RFC3331] [RFC4666] [RFC3868] [RFC4129] [RFC3807]
    14 : 'Protocol Data', # [RFC4233] [RFC4129] [RFC3807]
    15 : 'Release Reason', # [RFC4233] [RFC4129] [RFC3807]
    16 : 'Status', # [RFC4233] [RFC4129] [RFC3807]
    17 : 'ASP Identifier', # [RFC3331] [RFC4666] [RFC3868]
    18 : 'Affected Point Code', # [RFC4666] [RFC3868]
    19 : 'Correlation Id', # [RFC3331] [RFC4666] [RFC3868]
    20 : 'Registration Result', # [RFC3868]
    21 : 'Deregistration Result', # [RFC3868]
    22 : 'Registration Status', # [RFC3868]
    23 : 'Deregistration Status', # [RFC3868]
    24 : 'Local Routing Key Identifier', # [RFC3868]
    25 : 'Unassigned',
    129 : 'DLCI/EFA', # [RFC3807]
    130 : 'Link Status', # [RFC3807]
    131 : 'Bit ID/Bit Value', # [RFC3807]
    132 : 'Error Reason', # [RFC3807]
    133 : 'Unassigned',
    256 : 'Unassigned',
    257 : 'SS7 Hop Counter', # [RFC3868]
    258 : 'Source Address', # [RFC3868]
    259 : 'Destination Address', # [RFC3868]
    260 : 'Source Reference Number', # [RFC3868]
    261 : 'Destination Reference Number', # [RFC3868]
    262 : 'SCCP Cause', # [RFC3868]
    263 : 'Sequence Number', # [RFC3868]
    264 : 'Receive Sequence Number', # [RFC3868]
    265 : 'ASP Capabilities', # [RFC3868]
    266 : 'Credit', # [RFC3868]
    267 : 'Data', # [RFC3868]
    268 : 'Cause / User', # [RFC3868]
    269 : 'Network Appearance', # [RFC3868]
    270 : 'Routing Key', # [RFC3868]
    271 : 'DRN Label', # [RFC3868]
    272 : 'TID Label', # [RFC3868]
    273 : 'Address Range', # [RFC3868]
    274 : 'SMI', # [RFC3868]
    275 : 'Importance', # [RFC3868]
    276 : 'Message Priority', # [RFC3868]
    277 : 'Protocol Class', # [RFC3868]
    278 : 'Sequence Control', # [RFC3868]
    279 : 'Segmentation', # [RFC3868]
    280 : 'Congestion Level', # [RFC3868]
    281 : 'Unassigned',
    512 : 'Network Appearance', # [RFC4666]
    513 : 'Reserved', # [RFC4666]
    514 : 'Reserved', # [RFC4666]
    515 : 'Reserved', # [RFC4666]
    516 : 'User/Cause', # [RFC4666]
    517 : 'Congestion Indications', # [RFC4666]
    518 : 'Concerned Destination', # [RFC4666]
    519 : 'Routing Key', # [RFC4666]
    520 : 'Registration Result', # [RFC4666]
    521 : 'Deregistration Result', # [RFC4666]
    522 : 'Local_Routing Key Identifier', # [RFC4666]
    523 : 'Destination Point Code', # [RFC4666]
    524 : 'Service Indicators', # [RFC4666]
    525 : 'Reserved', # [RFC4666]
    526 : 'Originating Point Code List', # [RFC4666]
    527 : 'Circuit Range', # [RFC4666]
    528 : 'Protocol Data', # [RFC4666]
    529 : 'Reserved', # [RFC4666]
    530 : 'Registration Status', # [RFC4666]
    531 : 'Deregistration Status', # [RFC4666]
    532 : 'Unassigned',
    768 : 'Protocol Data 1', # [RFC3331]
    769 : ('Protocol Data 2', 'TTC'), # [RFC3331]
    770 : 'State Request', # [RFC3331]
    771 : 'State Event', # [RFC3331]
    772 : 'Congestion Status', # [RFC3331]
    773 : 'Discard Status', # [RFC3331]
    774 : 'Action', # [RFC3331]
    775 : 'Sequence Number', # [RFC3331]
    776 : 'Retrieval Result', # [RFC3331]
    777 : 'Link Key', # [RFC3331]
    778 : 'Local-LK-Identifier', # [RFC3331]
    779 : ('Signalling Data Terminal Identifier', 'SDT'), # [RFC3331]
    780 : ('Signalling Data Link Identifier', 'SDL'), # [RFC3331]
    781 : 'Registration Result', # [RFC3331]
    782 : 'Registration Status', # [RFC3331]
    783 : 'De-Registration Result', # [RFC3331]
    784 : 'De-Registration Status', # [RFC3331]
    785 : 'Unassigned',
    32769 : 'Global Title', # [RFC3868]
    32770 : 'Point Code', # [RFC3868]
    32771 : 'Subsystem Number', # [RFC3868]
    32772 : 'IPv4 Address', # [RFC3868]
    32773 : 'Hostname', # [RFC3868]
    32774 : 'IPv6 Addresses', # [RFC3868]
    32775 : 'Unassigned',
    65535 : 'Reserved', # [RFC4233]
})


# Generic block
class Sigtran(Block):
    
    def __init__(self, prot='SUA', cla=0, typ=1):
        Block.__init__(self, Name='Sigtran')
        self.append( Hdr(prot, cla, typ) )
    
    def parse(self, s=''):
        self[0].map(s)
        s = s[ len(self[0]) : ]
        # map iteratively TLV Information Elements
        while len(s) > 0:
            self.append( Param() )
            self[-1].hierarchy = self[0].hierarchy+1
            self[-1].map(s)
            s = s[ len(self[-1]) : ]


# Generic class
class Hdr(Layer):
    constructorList = [
        Int(CallName='ver', ReprName='Version', Pt=1, Type='uint8'),
        Int(CallName='spa', ReprName='Spare', Pt=0, Type='uint8'),
        Int(CallName='cla', ReprName='Message Class', Type='uint8',\
            Dict=Classes),
        Int(CallName='typ', ReprName='Message Type', Type='uint8'),
        Int(CallName='len', ReprName='Message Length', Pt='uint32'),
        ]
    
    type_dict = (MGMT, Transfer, SSNM, ASPSM, ASPTM, QPTM, MAUP,\
                 ConLess, ConOriented, RKM, IIM, M2PA, Security,\
                 DPNSSBound, V5Bound)
    
    def __init__(self, prot='SUA', cla=0, typ=0):
        if prot not in ('M2UA', 'M3UA', 'SUA'):
            prot='generic'
        Layer.__init__(self, CallName=prot, \
              ReprName='SIGTRAN %s header' % prot)
        self.cla.Pt = cla
        self.typ.Pt = typ
        self.typ.Dict = self.cla
        self.typ.DictFunc = lambda cla: self.type_dict[cla()]
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8
    

class Param(Layer):
    constructorList = [
        Int(CallName='T', ReprName='Tag', Type='uint16', Dict=Params),
        Int(CallName='L', ReprName='Length', Type='uint16'),
        Str(CallName='V', ReprName='Value'),
        Str(CallName='p', ReprName='Padding', Pt='', Len=0, Repr='hex'),
        ]
    
    padding_byte = '\0'
    
    def __init__(self, T=0, V=''):
        Layer.__init__(self, CallName='Param', \
              ReprName='SIGTRAN common parameter')
        self.T.Pt = T
        # Lots of values are encoded as integer 
        # corresponding with specific enum()
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)-4
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)+4
        self.p.Pt = self.V
        self.p.PtFunc = lambda V: self.__pad(V)
        self.p.Len = self.V
        self.p.LenFunc = lambda V: self.__pad_len(V)
    
    def __pad(self, V):
        return (4-len(V)%4)%4 * self.padding_byte
    
    def __pad_len(self, V):
        return (4-len(V)%4)%4
    
    

