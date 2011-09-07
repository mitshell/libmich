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
# * File Name : formats/L3Mobile.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import RawLayer, Block, show, debug
from libmich.formats.L3Mobile_MM import *
from libmich.formats.L3Mobile_CC import *
from libmich.formats.L3GSM_RR import *
from libmich.formats.L3Mobile_24007 import PD_dict

# Handles commonly all defined L3Mobile_XYZ stacks

L3Call = {
# L3Mobile_CC, PD=3
3:{
1:ALERTING,
2:CALL_PROCEEDING,
3:PROGRESS,
4:CC_ESTABLISHMENT,
5:SETUP,
6:CC_ESTABLISHMENT_CONFIRMED,
7:CONNECT,
8:CALL_CONFIRMED,
9:START_CC,
11:RECALL,
14:EMERGENCY_SETUP,
15:CONNECT_ACKNOWLEDGE,
16:USER_INFORMATION,
19:MODIFY_REJECT,
23:MODIFY,
24:HOLD,
25:HOLD_ACKNOWLEDGE,
26:HOLD_REJECT,
28:RETRIEVE,
29:RETRIEVE_ACKNOWLEDGE,
30:RETRIEVE_REJECT,
31:MODIFY_COMPLETE,
37:DISCONNECT,
42:RELEASE_COMPLETE,
45:RELEASE,
49:STOP_DTMF,
50:STOP_DTMF_ACKNOWLEDGE,
52:STATUS_ENQUIRY,
53:START_DTMF,
54:START_DTMF_ACKNOWLEDGE,
55:START_DTMF_REJECT,
57:CONGESTION_CONTROL,
58:FACILITY,
61:STATUS,
62:NOTIFY,
0x100:Header,},
# L3Mobile_MM, PD=5
5:{
1:IMSI_DETACH_INDICATION,
2:LOCATION_UPDATING_ACCEPT,
4:LOCATION_UPDATING_REJECT,
8:LOCATION_UPDATING_REQUEST,
17:AUTHENTICATION_REJECT,
18:AUTHENTICATION_REQUEST,
20:AUTHENTICATION_RESPONSE,
24:IDENTITY_REQUEST,
25:IDENTITY_RESPONSE,
26:TMSI_REALLOCATION_COMMAND,
27:TMSI_REALLOCATION_COMPLETE,
28:AUTHENTICATION_FAILURE,
33:CM_SERVICE_ACCEPT,
34:CM_SERVICE_REJECT,
35:CM_SERVICE_ABORT,
36:CM_SERVICE_REQUEST,
37:CM_SERVICE_PROMPT,
40:CM_REESTABLISHMENT_REQUEST,
41:ABORT,
48:MM_NULL,
49:MM_STATUS,
50:MM_INFORMATION,
0x100:Header,},
# L3GSM_RR, PD=6
6:{
13:CHANNEL_RELEASE,
41:ASSIGNMENT_COMPLETE,
46:ASSIGNMENT_COMMAND,
47:ASSIGNMENT_FAILURE,},
# Nothing more yet...
}

# Define a dummy RAW L3 header / message for parts not implemented
class RawL3(Layer3):
    constructorList = [
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Pt=0, Type='uint8'),
        Str('Msg', Pt='', Repr='hex')]
#

def parse_L3(buf):
    # select message from PD and Type
    if len(buf) < 2:
        print('[ERR] Message too short for L3 mobile')
        return RawLayer(buf)
    # protocol is 4 last bits of 1st byte
    # type is 6 last bits of 2nd byte
    Prot, Type = ord(buf[0])&0x0F, ord(buf[1])&0x3F
    # get the right protocol from PD
    if Prot not in L3Call.keys():
        if Prot not in PD_dict.keys():
            print('[ERR] non-standard L3 protocol discriminator: PD=%i' % Prot)
        else:
            print('[WNG] L3 protocol %s not implemented (yet)' % PD_dict[Prot])
        ret = rawL3()
        ret.map(buf)
        return ret
    # get the right type from Type
    if Type not in L3Call[Prot].keys():
        print('[ERR] L3 message type %i non-standard or not implemented for %s' \
              % (Type, PD_dict[Prot]))
        ret = rawL3()
        # for L3GSM_RR, still use the msg type dict
        if Prot == 6:
            ret.Type.Dict = GSM_RR_dict
        ret.map(buf)
        return ret
    l3 = L3Call[Prot][Type]()
    l3.map(buf)
    return l3

    
#
# OpenBTS typical sequence:
bts = \
['\x05$\x11\x033Y\x90\x05\xf4T\x01\x98\xcb',
 '\x05\x18\x01',
 '\x05Y\x08)\x80\x10\x13\x10w6R',
 '\x05!',
 '\x03\x05\x04\x06`\x04\x02\x00\x05\x81^\x08\x81\x00\x12cy65\x16',
 '\x83\x02',
 '\x06.\n@3\x00c\x01',
 '\x06)\x00',
 '\x83%\x02\xe1\xff',
 '\x83*',
 '\x06\r\x00',
 '\x03m\x08\x02\xe0\x90',
 '\x05$\x11\x033Y\x90\x05\xf4T\x01\x98\xcb',
 '\x05\x18\x01',
 '\x05Y\x08)\x80\x10\x13\x10w6R',
 '\x05!',
 '\x03\x05\x04\x06`\x04\x02\x00\x05\x81^\x03\x81\x120',
 '\x83\x02',
 '\x06.\n@3\x00c\x01',
 '\x06)\x00',
 '\x83\x03\x02\xe1\x80',
 '\x83\x01',
 '\x83\x07',
 '\x03O',
 '\x03%\x02\xe0\x90',
 '\x83-',
 '\x03j\x08\x02\xe0\x90',
 '\x06\r\x00',
 '\x83%\x02\xe1\x90',
 '\x83*',
 '\x06\r\x00',
 '\x06\r\x01',
 '\x05\x08\x11\x00\xf2 \x03\xe83\x05\xf4T\x01\x98\xcb',
 '\x05\x18\x01',
 '\x05Y\x08)\x80\x10\x13\x10w6R',
 '\x052E\x06\x8dAt\xbbL\x06G\x11\x80\x90AE\x91\xe1',
 '\x05\x02\x00\xf2 \x03\xe8\x17\x05\xf4M\xf7\xba8',
 '\x06\r\x00',
 '\x06?\x00 @3B\xbbW\x01\x00',
 '\x06!\x10\x08)\x80\x10D\x02\x00B\x13',
 '\x06.\n@3\x00c\x01',
 '\x06!\x10\x08)\x80\x10D\x02\x00B\x13',
 '\x06?\x00(@3\x12\xbc`\x00\x00',
 '\x06!\x10\x08)\x80\x10D\x02\x00B\x13',
 "\x06'\x07\x033Y\xa6\x08)\x80\x10D\x02\x00B\x13",
 '\x06!\x10\x08)\x80\x10D\x02\x00B\x13',
 '\x06?\x00 @3\x17\xeb!\x01\x00',
 '\x06!\x10\x08)\x80\x10D\x02\x00B\x13',
 "\x06'\x07\x033Y\xa6\x08)\x80\x10D\x02\x00B\x13"]


