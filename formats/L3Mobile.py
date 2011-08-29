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
# test messages:
# Mobility Management
test_MM = {
'loc_upd_req' : '\x05\x08pC\xf0\x10\xff\xfeW\x08)\x80\x10D\x02\x00B\x133\x03WX\xa2',
'loc_upd_acc' : '\x05\x02\x02\xf8\x10\x1fO',
'aut_req' : '\x05\x12\x064H\xf6\xa8a"\x90\xf2<\xdb\x11\x0f.5?\xeb \x10\x90\x91\x80vM\x83\x00\x00n\xcb*\xe7\xb2\xfe\r\xbe',
'aut_res' : '\x05T\xaa\xe8\xfa\x1a!\x04\x01\x95\x84\xdd',
'tmsi_rea_cmd' : '\x05\x1a\x02\xf8\x10\x1fO\x05\xf4 AE\x01',
'tmsi_rea_comp' : '\x05\x9b',
'id_req' : '\x05\x18\x03',
'id_res_imei' : '\x05\xd9\t\x03@\x04\x12\x14)6\x08\xf0',
'cm_serv_req' : '\x05$d\x03WX\xa2\x05\xf4 AE\x01',
}

# Call Control
test_CC_NETini = {
'setup': '\x03\x05\x04\x01\xa0',
'call_proc' : '\x83\x02',
'alert' : '\x83\x01\x1e\x02\xe2\xa0',
'con' : '\x83\x07\x1e\x02\xe2\xa0',
'con_ack' : '\x03\x0f',
'discon' : '\x03%\x02\xe0\x90',
'rel' : '\x83-\x08\x02\xe0\x90',
'rel_comp' : '\x03*\x08\x02\xe0\x90',
}
test_CC_MEini = {
'alert' : '\x83\xc1',
'call_conf' : '\x83\x88\x04\x06`\x04\x02\x00\x05\x81\x15\x02\x01\x00@\x08\x04\x02`\x00\x00\x02\x1f\x00',
'con' : '\x83\x07',
'con_ack' : '\x03\x0f',
'discon' : '\x03e\x02\xe0\x90',
'rel' : '\x83m',
'rel_comp' : '\x83\xaa',
'setup' : '\x03\x85\x04\x06`\x04\x02\x00\x05\x81^\x08\x81\x003\x96\x99 4\xf0\x15\x02\x01\x00@\x08\x04\x02`\x04\x00\x02\x1f\x00',
}

# Short Message Service
test_SMS = {
'cp_rp_1' : '\t\x01\xa5\x00\x01\x00\x07\x913\x86\t@\x00\xf0\x99A\x02\x0b\x91dg\x03\x17\x81\xf5\x00\x00\xa0\x05\x00\x03\xbc\x02\x01\x82A\x1d\x08\x06\xa3\xd1`\xb2\x18-\x96\x93\xd9f8\x98"X\xd4\x81\xaeO)\x93\xd8\x8a\xb5p\x91\x99\x0b\xe6\n\xba`\xae\x99\xcc\xa6\x08\x1au\xa0\x98\x8cvk\xc9d\xb0YDJ\x1b*\x82S\x1dH\x06\xc3\xc1b4\x9a\x0c\x06\x83\xc9h\xb3\x98"\x88\xd5\x81f4\x98"\x98\xd5\x81`1\x85\xd0\xa8\x03\xd1`6\x85\x10\xa9\x03\xd1j0\x850\xa9\x03\xdd\x14B\xa5\x0e\x04S\x08\xb1:\x10L!\xcc\xea@7\xc5\x90\xaa\x03\xcdb6\xd8,7\xc3\xc9\x14',
'cp_rp_2' : '\t\x01J\x00\x02\x00\x07\x913\x86\t@\x00\xf0>A\x03\x0b\x91dg\x03\x17\x81\xf5\x00\x008\x05\x00\x03\xbc\x02\x02\x82C\x1dh\xe6\x82\xb9\x82.\x98k&\xb3\x81b2\x9a\xacE\xa3\xd9l\x91c\xd1Y\x94&\x87\x91\xea\xb4(%\x16\x85\xd5c\xa4I\x8d\xd5\x14',
'cp_ack' : '\x89\x04',
'rp_err': '\x89\x01\x04\x05\x01\x01&',
}

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

'''
recv: 0524110333599005f4540198cb : MM CM Service Request serviceType=MOC mobileIdentity=(TMSI=0x540198cb) classmark=(revision=1 ES-IND=1 A5/1=0 A5/2=0 A5/3=0 powerCap=3 PS=1 SSScrenInd=1 SM=1 VBS=0 VGCS=0 FC=1 CM3=1 LCSVA=0 SoLSA=0 CMSF=0)
send: 051801 : MM Identity Request type=IMSI
recv: 0559082980101310773652 : MM Identity Response mobile id=IMSI=208013101776325
send: 0521 : MM CM Service Accept
recv: 030504066004020005815e088100126379363516 : CC Setup TI=(0,0) CalledPartyBCDNumber=(type=unknown plan=E.164/ISDN digits=00213697635361)
send: 8302 : CC Call Proceeding TI=(1,0)
send: 062e0a4033006301 : RR Assignment Command channelDescription=(typeAndOffset=TCH/F TN=2 TSC=2 ARFCN=51) powerCommand=0 mode1=speech1
recv: 062900 : RR Assignment Complete cause=0x0
send: 832502e1ff : CC Disconnect TI=(1,0) cause=(location=1 cause=0x7f)
send: 832a : CC Release Complete TI=(1,0)
send: 060d00 : RR Channel Release cause=0x0
recv: 036d0802e090 : CC Release TI=(0,0) cause=(location=0 cause=0x10)
recv: 0524110333599005f4540198cb : MM CM Service Request serviceType=MOC mobileIdentity=(TMSI=0x540198cb) classmark=(revision=1 ES-IND=1 A5/1=0 A5/2=0 A5/3=0 powerCap=3 PS=1 SSScrenInd=1 SM=1 VBS=0 VGCS=0 FC=1 CM3=1 LCSVA=0 SoLSA=0 CMSF=0)
send: 051801 : MM Identity Request type=IMSI
recv: 0559082980101310773652 : MM Identity Response mobile id=IMSI=208013101776325
send: 0521 : MM CM Service Accept
recv: 030504066004020005815e03811230 : CC Setup TI=(0,0) CalledPartyBCDNumber=(type=unknown plan=E.164/ISDN digits=2103)
send: 8302 : CC Call Proceeding TI=(1,0)
send: 062e0a4033006301 : RR Assignment Command channelDescription=(typeAndOffset=TCH/F TN=2 TSC=2 ARFCN=51) powerCommand=0 mode1=speech1
recv: 062900 : RR Assignment Complete cause=0x0
send: 830302e180 : CC 0x3 TI=(1,0) prog_ind=(location=1 progress=0x0)
send: 8301 : CC Alerting TI=(1,0)
send: 8307 : CC Connect TI=(1,0)
recv: 034f : CC Connect Acknowledge TI=(0,0)
recv: 032502e090 : CC Disconnect TI=(0,0) cause=(location=0 cause=0x10)
send: 832d : CC Release TI=(1,0)
recv: 036a0802e090 : CC Release Complete TI=(0,0) cause=(location=0 cause=0x10)
send: 060d00 : RR Channel Release cause=0x0
send: 832502e190 : CC Disconnect TI=(1,0) cause=(location=1 cause=0x10)
send: 832a : CC Release Complete TI=(1,0)
send: 060d00 : RR Channel Release cause=0x0
send: 060d01 : RR Channel Release cause=0x1
recv: 05081100f22003e83305f4540198cb : MM Location Updating Request LAI=(MCC=002 MNC=02 LAC=0x3e8) MobileIdentity=(TMSI=0x540198cb) classmark=(revision=1 ES-IND=1 A5/1=0 powerCap=3)
send: 051801 : MM Identity Request type=IMSI
recv: 0559082980101310773652 : MM Identity Response mobile id=IMSI=208013101776325
send: 053245068d4174bb4c0647118090414591e1 : MM MM Information short name=(Ahmed) time=(Tue Aug  9 10:54:19 2011)
send: 050200f22003e81705f44df7ba38 : MM Location Updating Accept LAI=(MCC=002 MNC=02 LAC=0x3e8)ID=(TMSI=0x4df7ba38)
send: 060d00 : RR Channel Release cause=0x0
'''