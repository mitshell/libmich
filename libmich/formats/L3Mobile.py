# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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

from libmich.core.element import RawLayer, Block, show, debug, \
    log, ERR, WNG, DBG
#
from L3Mobile_24007 import PD_dict
#
# 2G Radio Ressources (uncomplete)
from L3GSM_RR import *
# 2G / 3G core CS stacks (complete)
from L3Mobile_MM import *
from L3Mobile_CC import *
from L3Mobile_SMS import *
# 2G / 3G core PS stacks (complete)
from L3Mobile_GMM import *
from L3Mobile_SM import *
# 4G core stacks (complete)
from L3Mobile_EMM import *
from L3Mobile_ESM import *
# 2G / 3G / 4G Information Element (uncomplete)
from L3Mobile_IE import *


# Handles commonly all defined L3Mobile_XYZ stacks

L3Call = {
# L3Mobile_ESM, PD=2
2 : {
    193:ACTIVATE_DEFAULT_EPS_BEARER_CTX_REQUEST,
    194:ACTIVATE_DEFAULT_EPS_BEARER_CTX_ACCEPT,
    195:ACTIVATE_DEFAULT_EPS_BEARER_CTX_REJECT,
    197:ACTIVATE_DEDI_EPS_BEARER_CTX_REQUEST,
    198:ACTIVATE_DEDI_EPS_BEARER_CTX_ACCEPT,
    199:ACTIVATE_DEDI_EPS_BEARER_CTX_REJECT,
    201:MODIFY_EPS_BEARER_CTX_REQUEST,
    202:MODIFY_EPS_BEARER_CTX_ACCEPT,
    203:MODIFY_EPS_BEARER_CTX_REJECT,
    205:DEACTIVATE_EPS_BEARER_CTX_REQUEST,
    206:DEACTIVATE_EPS_BEARER_CTX_ACCEPT,
    208:PDN_CONNECTIVITY_REQUEST,
    209:PDN_CONNECTIVITY_REJECT,
    210:PDN_DISCONNECT_REQUEST,
    211:PDN_DISCONNECT_REJECT,
    212:BEARER_RESOURCE_ALLOC_REQUEST,
    213:BEARER_RESOURCE_ALLOC_REJECT,
    214:BEARER_RESOURCE_MODIF_REQUEST,
    215:BEARER_RESOURCE_MODIF_REJECT,
    217:ESM_INFORMATION_REQUEST,
    218:ESM_INFORMATION_RESPONSE,
    219:ESM_NOTIFICATION,
    232:ESM_STATUS
    },
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
    62:NOTIFY
    },
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
    50:MM_INFORMATION
    },
# L3GSM_RR, PD=6
6:{
    0:SI_13,
    2:SI_2bis,
    3:SI_2ter,
    5:SI_5bis,
    6:SI_5ter,
    7:SI_2quater,
    13:CHANNEL_RELEASE,
    19:CLASSMARK_ENQUIRY,
    21:MEASUREMENT_REPORT,
    22:CLASSMARK_CHANGE,
    25:SI_1,
    26:SI_2,
    27:SI_3,
    28:SI_4,
    29:SI_5,
    30:SI_6,
    33:PAGING_REQUEST_1,
    34:PAGING_REQUEST_2,
    36:PAGING_REQUEST_3,
    39:PAGING_RESPONSE,
    41:ASSIGNMENT_COMPLETE,
    46:ASSIGNMENT_COMMAND,
    47:ASSIGNMENT_FAILURE,
    50:CIPHERING_MODE_COMPLETE,
    53:CIPHERING_MODE_COMMAND,
    63:IMMEDIATE_ASSIGNMENT
    },
# L3Mobile_EMM, PD=7
7:{
    65:ATTACH_REQUEST,
    66:ATTACH_ACCEPT,
    67:ATTACH_COMPLETE,
    68:ATTACH_REJECT,
    69:DETACH_REQUEST,
    70:DETACH_ACCEPT,
    72:TRACKING_AREA_UPDATE_REQUEST,
    73:TRACKING_AREA_UPDATE_ACCEPT,
    74:TRACKING_AREA_UPDATE_COMPLETE,
    75:TRACKING_AREA_UPDATE_REJECT,
    76:EXTENDED_SERVICE_REQUEST,
    78:SERVICE_REJECT,
    80:GUTI_REALLOCATION_COMMAND,
    81:GUTI_REALLOCATION_COMPLETE,
    82:EPS_AUTHENTICATION_REQUEST,
    83:EPS_AUTHENTICATION_RESPONSE,
    84:EPS_AUTHENTICATION_REJECT,
    92:EPS_AUTHENTICATION_FAILURE,
    85:EPS_IDENTITY_REQUEST,
    86:EPS_IDENTITY_RESPONSE,
    93:SECURITY_MODE_COMMAND,
    94:SECURITY_MODE_COMPLETE,
    95:SECURITY_MODE_REJECT,
    96:EMM_STATUS,
    97:EMM_INFORMATION,
    98:DOWNLINK_NAS_TRANSPORT,
    99:UPLINK_NAS_TRANSPORT,
    100:CS_SERVICE_NOTIFICATION,
    104:DOWNLINK_GENERIC_NAS_TRANSPORT,
    105:UPLINK_GENERIC_NAS_TRANSPORT
    },
# L3Mobile_GMM, PD=8
8:{
    1:GPRS_ATTACH_REQUEST,
    2:GPRS_ATTACH_ACCEPT,
    3:GPRS_ATTACH_COMPLETE,
    4:GPRS_ATTACH_REJECT,
    5:GPRS_DETACH_REQUEST,
    6:GPRS_DETACH_ACCEPT,
    8:ROUTING_AREA_UPDATE_REQUEST,
    9:ROUTING_AREA_UPDATE_ACCEPT,
    10:ROUTING_AREA_UPDATE_COMPLETE,
    11:ROUTING_AREA_UPDATE_REJECT,
    12:GPRS_SERVICE_REQUEST,
    13:GPRS_SERVICE_ACCEPT,
    14:GPRS_SERVICE_REJECT,
    16:PTMSI_REALLOCATION_COMMAND,
    17:PTMSI_REALLOCATION_COMPLETE,
    18:AUTHENTICATION_CIPHERING_REQUEST,
    19:AUTHENTICATION_CIPHERING_RESPONSE,
    20:AUTHENTICATION_CIPHERING_REJECT,
    28:AUTHENTICATION_CIPHERING_FAILURE,
    21:GPRS_IDENTITY_REQUEST,
    22:GPRS_IDENTITY_RESPONSE,
    32:GMM_STATUS,
    33:GMM_INFORMATION
    },
# L3Mobile_SMS, PD=9
9:{
    1:CP_DATA,
    4:CP_ACK,
    16:CP_ERROR,
    },
# L3Mobile_SM, PD=10
10:{
    65:ACTIVATE_PDP_CONTEXT_REQUEST,
    66:ACTIVATE_PDP_CONTEXT_ACCEPT,
    67:ACTIVATE_PDP_CONTEXT_REJECT,
    68:REQUEST_PDP_CONTEXT_ACTIVATION,
    69:REQUEST_PDP_CONTEXT_ACTIVATION_REJECT,
    70:DEACTIVATE_PDP_CONTEXT_REQUEST,
    71:DEACTIVATE_PDP_CONTEXT_ACCEPT,
    72:MODIFY_PDP_CONTEXT_REQUEST_NETTOMS,
    73:MODIFY_PDP_CONTEXT_ACCEPT_MSTONET,
    74:MODIFY_PDP_CONTEXT_REQUEST_MSTONET,
    75:MODIFY_PDP_CONTEXT_ACCEPT_NETTOMS,
    76:MODIFY_PDP_CONTEXT_REJECT,
    77:ACTIVATE_SECONDARY_PDP_CONTEXT_REQUEST,
    78:ACTIVATE_SECONDARY_PDP_CONTEXT_ACCEPT,
    79:ACTIVATE_SECONDARY_PDP_CONTEXT_REJECT,
    85:SM_STATUS,
    86:ACTIVATE_MBMS_CONTEXT_REQUEST,
    87:ACTIVATE_MBMS_CONTEXT_ACCEPT,
    88:ACTIVATE_MBMS_CONTEXT_REJECT,
    89:REQUEST_MBMS_CONTEXT_ACTIVATION,
    90:REQUEST_MBMS_CONTEXT_ACTIVATION_REJECT,
    91:REQUEST_SECONDARY_PDP_CONTEXT_ACTIVATION,
    92:REQUEST_SECONDARY_PDP_CONTEXT_ACTIVATION_REJECT,
    93:GPRS_NOTIFICATION
    }
    # Nothing more yet...
}

# Define a dummy RAW L3 header / message for parts not implemented
class RawL3(Layer3):
    constructorList = [
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Pt=0, Type='uint8'),
        Str('Msg', Pt='', Len=None, Repr='hex')]
#
#
def parse_L3(buf, L2_length_incl=0):
    '''
    This is a global parser for mobile layer 3 signalling.
    It works fine as is with MM, CC, GMM and SM protocols.
    For GSM RR signalling, the length of the L2 pseudo-length header (1 byte)
    needs to be passed as parameter "L2_length_incl" to retrieve correctly 
    the protocol discriminator and message type.
    E.g. for messages passed over GSM BCCH or CCCH: L2_length_incl=1
    
    parse_L3(string_buffer, L2_length_incl=0) -> L3Mobile_instance
    '''
    # select message from PD and Type
    if len(buf) < 2:
        log(ERR, '(parse_L3) message too short for L3 mobile')
        return RawLayer(buf)
    #
    # protocol discriminator is 4 last bits (LSB) of 1st byte
    PD = ord(buf[L2_length_incl]) & 0x0F
    #
    # for MM, CC and GSM RR, only 6 1st bits for the message type
    if PD in (3, 5, 6):
        Type = ord(buf[L2_length_incl+1]) & 0x3F
    # for LTE NAS protocols, the security processing and decoding is
    # managed in Layer3NAS class
    elif PD in (2, 7):
        # check Security Header
        SH = ord(buf[L2_length_incl]) >> 4
        # no security
        if SH == 0:
            Type = ord(buf[L2_length_incl+1])
        # integrity protection only
        elif SH in (1, 3):
            if len(buf) < 8:
                Type = None 
            Type = ord(buf[7])
        # ciphering, hence not possible to know the payload Type
        elif SH in (2, 4):
            Type = None
    else:
        Type = ord(buf[L2_length_incl+1])
    #
    if PD not in L3Call:
        if PD not in PD_dict:
            log(ERR, '(parse_L3) unknown L3 protocol discriminator: %i' % PD)
        else:
            log(WNG, '(parse_L3) L3 protocol %s not implemented' % PD_dict[PD])
        l3 = RawL3()
        l3.map(buf)
    #
    # get the right type from Type
    elif Type not in L3Call[PD] and Type is not None:
        log(ERR, '(parse_L3) L3 message type %i undefined for protocol %s' \
              % (Type, PD_dict[PD]))
        l3 = RawL3()
        l3.map(buf)
        # for L3GSM_RR, still use the msg type dict:
        # because GSM RR are not all implemented
        if PD == 6:
            l3.Type.Dict = GSM_RR_dict
    # select the correct L3 signalling message
    else:
        # for LTE NAS, if ciphered
        if Type is None:
            l3 = Layer3NAS(with_security=True)
        else:
            l3 = L3Call[PD][Type]()
        try:
            l3.map(buf)
        except:
            log(ERR, '(parse_L3) mapping buffer on L3 message failed')
            l3 = RawL3()
            l3.map(buf)
    return l3

#
# OpenBTS typical sequence:
_bts_test = \
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
#

# as the L3Mobile starts to grow up quite a bit
# some regression testing may be welcome !
def test_regr():
    '''
    L3GSM_RR and L3Mobile_* regression testing:
    checking all signalling messages from the L3Call dictionnary
    '''
    # libmich settings
    e_safe = Element.safe
    l_safe = Layer.safe
    Element.safe = True
    Layer.safe = True
    Element.dbg = ERR
    Layer.dbg = ERR
    #
    glob_errors = 0
    #
    def test_dict():
        e = 0
        for pd in L3Call:
            for msg in L3Call[pd]:
                error = ''
                cl = L3Call[pd][msg]
                if not issubclass(cl, Layer3):
                    log(WNG, 'message %s not subclass of Layer3' % repr(cl))
                else:
                    try:
                        m = cl(with_options=True)
                    except:
                        error = '__init__(with_options=True)'
                    else:
                        try: 
                            buf = str(m)
                        except:
                            error = '__str__()'
                        else:
                            try:
                                m2 = cl(with_options=False)
                                m2.parse(buf)
                            except:
                                error = 'parse()'
                            else:
                                if str(m2) != buf:
                                    error = '__str__() result discrepancy ' + \
                                            ' parse()d buffer'
                    if error:
                        log(ERR, 'message %s test returns error: %s' \
                                 % (repr(cl), error))
                        e += 1
        return e
    #
    Layer3._initiator = 'Net'
    log(DBG, 'testing with Net initiator')
    glob_errors += test_dict()
    Layer3._initiator = 'ME'
    log(DBG, 'testing with ME initiator')
    glob_errors += test_dict()
    #
    Element.safe = e_safe
    Layer.safe = l_safe
    #
    if not glob_errors:
        print('[Heeeeha!!!] all L3Mobile tests passed successfully')
    return glob_errors 


