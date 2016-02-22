# −*− coding: UTF−8 −*−
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
# * File Name : formats/L3Mobile_GMM.py
# * Created : 2012-08-27 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from libmich.core.element import Bit, Int, Str, Layer
from libmich.core.IANA_dict import IANA_dict
#
from .L3Mobile_24007 import Type1_TV, Type2, Type3_V, Type3_TV, Type4_LV, \
     Type4_TLV, PD_dict, Layer3
#
# these are the libraries for IE interpretation
from .L3Mobile_IE import ID, MSCm2, PLMNList, MSCm3
from .L3Mobile_IEdict import *

# TS 24.008 defines L3 signalling for mobile networks
#
# section 9: 
# Message definition
#
# describes mobile L3 signalling messages
# each message composed of Information Element (IE)
# each IE is coded on a TypeX (T, TV, LV, TLV...) from 24.007
# each IE is mandatory, conditional, or optional in the message
#
# Messages are coded as Layer
# containing Bit, Int, Str or Layer for each IE
# ...
# It's going to rock!

# 24008, section 10.4
# Packet Service Mobility Management procedures dict
PS_MM_dict = {
    1:"GPRS - Attach request",
    2:"GPRS - Attach accept",
    3:"GPRS - Attach complete",
    4:"GPRS - Attach reject",
    5:"GPRS - Detach request",
    6:"GPRS - Detach accept",
    8:"GPRS - Routing area update request",
    9:"GPRS - Routing area update accept",
    10:"GPRS - Routing area update complete",
    11:"GPRS - Routing area update reject",
    12:"GPRS - Service Request",
    13:"GPRS - Service Accept",
    14:"GPRS - Service Reject",
    16:"GPRS - P-TMSI reallocation command",
    17:"GPRS - P-TMSI reallocation complete",
    18:"GPRS - Authentication and ciphering request",
    19:"GPRS - Authentication and ciphering response",
    20:"GPRS - Authentication and ciphering reject",
    28:"GPRS - Authentication and ciphering failure",
    21:"GPRS - Identity request",
    22:"GPRS - Identity response",
    32:"GPRS - GMM status",
    33:"GPRS - GMM information",
    }

# 24008, 10.5.5.14
GMMCause_dict = IANA_dict({ \
    0:'Protocol error, unspecified',
    2:'IMSI unknown in HLR',
    3:'Illegal MS',
    4:'Protocol error, unspecified',
    5:'IMEI not accepted',
    6:'Illegal ME',
    7:'GPRS services not allowed',
    8:'GPRS services and non-GPRS services not allowed',
    9:'MS identity cannot be derived by the network',
    10:'implicitly detached',
    11:'PLMN not allowed',
    12:'Location Area not allowed',
    13:'Roaming not allowed in this location area',
    14:'GPRS services not allowed in this PLMN',
    15:'GPRS services not allowed in this PLMN',
    16:'MSC temporarily not reachable',
    17:'Network failure',
    18:'Protocol error, unspecified',
    20:'MAC failure',
    21:'Synch failure',
    22:'Congestion',
    23:'GSM authentication unacceptable',
    24:'Protocol error, unspecified',
    25:'Not authorized for this CSG',
    26:'Protocol error, unspecified',
    40:'No PDP context activated',
    41:'Protocol error, unspecified',
    48:'retry upon entry into a new cell',
    64:'Protocol error, unspecified',
    95:'Semantically incorrect message',
    96:'Invalid mandatory information',
    97:'Message type non-existent or not implemented',
    98:'Message type not compatible with the protocol state',
    99:'Information element non-existent or not implemented',
    100:'Conditional IE error',
    101:'Message not compatible with the protocol state',
    102:'Protocol error, unspecified',
    })

###################
# message formats #
###################
# TS 24.008, section 9
class Header(Layer):
    constructorList = [
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator',
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=PS_MM_dict, Repr='hum'),
        ]
    def __init__(self, prot=8, type=32):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type


############################
# TS 24.008, section 9.4   #
# GPRS Mobility Management #
############################

# section 9.4.1
class GPRS_ATTACH_REQUEST(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 1)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('MSNetCap', ReprName='MS network capability', V='\0\0'),
            Bit('CKSN', ReprName='GPRS ciphering key sequence number',
                Pt=0, BitLen=4, Dict=CKSN_dict),
            Bit('AttachTypeFOR', ReprName='Attach follow-on request pending',
                Pt=0, BitLen=1, Repr='hum', Dict=AttachTypeFOR_dict),
            Bit('AttachType', Pt=1, BitLen=3, Repr='hum', Dict=AttachType_dict),
            Str('DRXPara', ReprName='DRX parameter', Pt='\0\0', Len=2),
            Type4_LV('ID', V=ID()),
            Str('RAI', ReprName='Old routing area identification', Pt=6*'\0',
                Len=6),
            Type4_LV('MSRACap', ReprName='MS radio access capability',
                     V=5*'\0'),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI signature', T=0x19,
                     V=3*'\0', Len=3),
            Type3_TV('GPRSTimer', ReprName='Request READY timer', T=0x17,
                     V='\0', Len=1),
            Type1_TV('TMSIStat', ReprName='TMSI status', T=0x9, V=0,
                     Dict=TMSIStatus_dict),
            Type4_TLV('PSLCSCap', ReprName='PS location service capability',
                      T=0x33, V='\0'),
            Type4_TLV('MSCm2', T=0x11, V=MSCm2()),
            Type4_TLV('MSCm3', T=0x20, V=MSCm3()),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list',
                      T=0x40, V='\0\0\0'),
            Type4_TLV('UENetCap', ReprName='UE network capability', T=0x58,
                      V='\0\0'),
            Type4_TLV('ID_2', ReprName='Additional mobile identity', T=0x1A,
                      V=ID()),
            Type4_TLV('RAI_2', ReprName='Additional old routing area identification',
                      T=0x1B, V=6*'\0'),
            Type4_TLV('VoicePref', ReprName='Voice domain preference', T=0x5D,
                      V='\0')])
        self._post_init(with_options, **kwargs)


# section 9.4.2
class GPRS_ATTACH_ACCEPT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 2)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Bit('AttachResFOP', ReprName='Attach follow-on proceed',
                Pt=0, BitLen=1, Repr='hum', Dict=AttachResFOP_dict),
            Bit('AttachRes', ReprName='Attach result', Pt=1, BitLen=3,
                Repr='hum', Dict=AttachRes_dict),
            Int('GPRSTimer', ReprName='Periodic RA update timer', Pt=0,
                Type='uint8'),
            Bit('RadioPrio_2', ReprName='Radio priority 2', Pt=1, BitLen=4),
            Bit('RadioPrio', ReprName='Radio priority', Pt=1, BitLen=4),
            Str('RAI', ReprName='Routing area identification', Pt=6*'\0',
                Len=6),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI signature', T=0x19,
                     V=3*'\0', Len=3),
            Type3_TV('GPRSTimer_2', ReprName='Negotiated READY timer', T=0x17,
                     V='\0', Len=1),
            Type4_TLV('ID', ReprName='Allocated P-TMSI', T=0x18,
                      V=ID(type='TMSI')),
            Type4_TLV('ID_2', ReprName='MS identity', T=0x23, V=ID()),
            Type3_TV('GMMCause', T=0x25, V='\x01', Len=1), # see GMMCause_dict
            Type4_TLV('T3302', T=0x2A, V='\0'),
            Type2('CellNotif', T=0x8C),
            Type4_TLV('PLMNList', ReprName='Equivalent PLMNs', T=0x4A, 
                      V=PLMNList()),
            Type1_TV('NetFeatSupport', T=0xA, V=0),
            Type4_TLV('T3319', T=0x37, V='\0'),
            Type4_TLV('T3323', T=0x38, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.3
class GPRS_ATTACH_COMPLETE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 3)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('IRAT_HO', ReprName='Inter-RAT HO info container',
                      T=0x27, V='\0'),
            Type4_TLV('EUTRAN_IRAT_HO', ReprName='EUTRAN Inter-RAT HO info container',
                      T=0x2B, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.4
class GPRS_ATTACH_REJECT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 4)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('GMMCause', Pt=1, Type='uint8', Dict=GMMCause_dict),
            Type4_TLV('T3302', T=0x2A, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.5
class GPRS_DETACH_REQUEST(Layer3):
    '''
    MS <-> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 5)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        if self._initiator == 'Net':
            # Mobile terminated detach procedure
            self.extend([ \
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Bit('DetachType', Pt=1, BitLen=4, Repr='hum', \
                Dict=DetachTypeNet_dict),
            Type3_TV('GMMCause', T=0x25, V='\x01', Len=1), # see GMMCause_dict
            ])
        else:
            # Mobile originating detach procedure
            self.extend([ \
            Bit('spare', Pt=0, BitLen=4, Repr='hex'),
            Bit('DetachType', Pt=1, BitLen=4, Repr='hum',
                Dict=DetachTypeMS_dict),
            Type4_TLV('ID', T=0x18, V=ID(type='TMSI')),
            Type4_TLV('PTMSISign', ReprName='P-TMSI signature', T=0x19,
                      V='\0\0\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.6
class GPRS_DETACH_ACCEPT(Layer3):
    '''
    MS <-> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 6)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        if self._initiator != 'Net':
            # Mobile originating detach procedure
            self.extend([ \
            Bit('spare', Pt=0, BitLen=4, Repr='hex'),
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
                ])
        self._post_init(with_options, **kwargs)

# section 9.4.7
class PTMSI_REALLOCATION_COMMAND(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 16)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('ID', ReprName='Allocated M-TMSI', V=ID(type='TMSI')),
            Str('RAI', ReprName='Routing area identification',
                Pt=6*'\0', Len=6),
            Bit('spare', Pt=0, BitLen=4, Repr='hex'),
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Type3_TV('PTMSISign', ReprName='P-TMSI signature', T=0x19,
                      V='\0\0\0', Len=3),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.8
class PTMSI_REALLOCATION_COMPLETE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 17)]

# section 9.4.9
class AUTHENTICATION_CIPHERING_REQUEST(Layer3):
    '''
    Net -> MS
    Dual
    '''
    _byte_aligned = False
    constructorList = [ie for ie in Header(8, 18)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('IMEISVReq', Pt=0, BitLen=4),
            Bit('CiphAlg', ReprName='Ciphering algorithm', Pt=0, BitLen=4,
                Repr='hum', Dict=CiphAlg_dict),
            Bit('ACRef', ReprName='A&C reference number', Pt=0, BitLen=4,
                Repr='hex'),
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Type3_TV('RAND', T=0x21, V=16*'\0', Len=16),
            Type1_TV('CKSN', T=0x8, V=0, Dict=CKSN_dict),
            Type4_TLV('AUTN', T=0x28, V=16*'\0'),
            ])
        self.RAND.V.Repr = 'hex'
        self.AUTN.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.4.10
class AUTHENTICATION_CIPHERING_RESPONSE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 19)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4, Repr='hex'),
            Bit('ACRef', ReprName='A&C reference numver', Pt=0, BitLen=4,
                Repr='hex'),
            Type3_TV('RES', T=0x22, V='\0\0\0\0', Len=4),
            Type4_TLV('IMEISV', T=0x23, V=9*'\0'),
            Type4_TLV('RESext', T=0x29, V='\0\0\0\0'),
            ])
        self.RES.V.Repr = 'hex'
        self.RESext.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.4.10a
class AUTHENTICATION_CIPHERING_FAILURE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 28)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('GMMCause', Pt=1, Type='uint8', Dict=GMMCause_dict),
            Type4_TLV('AUTS', T=0x30, V=14*'\0'),
            ])
        self.AUTS.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.4.11
class AUTHENTICATION_CIPHERING_REJECT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 20)]


# section 9.4.12
class GPRS_IDENTITY_REQUEST(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 21)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Bit('IDtype', Pt=1, BitLen=4, Repr='hum', Dict=IDType_dict)
            ])
        self._post_init(with_options, **kwargs)
#
# section 9.4.13
class GPRS_IDENTITY_RESPONSE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 22)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ Type4_LV('ID', V=ID()) ])
        self._post_init(with_options, **kwargs)

# section 9.4.14
class ROUTING_AREA_UPDATE_REQUEST(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 8)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('CKSN', ReprName='GPRS ciphering key sequence number',
                Pt=0, BitLen=4, Dict=CKSN_dict),
            Bit('UpdateTypeFOR', ReprName='Update follow-on request pending',
                Pt=0, BitLen=1, Repr='hum', Dict=AttachTypeFOR_dict),
            Bit('UpdateType', Pt=0, BitLen=3, Repr='hum', Dict=UpdateType_dict),
            Str('RAI', ReprName='Old routing area identification', Pt=6*'\0',
                Len=6),
            Type4_LV('MSRACap', ReprName='MS radio access capability',
                     V=5*'\0'),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI signature', T=0x19,
                     V=3*'\0', Len=3),
            Type3_TV('GPRSTimer', ReprName='Request READY timer', T=0x17,
                     V='\0', Len=1),
            Type3_TV('DRXPara', ReprName='DRX parameter', T=0x27,
                     V='\0\0', Len=2),
            Type1_TV('TMSIStat', ReprName='TMSI status', T=0x9, V=0,
                     Dict=TMSIStatus_dict),
            Type4_TLV('ID', T=0x18, V=ID(type='TMSI')),
            Type4_TLV('MSNetCap', ReprName='MS network capability', T=0x31,
                      V='\0\0'),
            Type4_TLV('PDPCtxStat', ReprName='PDP context status', T=0x32,
                      V='\0\0'),
            Type4_TLV('PSLCSCap', ReprName='PS location service capability',
                      T=0x33, V='\0'),
            Type4_TLV('MBMSCtxStat', ReprName='MBMS context status', T=0x35,
                      V=''),
            Type4_TLV('UENetCap', ReprName='UE network capability', T=0x58,
                      V='\0\0'),
            Type4_TLV('ID_2', ReprName='Additional mobile identity', T=0x1A,
                      V=ID()),
            Type4_TLV('RAI_2', ReprName='Additional old routing area identification',
                      T=0x1B, V=6*'\0'),
            Type4_TLV('MSCm2', T=0x11, V=MSCm2()),
            Type4_TLV('MSCm3', T=0x20, V=MSCm3()),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list',
                      T=0x40, V='\0\0\0'),
            Type4_TLV('VoicePref', ReprName='Voice domain preference', T=0x5D,
                      V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.15
class ROUTING_AREA_UPDATE_ACCEPT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 9)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('UpdateResFOP', ReprName='Update follow-on proceed',
                Pt=0, BitLen=1, Repr='hum', Dict=AttachResFOP_dict),
            Bit('UpdateRes', ReprName='Update result', Pt=1, BitLen=3,
                Repr='hum', Dict=UpdateRes_dict),
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Int('GPRSTimer', ReprName='Periodic RA update timer', Pt=0,
                Type='uint8'),
            Str('RAI', ReprName='Routing area identification', Pt=6*'\0',
                Len=6),
            Type3_TV('PTMSISign', ReprName='Old P-TMSI signature', T=0x19,
                     V=3*'\0', Len=3),
            Type4_TLV('ID', ReprName='Allocated P-TMSI', T=0x18,
                      V=ID(type='TMSI')),
            Type4_TLV('ID_2', ReprName='MS identity', T=0x23, V=ID()),
            Type4_TLV('RxNPDU', ReprName='Receive N-PDU number list', T=0x26,
                      V='\0\0'),
            Type3_TV('GPRSTimer_2', ReprName='Negotiated READY timer', T=0x17,
                     V='\0', Len=1),
            Type3_TV('GMMCause', T=0x25, V='\x01', Len=1), # see GMMCause_dict
            Type4_TLV('T3302', T=0x2A, V='\0'),
            Type2('CellNotif', T=0x8C),
            Type4_TLV('PLMNList', T=0x4A, V=PLMNList()),
            Type4_TLV('PDPCtxStat', ReprName='PDP context status', T=0x32,
                      V='\0\0'),
            Type1_TV('NetFeatSupport', T=0xB, V=0),
            Type4_TLV('ECNumber', ReprName='Emergency number list', T=0x34,
                      V='\0\0\0'),
            Type4_TLV('MBMSCtxStat', ReprName='MBMS context status', T=0x35,
                      V=''),
            Type1_TV('MSInfo', ReprName='MS info requested', T=0xA, V=0),
            Type4_TLV('T3319', T=0x37, V='\0'),
            Type4_TLV('T3323', T=0x38, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.16
class ROUTING_AREA_UPDATE_COMPLETE(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 10)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('RxNPDU', ReprName='Receive N-PDU number list', T=0x26,
                      V='\0\0'),
            Type4_TLV('IRAT_HO', ReprName='Inter-RAT HO info container',
                      T=0x27, V='\0'),
            Type4_TLV('EUTRAN_IRAT_HO', ReprName='EUTRAN Inter-RAT HO info container',
                      T=0x2B, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.17
class ROUTING_AREA_UPDATE_REJECT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 11)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('GMMCause', Pt=1, Type='uint8', Dict=GMMCause_dict),
            Bit('spare', Pt=0, BitLen=4, Repr='hex'),
            Bit('ForceStdby', ReprName='Force to standby', Pt=0, BitLen=4,
                Repr='hum', Dict=ForceStdby_dict),
            Type4_TLV('T3302', T=0x2A, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.18
class GMM_STATUS(Layer3):
    '''
    MS <-> Net
    Local
    '''
    constructorList = [ie for ie in Header(8, 32)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ Int('GMMCause', Pt=1, Type='uint8', Dict=GMMCause_dict) ])
        self._post_init(with_options, **kwargs)

# section 9.4.19
class GMM_INFORMATION(Layer3):
    '''
    Net -> MS
    Local
    '''
    constructorList = [ie for ie in Header(8, 33)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('NetFullName', T=0x43, V='\0'),
            Type4_TLV('NetShortName', T=0x45, V='\0'),
            Type3_TV('TZ', ReprName='Local Time Zone', T=0x46,
               V='\0', Len=1),
            Type3_TV('TZTime', ReprName='Time Zone and Time',
                     T=0x47, V='\0\0\0\0\0\0\0', Len=7),
            Type4_TLV('LSAid', ReprName='Localised Service Area Identity',
                      T=0x48, V=''),
            Type4_TLV('DTime', ReprName='Daylight Saving Time',
                      T=0x49, V='\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.20
class GPRS_SERVICE_REQUEST(Layer3):
    '''
    MS -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(8, 12)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('ServiceType', Pt=0, BitLen=4, Repr='hum',
                Dict=ServiceType_dict),
            Bit('CKSN', ReprName='GPRS ciphering key sequence number',
                Pt=0, BitLen=4, Dict=CKSN_dict),
            Type4_LV('ID', V=ID(type='TMSI')),
            Type4_TLV('PDPCtxStat', ReprName='PDP context status', T=0x32,
                      V='\0\0'),
            Type4_TLV('MBMSCtxStat', ReprName='MBMS context status', T=0x35,
                      V=''),
            Type4_TLV('ULDataStat', ReprName='Uplink data status', T=0x36,
                      V='\0\0'),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.21
class GPRS_SERVICE_ACCEPT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 13)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('PDPCtxStat', ReprName='PDP context status', T=0x32,
                      V='\0\0'),
            Type4_TLV('MBMSCtxStat', ReprName='MBMS context status', T=0x35,
                      V=''),
            ])
        self._post_init(with_options, **kwargs)

# section 9.4.22
class GPRS_SERVICE_REJECT(Layer3):
    '''
    Net -> MS
    Dual
    '''
    constructorList = [ie for ie in Header(8, 14)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ Int('GMMCause', Pt=1, Type='uint8', Dict=GMMCause_dict) ])
        self._post_init(with_options, **kwargs)
#
