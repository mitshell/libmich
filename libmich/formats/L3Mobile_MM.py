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
# * File Name : formats/L3Mobile_MM.py
# * Created : 2011-08-28 
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
from .L3Mobile_IE import LAI, ID, MSCm1, MSCm2, PLMNList
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
# CS Mobility Management procedures dict
CS_MM_dict = {
    1:"Registration - IMSI DETACH INDICATION",
    2:"Registration - LOCATION UPDATING ACCEPT",
    4:"Registration - LOCATION UPDATING REJECT",
    8:"Registration - LOCATION UPDATING REQUEST",
    17:"Security - AUTHENTICATION REJECT",
    18:"Security - AUTHENTICATION REQUEST",
    20:"Security - AUTHENTICATION RESPONSE",
    28:"Security - AUTHENTICATION FAILURE",
    24:"Security - IDENTITY REQUEST",
    25:"Security - IDENTITY RESPONSE",
    26:"Security - TMSI REALLOCATION COMMAND",
    27:"Security - TMSI REALLOCATION COMPLETE",
    33:"Connection Mgt - CM SERVICE ACCEPT",
    34:"Connection Mgt - CM SERVICE REJECT",
    35:"Connection Mgt - CM SERVICE ABORT",
    36:"Connection Mgt - CM SERVICE REQUEST",
    37:"Connection Mgt - CM SERVICE PROMPT",
    38:"Connection Mgt - Reserved",
    40:"Connection Mgt - CM RE-ESTABLISHMENT REQUEST",
    41:"Connection Mgt - ABORT",
    48:"Misc - MM NULL",
    49:"Misc - MM STATUS",
    50:"Misc - MM INFORMATION",
    }

# 24008, section 10.5.3.6
# Reject Cause
Reject_dict = IANA_dict({ \
    0:'private',
    2:'IMSI unknown in HLR',
    3:'Illegal MS',
    4:'IMSI unknown in VLR',
    5:'IMEI not accepted',
    6:'Illegal ME',
    7:'private',
    11:'PLMN not allowed',
    12:'Location Area not allowed',
    13:'Roaming not allowed in this location area',
    14:'private',
    15:'No Suitable Cells In Location Area',
    16:'private',
    17:'Network failure',
    18:'private',
    20:'MAC failure',
    21:'Synch failure',
    22:'Congestion',
    23:'GSM authentication unacceptable',
    24:'private',
    25:'Not authorized for this CSG',
    26:'private',
    32:'Service option not supported',
    33:'Requested service option not subscribed',
    34:'Service option temporarily out of order',
    35:'private',
    38:'Call cannot be identified',
    39:'private',
    48:'retry upon entry into a new cell',
    95:'Semantically incorrect message',
    96:'Invalid mandatory information',
    97:'Message type non-existent or not implemented',
    98:'Message type not compatible with the protocol state',
    99:'Information element non-existent or not implemented',
    100:'Conditional IE error',
    101:'Message not compatible with the protocol state',
    102:'private',
    111:'Protocol error, unspecified',
    112:'private'})

###################
# message formats #
###################
# TS 24.008, section 9
class Header(Layer):
    constructorList = [
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Bit('seq', ReprName='Sequence Number', Pt=0, BitLen=2, Repr='hum'),
        Bit('Type', BitLen=6, Dict=CS_MM_dict, Repr='hum'),
        ]
    def __init__(self, prot=5, type=48):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type


################
# TS 24.008, section 9.2 #
# Mobility Management    #
################

# section 9.2.12
class IMSI_DETACH_INDICATION(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    MS classmark 1 is 1 byte
    Identity is 1 to 8 bytes
    '''
    constructorList = [ie for ie in Header(5, 1)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('MSCm1', Pt=MSCm1(), Len=1),
            Type4_LV('ID', V=ID())])
        self._post_init(with_options, **kwargs)

# section 9.2.13
class LOCATION_UPDATING_ACCEPT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Location Area ID is 5 bytes
    Opt: Identity (value is 1 to 8 bytes)
    Opt: Follow on proceed
    Opt: CTS permission
    Opt: PLMN list (3 to 44 bytes)
    Opt: EC number (3 to 48 bytes)
    '''
    constructorList = [ie for ie in Header(5, 2)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('LAI', Pt=LAI(), Len=5),
            Type4_TLV('ID', T=0x17, V=ID()),
            Type2('FollowOnProceed', T=0xA1),
            Type2('CTSperm', T=0xA2),
            Type4_TLV('PLMNList', T=0x4A, V=PLMNList()),
            Type4_TLV('ECNList', ReprName='Emergency Number List', T=0x34, \
                      V='\0\0\0')])
        self._post_init(with_options, **kwargs)

# section 9.2.14
class LOCATION_UPDATING_REJECT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(5, 4)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=2, Type='uint8', Dict=Reject_dict)])
        self._post_init(with_options, **kwargs)

# section 9.2.15
class LOCATION_UPDATING_REQUEST(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    Location update type is 4 bits
    Ciphering Key Sequence Number is 4 bits
    Location Area ID is 5 bytes
    MS classmark 1 is 1 byte
    Identity is 1 to 8 bytes
    Cond: MSClassmark2 (3 bytes) to be added only in Iu mode
    '''
    constructorList = [ie for ie in Header(5, 8)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('CKSN', ReprName='Ciphering Key Sequence Number', \
                Pt=0, BitLen=4, Dict=CKSN_dict, Repr='hum'),
            Bit('LUType', ReprName='Location Update Type', \
                Pt=0, BitLen=4, Dict=LUType_dict, Repr='hum'),
            Str('LAI', Pt=LAI(), Len=5),
            Str('MSCm1', Pt=MSCm1(), Len=1),
            Type4_LV('ID', V=ID()),
            Type4_TLV('MSCm2', T=0x33, V=MSCm2())])
        self._post_init(with_options, **kwargs)

# section 9.2.1
class AUTHENTICATION_REJECT(Layer3):
    '''
    Net -> ME
    Dual
    '''
    constructorList = [ie for ie in Header(5, 17)]
#
# section 9.2.2
class AUTHENTICATION_REQUEST(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Ciphering Key Sequence Number is 4 bits
    RAND is 16 bytes
    Cond: AUTN (16 bytes) only if 3G authentication requested
    '''
    constructorList = [ie for ie in Header(5, 18)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4),
            Bit('CKSN', ReprName='Ciphering Key Sequence Number', \
                Pt=0, BitLen=4, Dict=CKSN_dict, Repr='hum'),
            Str('RAND', Pt=16*'\0', Len=16, Repr='hex'),
            Type4_TLV('AUTN', T=0x20, V=16*'\0')])
        self.AUTN.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.2.3
class AUTHENTICATION_RESPONSE(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    RES is 4 bytes (GSM way)
    Cond: RESext (1 to 12 bytes) only if USIM is used in the MS
    '''
    constructorList = [ie for ie in Header(5, 20)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('RES', Pt='\0\0\0\0', Len=4, Repr='hex'),
            Type4_TLV('RESext', T=0x21, V='\0\0\0\0')])
        self.RESext.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.2.3A
class AUTHENTICATION_FAILURE(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    Cause is 1 byte
    Cond: AUTS (16 bytes) only if USIM is used in the MS
    '''
    constructorList = [ie for ie in Header(5, 28)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=2, Type='uint8', Dict=Reject_dict),
            Type4_TLV('AUTS', T=0x22, V=16*'\0')])
        self.AUTS.V.Repr = 'hex'
        self._post_init(with_options, **kwargs)

# section 9.2.10
class IDENTITY_REQUEST(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Identity type is 4 bits
    '''
    constructorList = [ie for ie in Header(5, 24)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4),
            Bit('IDtype', Pt=1, BitLen=4, Dict=IDType_dict, Repr='hum')])
        self._post_init(with_options, **kwargs)

# section 9.2.11
class IDENTITY_RESPONSE(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    Identity value is 1 to 8 bytes
    '''
    constructorList = [ie for ie in Header(5, 25)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('ID', V=ID())])
        self._post_init(with_options, **kwargs)

# section 9.2.17
class TMSI_REALLOCATION_COMMAND(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Location Area ID is 5 bytes
    Identity is 1 to 8 bytes
    '''
    constructorList = [ie for ie in Header(5, 26)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('LAI', Pt=LAI(), Len=5),
            Type4_LV('ID', V=ID())])
        self._post_init(with_options, **kwargs)

# section 9.2.18
class TMSI_REALLOCATION_COMPLETE(Layer3):
    '''
    Net -> ME
    Dual
    '''
    constructorList = [ie for ie in Header(5, 27)]

# section 9.2.5
class CM_SERVICE_ACCEPT(Layer3):
    '''
    Net -> ME
    Dual
    '''
    constructorList = [ie for ie in Header(5, 33)]

# section 9.2.5A
class CM_SERVICE_PROMPT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    SAPI is 1 byte (decomposed)
    '''
    constructorList = [ie for ie in Header(5, 37)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=2),
            Bit('SAPI', Pt=0, BitLen=2),
            Bit('SAPI_PD', Pt=6, BitLen=4, Dict=PD_dict, Repr='hum')])
        self._post_init(with_options, **kwargs)

# section 9.2.6
class CM_SERVICE_REJECT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(5, 34)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=2, Type='uint8', Dict=Reject_dict)])
        self._post_init(with_options, **kwargs)

# section 9.2.7
class CM_SERVICE_ABORT(Layer3):
    '''
    ME -> Net
    Dual
    '''
    constructorList = [ie for ie in Header(5, 35)]

# section 9.2.9
class CM_SERVICE_REQUEST(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    CM service type is 4 bits
    Ciphering Key Sequence Number is 4 bits
    MSClassmark2 value is 3 bytes
    Identity value is 1 to 8 bytes
    Opt: Priority (3 bits)
    '''
    constructorList = [ie for ie in Header(5, 36)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('CKSN', ReprName='Ciphering Key Sequence Number', \
                Pt=0, BitLen=4, Dict=CKSN_dict, Repr='hum'),
            Bit('Service', Pt=1, BitLen=4, Dict=CMService_dict, Repr='hum'),
            Type4_LV('MSCm2', V=MSCm2()),
            Type4_LV('ID', V=ID()),
            Type1_TV('Priority', T=0x8, V=0)])
        self._post_init(with_options, **kwargs)

# section 9.2.4
class CM_REESTABLISHMENT_REQUEST(Layer3):
    '''
    ME -> Net
    Dual
    # content #
    Ciphering Key Sequence Number is 4 bits
    MSClassmark2 value is 3 bytes
    Identity value is 1 to 8 bytes
    Cond: Location Area Id (5 bytes), when TMSI is used
    '''
    constructorList = [ie for ie in Header(5, 40)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('spare', Pt=0, BitLen=4),
            Bit('CKSN', ReprName='Ciphering Key Sequence Number', \
                Pt=0, BitLen=4, Dict=CKSN_dict, Repr='hum'),
            Type4_LV('MSCm2', V=MSCm2()),
            Type4_LV('ID', V=ID()),
            Type3_TV('LAI', T=0x13, V=LAI(), Len=5)])
        self._post_init(with_options, **kwargs)

# section 9.2.8
class ABORT(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(5, 41)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=2, Type='uint8', Dict=Reject_dict)])
        self._post_init(with_options, **kwargs)

# section 9.2.15A
class MM_INFORMATION(Layer3):
    '''
    Net -> ME
    Dual
    # content #
    Opt: Network full name (1 to max bytes)
    Opt: Network short name (1 to max bytes)
    Opt: Local time zone (1 byte)
    Opt: Universal time and local time zone (7 bytes)
    Opt: Localised Service Area identity (4 bytes)
    Opt: Network Daylight Saving Time (1 byte)
    '''
    constructorList = [ie for ie in Header(5, 50)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('NetFullName', T=0x43, V='\0'),
            Type4_TLV('NetShortName', T=0x45, V='\0'),
            Type3_TV('TZ', ReprName='Local Time Zone', T=0x46, \
               V='\0', Len=1),
            Type3_TV('TZTime', ReprName='Time Zone and Time',\
                     T=0x47, V='\0\0\0\0\0\0\0', Len=7),
            Type4_TLV('LSAid', ReprName='Localised Service Area Identity', \
                      T=0x48, V=''),
            Type4_TLV('DTime', ReprName='Daylight Saving Time',\
                      T=0x49, V='\0')])
        self._post_init(with_options, **kwargs)

# section 9.2.16
class MM_STATUS(Layer3):
    '''
    Net <-> ME
    Local
    # content #
    Cause is 1 byte
    '''
    constructorList = [ie for ie in Header(5, 49)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Int('Cause', Pt=2, Type='uint8', Dict=Reject_dict)])
        self._post_init(with_options, **kwargs)

# section 9.2.19
class MM_NULL(Layer3):
    '''
    ME -> Net
    -- to solve interworking issues --
    -- must not ignored --
    '''
    constructorList = [ie for ie in Header(5, 48)]
#
