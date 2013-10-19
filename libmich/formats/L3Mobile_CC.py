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
# * File Name : formats/L3Mobile_CC.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer, \
    show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.L3Mobile_24007 import Type1_TV, Type2, \
    Type3_V, Type3_TV, Type4_LV, Type4_TLV, PD_dict, \
    Layer3
from libmich.formats.L3Mobile_IE import AuxState, BearerCap, CCCap

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
# Call Control and call related SS procedures list
CS_CC_dict = {
    0:"national specific",
    1:"Call establishment - ALERTING",
    8:"Call establishment - CALL CONFIRMED",
    2:"Call establishment - CALL PROCEEDING",
    7:"Call establishment - CONNECT",
    15:"Call establishment - CONNECT ACKNOWLEDGE",
    14:"Call establishment - EMERGENCY SETUP",
    3:"Call establishment - PROGRESS",
    4:"Call establishment - CC-ESTABLISHMENT",
    6:"Call establishment - CC-ESTABLISHMENT CONFIRMED",
    11:"Call establishment - RECALL",
    9:"Call establishment - START CC",
    5:"Call establishment - SETUP",
    23:"Call information - MODIFY",
    31:"Call information - MODIFY COMPLETE",
    19:"Call information - MODIFY REJECT",
    16:"Call information - USER INFORMATION",
    24:"Call information - HOLD",
    25:"Call information - HOLD ACKNOWLEDGE",
    26:"Call information - HOLD REJECT",
    28:"Call information - RETRIEVE",
    29:"Call information - RETRIEVE ACKNOWLEDGE",
    30:"Call information - RETRIEVE REJECT",
    37:"Call clearing - DISCONNECT",
    45:"Call clearing - RELEASE",
    42:"Call clearing - RELEASE COMPLETE",
    57:"Misc - CONGESTION CONTROL",
    62:"Misc - NOTIFY",
    61:"Misc - STATUS",
    52:"Misc - STATUS ENQUIRY",
    53:"Misc - START DTMF",
    49:"Misc - STOP DTMF",
    50:"Misc - STOP DTMF ACKNOWLEDGE",
    54:"Misc - START DTMF ACKNOWLEDGE",
    55:"Misc - START DTMF REJECT",
    58:"Misc - FACILITY",
    }

# 
# section 10.5.4.22
# Repeat indicator, when 2 repeated IE are present:
Repeat_dict = {
    0:'no repeated IE',
    1:'mode 1 alternate mode 2',
    2:'mode 1 preferred, mode 2 if mode 1 fails',
    3:'reserved',
    4:'mode 1 alternate mode2, mode 1 preferred'}


########################
# Now, message formats #
########################
# TS 24.008, section 9
class Header(Layer):
    constructorList = [
        Bit('TI', ReprName='Transaction Identifier', \
            Pt=0, BitLen=4, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Bit('seq', ReprName='Sequence Number', Pt=0, BitLen=2, Repr='hum'),
        Bit('Type', BitLen=6, Dict=CS_CC_dict, Repr='hum')]
    
    def __init__(self, prot=3, type=58):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type

###############################
# TS 24.008, section 9.3      #
# Circuit Switch Call Control #
###############################

# section 9.3.1
class ALERTING(Layer3):
    '''
    Net <-> ME
    Global
    # content #
    Opt: Facility (0 to max bytes), for SS, only Net -> ME
    Opt: Progress Indicator (2 bytes)
    Opt: User-User (1 to 129 bytes)
    Opt: SS version indicator (0 or 1 byte), only ME -> Net
    '''
    constructorList = [ie for ie in Header(3, 1)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('ProgressInd', T=0x1E, V='\x80\x80'),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0'),
            Type4_TLV('SS', ReprName='Supplementary Service version indicator',\
                      T=0x7F, V='', Trans=True)])
        self._post_init(with_options, **kwargs)

# section 9.3.2
class CALL_CONFIRMED(Layer3):
    '''
    ME -> Net
    Local
    # content #
    Cond: Repeat indicator (4 bits), only if BearerCap && BearerCap2
    Cond: Bearer capability (1 to 14 bytes), see 9.3.2.2
    Cond: Bearer capability 2 (1 to 14 bytes), see 9.3.2.2
    Opt: Cause (2 to 30 bytes)
    Opt: CC capability (2 bytes)
    Opt: Stream identifier (1 byte)
    Cond: Supported codecs (3 to max bytes), if UMTS supported
    '''
    constructorList = [ie for ie in Header(3, 8)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('BearerCap', T=0x4, V=BearerCap()),
            Type4_TLV('BearerCap_2', T=0x4, V=BearerCap(), Trans=True),
            Type4_TLV('Cause', T=0x8, V='\0\x80'),
            Type4_TLV('CCCap', T=0x15, V=CCCap()),
            Type4_TLV('StreamId', T=0x2D, V='\0'),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list', \
                      T=0x40, V='\0\0\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.3
class CALL_PROCEEDING(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Cond: Repeat indicator (4 bits), only if BearerCap && BearerCap2
    Opt: Bearer capability (1 to 14 bytes), see 9.3.3.2
    Opt: Bearer capability 2 (1 to 14 bytes), see 9.3.3.2
    Opt: Facility (0 to max bytes), for SS
    Opt: Progress Indicator (2 bytes)
    Opt: Priority (3 bits)
    Opt: Network CC capability (1 byte)
    '''
    constructorList = [ie for ie in Header(3, 2)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                      Trans=True),
            Type4_TLV('BearerCap', T=0x4, V=BearerCap()),
            Type4_TLV('BearerCap_2', T=0x4, V=BearerCap(), Trans=True),
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('ProgressInd', T=0x1E, V='\x80\x80'),
            Type1_TV('Priority', T=0x8, V=0),
            Type4_TLV('NetCCCap', T=0x2F, V='\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.4
class CONGESTION_CONTROL(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Level is 4 bits
    Opt: Cause (2 to 30 bytes)
    '''
    constructorList = [ie for ie in Header(3, 57)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Bit('Level', Pt=0, BitLen=4, Repr='hum'),
            Bit('spare', Pt=0, BitLen=4),
            Type4_TLV('Cause', T=0x8, V='\0\x80')])
        self._post_init(with_options, **kwargs)

#section 9.3.5
class CONNECT(Layer3):
    '''
    Net <-> ME
    Global
    # content, initiated by Net #
    Opt: Facility (0 to max bytes), for SS
    Opt: Progress Indicator (2 bytes)
    Opt: Connected number (1 to 12 bytes)
    Opt: Connected subaddress (0 to 21 bytes)
    Opt: User-user (1 to 129 bytes)
    # content, initiated by ME #
    Opt: Facility (0 to max bytes), for SS
    Opt: Connected subaddress (0 to 21 bytes)
    Opt: User-user (1 to 129 bytes)
    Cond: SS version (0 or 1 byte), only if Facility
    Opt: Stream identifier (1 byte)
    '''
    constructorList = [ie for ie in Header(3, 7)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        if self._initiator == 'Net':
            # network to MS direction
            self.extend([ \
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('ProgressInd', T=0x1E, V='\x80\x80'),
            Type4_TLV('Number', T=0x4C, V='\0'),
            Type4_TLV('Subaddr', T=0x4D, V=''),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                       V='\0')])
        else:
            # MS to network direction
            self.extend([ \
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('Subaddr', T=0x4D, V=''),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0'),
            Type4_TLV('SSversion', T=0x7F, V=''),
            Type4_TLV('StreamId', T=0x2D, V='\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.6
class CONNECT_ACKNOWLEDGE(Layer3):
    '''
    Net <-> ME
    Local
    '''
    constructorList = [ie for ie in Header(3, 15)]

#section 9.3.7.1
class DISCONNECT(Layer3):
    '''
    Net <-> ME
    Global
    # content, initiated by Net #
    Cause is 2 to 29 bytes
    Opt: Facility (0 to max bytes), for SS
    Opt: Progress Indicator (2 bytes)
    Opt: User-user (1 to 129 bytes)
    Opt: Allowed actions (1 byte)
    # content, initiated by ME #
    Cause is 2 to 29 bytes
    Opt: Facility (0 to max bytes), for SS
    Opt: User-user (1 to 129 bytes)
    Cond: SS version (0 or 1 byte), only if Facility
    '''
    constructorList = [ie for ie in Header(3, 37)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('Cause',V='\0\x80'),
            Type4_TLV('Facility', T=0x1C, V='')])
        if self._initiator == 'Net':
            # network to MS direction
            self.extend([ \
            Type4_TLV('ProgressInd', T=0x1E, V='\x80\x80'),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0'),
            Type4_TLV('AA', ReprName='Allowed Actions (CCBS)', \
                      T=0x7B, V='\0')])
        else:
            # MS to network direction
            self.extend([Type4_TLV('SSversion', T=0x7F, V='')])
        self._post_init(with_options, **kwargs)

#section 9.3.8
class EMERGENCY_SETUP(Layer3):
    '''
    ME -> Net
    Global
    # content #
    Opt: Bearer capability (1 to 9 bytes)
    Opt: Stream identifier (1 byte)
    Opt: Supported codec list (3 to ? bytes)
    Opt: Emergency category (1 byte)
    '''
    constructorList = [ie for ie in Header(3, 14)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('BearerCap', T=0x4, V=BearerCap()),
            Type4_TLV('StreamId', T=0x2D, V='\0'),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list', \
                      T=0x40, V='\0\0\0'),
            Type4_TLV('EC', ReprName='Emergency Category', \
                      T=0x2E, V='\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.9
class FACILITY(Layer3):
    '''
    Net <-> ME
    Local
    # content #
    Facility is 0 to ? bytes
    # content, initiated by ME #
    Opt: SS version (0 or 1 byte)
    '''
    constructorList = [ie for ie in Header(3, 58)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('Facility', V='')])
        if self._initiator != 'Net':
            # MS to network direction
            self.extend([Type4_TLV('SSversion', T=0x7F, V='')])
        self._post_init(with_options, **kwargs)

#section 9.3.10
class HOLD(Layer3):
    '''
    ME -> Net
    Local
    '''
    constructorList = [ie for ie in Header(3, 24)]

#section 9.3.11
class HOLD_ACKNOWLEDGE(Layer3):
    '''
    Net -> ME
    Local
    '''
    constructorList = [ie for ie in Header(3, 25)]

#section 9.3.12
class HOLD_REJECT(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Cause is 1 to 29 bytes
    '''
    constructorList = [ie for ie in Header(3, 26)]
    # actually, there is no option here...
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('Cause', V='\0\x80')])
        self._post_init(with_options, **kwargs)

#section 9.3.13
class MODIFY(Layer3):
    '''
    Net <-> ME
    Global
    # content #
    Bearer capability is 1 to 14 bytes
    Opt: Low layer compatibility (0 to 16 bytes)
    Opt: High layer compatibility (0 to 3 bytes)
    Opt: Reverse call setup direction, ME -> Net
    Opt: Network initiated service upgrade indicator, Net -> ME
    '''
    constructorList = [ie for ie in Header(3, 23)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('BearerCap', V=BearerCap()),
            Type4_TLV('LowLayerComp', T=0x7C, V=''),
            Type4_TLV('HighLayerComp', T=0x7D, V=''),
            Type2('Reverse', T=0xA3),
            Type2('UpgradeInd', T=0xA4)])
        self._post_init(with_options, **kwargs)

#section 9.3.14
class MODIFY_COMPLETE(Layer3):
    '''
    Net <-> ME
    Global
    # content #
    Bearer capability is 1 to 14 bytes
    Opt: Low layer compatibility (0 to 16 bytes)
    Opt: High layer compatibility (0 to 3 bytes)
    Opt: Reverse call setup direction
    '''
    constructorList = [ie for ie in Header(3, 31)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('BearerCap', V=BearerCap()),
            Type4_TLV('LowLayerComp', T=0x7C, V=''),
            Type4_TLV('HighLayerComp', T=0x7D, V=''),
            Type2('Reverse', T=0xA3)])
        self._post_init(with_options, **kwargs)

#section 9.3.15
class MODIFY_REJECT(Layer3):
    '''
    Net <-> ME
    Global
    # content #
    Bearer capability is 1 to 14 bytes
    Cause is 1 to 29 bytes
    Opt: Low layer compatibility (0 to 16 bytes)
    Opt: High layer compatibility (0 to 3 bytes)
    '''
    constructorList = [ie for ie in Header(3, 19)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('BearerCap', V=BearerCap()),
            Type4_LV('Cause', V='\0\x80'),
            Type4_TLV('LowLayerComp', T=0x7C, V=''),
            Type4_TLV('HighLayerComp', T=0x7D, V='')])
        self._post_init(with_options, **kwargs)

#section 9.3.16
class NOTIFY(Layer3):
    '''
    Net <-> ME
    Access
    # content #
    Notification indicator is 1 byte
    '''
    constructorList = [ie for ie in Header(3, 62)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('NotifInd', ReprName='Notify Indication', \
                Pt='\0', Len=1, Repr='hex')])
        self._post_init(with_options, **kwargs)

#section 9.3.17
class PROGRESS(Layer3):
    '''
    Net -> ME
    Global
    # content #
    Progress indicator is 2 bytes
    Opt: User-user (1 to 129 bytes)
    '''
    constructorList = [ie for ie in Header(3, 3)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('ProgressInd', V='\x80\x80'),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, V='\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.17a
class CC_ESTABLISHMENT(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Setup container is 2 to max bytes
    '''
    constructorList = [ie for ie in Header(3, 4)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('SetupCont', V='\0\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.17b
class CC_ESTABLISHMENT_CONFIRMED(Layer3):
    '''
    ME -> Net
    Local
    # content #
    Cond: Repeat indicator (4 bits), only if BearerCap && BearerCap2
    Bearer capability (1 to 8 bytes), see 9.3.17b.2
    Cond: Bearer capability 2 (1 to 8 bytes), see see 9.3.17b.2
    Opt: Cause (2 to 30 bytes)
    Cond: Supported codecs (3 to max bytes), if UMTS supported
    '''
    constructorList = [ie for ie in Header(3, 6)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('BearerCap', T=0x4, V=BearerCap()),
            Type4_TLV('BearerCap_2', T=0x4, V=BearerCap(), Trans=True),
            Type4_TLV('Cause', T=0x8, V='\0\x80'),
            Type4_TLV('SuppCodecs', ReprName='Supported codecs list', \
                      T=0x40, V='\0\0\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.18
class RELEASE(Layer3):
    '''
    Net <-> ME
    Local
    # content, initiated by Net #
    Opt: Cause (2 to 30 bytes)
    Opt: 2nd cause (2 to 30 bytes)
    Opt: Facility (0 to max bytes), for SS
    Opt: User-user (1 to 129 bytes)
    # content, initiated by ME #
    Opt: Cause (2 to 30 bytes)
    Opt: 2nd cause (2 to 30 bytes)
    Opt: Facility (0 to max bytes), for SS
    Opt: User-user (1 to 129 bytes)
    Cond: SS version (0 or 1 byte), only if Facility
    '''
    constructorList = [ie for ie in Header(3, 1)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('Cause', T=0x08, V='\0\x80'),
            Type4_TLV('Cause', T=0x08, V='\0\x80'),
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0')])
        if self._initiator != 'Net':
            # MS to network direction
            self.extend([Type4_TLV('SSversion', T=0x7F, V='')])
        self._post_init(with_options, **kwargs)

#section 9.3.18a
class RECALL(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Recall type is 1 byte
    Facility is 1 to max bytes
    '''
    constructorList = [ie for ie in Header(3, 11)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Str('Recall', Pt='\0', Len=1, Repr='hex'),
            Type4_LV('Facility', V='\0')])
        self._post_init(with_options, **kwargs)

#section 9.3.19
class RELEASE_COMPLETE(Layer3):
    '''
    Net <-> ME
    Local
    # content, initiated by ME #
    Opt: Cause (2 to 30 bytes)
    Opt: Facility (0 to max bytes), for SS
    Opt: User-user (1 to 129 bytes)
    # content, initiated by ME #
    Opt: Cause (2 to 30 bytes)
    Opt: Facility (0 to max bytes), for SS
    Opt: User-user (1 to 129 bytes)
    Opt: SS version (0 or 1 byte)
    '''
    constructorList = [ie for ie in Header(3, 42)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('Cause', T=0x08, V='\0\x80'),
            Type4_TLV('Facility', T=0x1C, V=''),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0')])
        if self._initiator != 'Net':
            # MS to network direction
            self.extend([Type4_TLV('SSversion', T=0x7F, V='')])
        self._post_init(with_options, **kwargs)

#section 9.3.20
class RETRIEVE(Layer3):
    '''
    ME -> Net
    Local
    '''
    constructorList = [ie for ie in Header(3, 28)]

#section 9.3.21
class RETRIEVE_ACKNOWLEDGE(Layer3):
    '''
    Net -> ME
    Local
    '''
    constructorList = [ie for ie in Header(3, 29)]

#section 9.3.22
class RETRIEVE_REJECT(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Cause is 2 to 30 bytes
    '''
    constructorList = [ie for ie in Header(3, 30)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('Cause', V='\0\x80')])
        self._post_init(with_options, **kwargs)

#section 9.3.23
class SETUP(Layer3):
    '''
    Net <-> ME
    Global
    # content, initiated by Net #
    Cond: Repeat indicator (4 bits), only if BearerCap && BearerCap2
    Opt: Bearer capability (1 to 14 bytes), see 9.3.23.1
    Opt: Bearer capability 2 (1 to 14 bytes), see 9.3.23.1
    Opt: Facility (0 to max bytes), for SS
    Opt: Progress Indicator (2 bytes)
    Opt: Signal (1 byte)
    Opt: Calling party BCD number (1 to 12 bytes)
    Opt: Calling party sub-address (0 to 21 bytes)
    Opt: Called party BCD number (1 to 17 bytes)
    Opt: Called party sub-address (0 to 21 bytes)
    Opt: Redirecting party BCD number (1 to 17 bytes)
    Opt: Redirecting party BCD sub-address (0 to 21 bytes)
    Cond: repeat indicator (4 bits), only if LLC && LLC2
    Opt: Low layer compatibility (0 to 16 bytes)
    Opt: Low layer compatibility 2 (0 to 16 bytes)
    Cond: repeat indicator (4 bits), only if HLC && HLC2
    Opt: High layer compatibility (0 to 3 bytes)
    Opt: High layer compatibility 2 (0 to 3 bytes)
    Opt: User-user (1 to 33 bytes)
    Opt: Priority (3 bits)
    Opt: Alert (1 byte)
    Opt: Network CC capability (1 byte)
    Opt: Cause of no CLI (1 byte)
    Opt: Backup bearer capability (1 to 13 bytes)
    # content, initiated by ME #
    Cond: Repeat indicator (4 bits), only if BearerCap && BearerCap2
    Opt: Bearer capability (1 to 14 bytes), see 9.3.23.1
    Opt: Bearer capability 2 (1 to 14 bytes), see 9.3.23.1
    Opt: Facility -simple recall alignment- (0 to max bytes), for SS
    Opt: Calling party sub-address (0 to 21 bytes)
    Opt: Called party BCD number (1 to 17 bytes)
    Opt: Called party sub-address (0 to 21 bytes)
    Cond: repeat indicator (4 bits), only if LLC && LLC2
    Opt: Low layer compatibility (0 to 16 bytes)
    Opt: Low layer compatibility 2 (0 to 16 bytes)
    Cond: repeat indicator (4 bits), only if HLC && HLC2
    Opt: High layer compatibility (0 to 3 bytes)
    Opt: High layer compatibility 2 (0 to 3 bytes)
    Opt: User-user (1 to 33 bytes)
    Opt: SS version (0 or 1 byte)
    Opt: CLIR suppression
    Opt: CLIR invocation
    Opt: CC capability (2 bytes)
    Opt: Facility -advanced recall alignment- (0 to max bytes)
    Opt: Facility -recall alignment not essential- (0 to max bytes)
    Opt: Stream identifier (1 byte)
    Cond: Supported codecs (3 to max bytes), if UMTS supported
    Opt: Redial
    '''
    
    constructorList = [ie for ie in Header(3, 5)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('BearerCap', T=0x4, V=BearerCap()),
            Type4_TLV('BearerCap_2', T=0x4, V=BearerCap(), Trans=True),
            Type4_TLV('Facility', T=0x1C, V='')])
        if self._initiator == 'Net':
            # network to MS direction
            self.extend([ \
            Type4_TLV('ProgressInd', T=0x1E, V='\x80\x80'),
            Type3_TV('Signal', T=0x34, V='\0', Len=1),
            Type4_TLV('CallingBCD', T=0x5C, V='\0'),
            Type4_TLV('CallingSub', T=0x5D, V=''),
            Type4_TLV('CalledBCD', T=0x5E, V='\0'),
            Type4_TLV('CalledSub', T=0x6D, V=''),
            Type4_TLV('RedirectingBCD', T=0x74, V='\0'),
            Type4_TLV('RedirectingSub', T=0x75, V=''),
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('LowLayerComp', T=0x7C, V='\0'),
            Type4_TLV('LowLayerComp_2', T=0x7C, V='\0', Trans=True),
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('HighLayerComp', T=0x7D, V='\0'),
            Type4_TLV('HighLayerComp_2', T=0x7D, V='\0', Trans=True),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0'),
            Type1_TV('Priority', T=0x8, V=0),
            Type4_TLV('Alert', T=0x19, V='\0'),
            Type4_TLV('NetCCCap', T=0x2F, V='\0'),
            Type4_TLV('CauseNoCLI', T=0x3A, V='\0'),
            Type4_TLV('BUBearerCap', T=0x41, V='\0')])
        else:
            # MS to network direction
            self.extend([ \
            Type4_TLV('CallingSub', T=0x5D, V=''),
            Type4_TLV('CalledBCD', T=0x5E, V='\0'),
            Type4_TLV('CalledSub', T=0x6D, V=''),
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('LowLayerComp', T=0x7C, V='\0'),
            Type4_TLV('LowLayerComp_2', T=0x7C, V='\0', Trans=True),
            Type1_TV('RepeatInd', T=0xD, V=1, Dict=Repeat_dict, \
                     Trans=True),
            Type4_TLV('HighLayerComp', T=0x7D, V='\0'),
            Type4_TLV('HighLayerComp_2', T=0x7D, V='\0', Trans=True),
            Type4_TLV('UU', ReprName='User-User', T=0x7E, \
                      V='\0'),
            Type4_TLV('SSversion', T=0x7F, V=''),
            Type2('CLIRSuppr', T=0x8),
            Type2('CLIRInvoc', T=0x19),
            Type4_TLV('CCCap', T=0x15, V=CCCap()),
            Type4_TLV('FacilityAdvanced', T=0x1D, V=''),
            Type4_TLV('FacilityNotEssential', T=0x1B, V=''),
            Type4_TLV('StreamId', T=0x2D, V='\0\0'),
            Type4_TLV('SuppCodecs', ReprName='Supported Codecs List', \
                      T=0x40, V='\0\0\0'),
            Type2('Redial', T=0xA3)])
        self._post_init(with_options, **kwargs)

#section 9.3.23a
class START_CC(Layer3):
    '''
    ME -> Net
    Local
    # content #
    Opt: CC capability (2 bytes)
    '''
    constructorList = [ie for ie in Header(3, 9)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_TLV('CCCap', T=0x15, V=CCCap())])
        self._post_init(with_options, **kwargs)

#section 9.3.24
class START_DTMF(Layer3):
    '''
    ME -> Net
    Local
    # content #
    Opt: Keypad facility (1 byte)
    '''
    constructorList = [ie for ie in Header(3, 53)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type3_TV('Keypad', T=0x2C, V='\0', Len=1)])
        self._post_init(with_options, **kwargs)

#section 9.3.25
class START_DTMF_ACKNOWLEDGE(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Opt: Keypad facility (1 byte)
    '''
    constructorList = [ie for ie in Header(3, 54)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type3_TV('Keypad', T=0x2C, V='\0', Len=1)])
        self._post_init(with_options, **kwargs)

#section 9.3.26
class START_DTMF_REJECT(Layer3):
    '''
    Net -> ME
    Local
    # content #
    Cause is 2 to 30 bytes
    '''
    constructorList = [ie for ie in Header(3, 55)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('Cause', V='\0\x80')])
        self._post_init(with_options, **kwargs)

#section 9.3.27
class STATUS(Layer3):
    '''
    Net <-> ME
    Local
    # content #
    Cause is 2 to 30 bytes
    Call state
    Opt: Auxiliary states
    '''
    constructorList = [ie for ie in Header(3, 61)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('Cause', V='\0\x80'),
            Str('CallState', Pt='\0', Len=1, Repr='hex'),
            Type4_TLV('AuxState', T=0x24, V=AuxState())])
        self._post_init(with_options, **kwargs)

#section 9.3.28
class STATUS_ENQUIRY(Layer3):
    '''
    Net <-> ME
    Local
    '''
    constructorList = [ie for ie in Header(3, 52)]

#section 9.3.29
class STOP_DTMF(Layer3):
    '''
    ME -> Net
    Local
    '''
    constructorList = [ie for ie in Header(3, 49)]

#section 9.3.30
class STOP_DTMF_ACKNOWLEDGE(Layer3):
    '''
    Net -> ME
    Local
    '''
    constructorList = [ie for ie in Header(3, 50)]

#section 9.3.31
class USER_INFORMATION(Layer3):
    '''
    Net <-> ME
    Access
    # content #
    User-user (1 to 129 bytes)
    Opt: More data
    '''
    constructorList = [ie for ie in Header(3, 1)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_LV('UU', ReprName='User-User', V='\0'),
            Type2('MoreData', T=0xA0)])
        self._post_init(with_options, **kwargs)
#
