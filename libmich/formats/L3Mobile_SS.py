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

# TS 24.080 defines L3 signalling for Supplementary Services over 
# mobile networks
#
# section 3: 
# Message format and IE coding
#
# describes mobile L3 Supplementary Services messages
# each message composed of Information Element (IE)
# each IE is coded on a TypeX (T, TV, LV, TLV...) from 24.007
# each IE is mandatory, conditional, or optional in the message
#
# Messages are coded as Layer
# containing Bit, Int, Str or Layer for each IE

# section 3.4, Message Type
SS_dict = {
    32:"Clearing message - undefined",
    33:"Clearing message - undefined",
    34:"Clearing message - undefined",
    35:"Clearing message - undefined",
    36:"Clearing message - undefined",
    37:"Clearing message - undefined",
    38:"Clearing message - undefined",
    39:"Clearing message - undefined",
    40:"Clearing message - undefined",
    41:"Clearing message - undefined",
    42:"Clearing message - RELEASE COMPLETE",
    43:"Clearing message - undefined",
    44:"Clearing message - undefined",
    45:"Clearing message - undefined",
    46:"Clearing message - undefined",
    47:"Clearing message - undefined",
    48:"Misc - undefined",
    49:"Misc - undefined",
    50:"Misc - undefined",
    51:"Misc - undefined",
    52:"Misc - undefined",
    53:"Misc - undefined",
    54:"Misc - undefined",
    55:"Misc - undefined",
    56:"Misc - undefined",
    57:"Misc - undefined",
    58:"Misc - FACILITY",
    59:"Misc - REGISTER",
    60:"Misc - undefined",
    61:"Misc - undefined",
    62:"Misc - undefined",
    63:"Misc - undefined",
    }

########################
# Now, message formats #
########################
# TS 24.080, section 3.2
class Header(Layer):
    constructorList = [
        Bit('TI', ReprName='Transaction Identifier', \
            Pt=0, BitLen=4, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Bit('seq', ReprName='Sequence Number', Pt=0, BitLen=2, Repr='hum'),
        Bit('Type', BitLen=6, Dict=SS_dict, Repr='hum')]
    
    def __init__(self, prot=11, type=58):
        Layer.__init__(self)
        self.PD.Pt = prot
        self.Type.Pt = type

########################
# TS 24.080, section 2 #
# Facility IE          #
########################

# section 2.3
class SS_FACILITY(Layer3):
    '''
    ME -> Net
    # content #
    Facility (1 to max bytes)
    Facility is a container for ASN.1 BER content
    '''
    constructorList = [ie for ie in Header(11, 58)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([Type4_LV('Facility', V='\0')])
        self._post_init(with_options, **kwargs)

# section 2.4
class SS_REGISTER(Layer3):
    '''
    Net <-> ME
    # content, initiated by Net #
    Facility (0 to max bytes)
    Facility is a container for ASN.1 BER content
    # content, initiated by ME #
    Facility (0 to max bytes)
    Facility is a container for ASN.1 BER content
    Opt: SS version (0 or 1 byte)
    '''
    constructorList = [ie for ie in Header(11, 59)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        #self.extend([Type4_TLV('Facility', T=0x1C, V='')])
        self.extend([Type4_LV('Facility', V='')])
        if self._initiator != 'Net':
            # MS to network direction
            self.extend([Type4_TLV('SSversion', T=0x7F, V='\0')])
        self._post_init(with_options, **kwargs)

# section 2.5
class SS_RELEASE_COMPLETE(Layer3):
    '''
    Net <-> ME
    # content #
    Opt: Cause (2 to 30 bytes)
    Opt: Facility (0 to max bytes)
    Facility is a container for ASN.1 BER content
    '''
    constructorList = [ie for ie in Header(11, 42)]
    def __init__(self, with_options=True, **kwargs):
        Layer3.__init__(self)
        self.extend([ \
            Type4_TLV('Cause', T=0x08, V='\0\x80'),
            Type4_TLV('Facility', T=0x1C, V='')])
        self._post_init(with_options, **kwargs)

# IE in L3Mobile_IE.py
# Facility: 3.6
# SSversion: 3.7.2
