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
# * File Name : formats/EAP.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# generic imports
from libmich.core.element import Str, Int, Layer, Block
from libmich.core.IANA_dict import IANA_dict

code_dict = IANA_dict({
    1 : "Request",
    2 : "Response",
    3 : "Success",
    4 : "Failure",
    5 : "Initiate",
    6 : "Finish",
    7  : "Unassigned",
    255 : "Unassigned",
    })
    
method_dict = IANA_dict({
    0 : "Reserved",
    1 : "Identity",
    2 : "Notification",
    3 : "Legacy Nak",
    4 : ("MD5-Challenge", "md5"),
    5 : ("One-Time Password", "otp"),
    6 : ("Generic Token Card", "gtc"),
    7 : "Allocated",
    8 : "Allocated",
    9 : "RSA Public Key Authentication",
    10 : "DSS Unilateral",
    11 : "KEA",
    12 : "KEA-VALIDATE",
    13 : "EAP-TLS",
    14 : "Defender Token (AXENT)",
    15 : "RSA Security SecurID EAP",
    16 : "Arcot Systems EAP",
    17 : "EAP-Cisco Wireless",
    18 : ("GSM Subscriber Identity Modules", "sim"),
    19 : "SRP-SHA1",
    20 : "Unassigned",
    21 : "EAP-TTLS",
    22 : "Remote Access Service",
    23 : ("EAP-AKA Authentication", "aka"),
    24 : "EAP-3Com Wireless",
    25 : "PEAP",
    26 : "MS-EAP-Authentication",
    27 : "Mutual Authentication w/Key Exchange (MAKE)",
    28 : "CRYPTOCard",
    29 : "EAP-MSCHAP-V2",
    30 : "DynamID",
    31 : "Rob EAP",
    32 : "Protected One-Time Password",
    33 : "MS-Authentication-TLV",
    34 : "SentriNET",
    35 : "EAP-Actiontec Wireless",
    36 : "Cogent Systems Biometrics Authentication EAP",
    37 : "AirFortress EAP",
    38 : "EAP-HTTP Digest",
    39 : "SecureSuite EAP",
    40 : "DeviceConnect EAP",
    41 : "EAP-SPEKE",
    42 : "EAP-MOBAC",
    43 : "EAP-FAST",
    44 : "ZoneLabs EAP (ZLXEAP)",
    45 : "EAP-Link",
    46 : "EAP-PAX",
    47 : "EAP-PSK",
    48 : "EAP-SAKE",
    49 : "EAP-IKEv2",
    50 : ("EAP-AKA\'", "aka-kdf"),
    51 : "EAP-GPSK",
    52 : "Unassigned",
    254 : "Reserved for the Expanded Type",
    255 : "Experimental",
    })

# specific imports
from libmich.formats.EAPAKA import SIMAKAAttribute

# EAP protocol basic description
class EAP(Block):
    
    def __init__(self, C=1, I=0):
        Block.__init__(self, Name="EAP")
        self.append( EAP_hdr(C=C, I=I) )
    
    def parse(self, s):
        self[0].map(s)
        s = s[ 4 : self[0].L.Val ]
        if len(s) > 0:
            self.append( EAP_type() )
            self[-1].hierarchy = 1
            self[-1].data.Len = len(s)-1
            self[-1].map(s)


class EAP_hdr(Layer):
    constructorList = [
        Int(CallName="C", ReprName="Code", Type="uint8", Dict=code_dict),
        Int(CallName="I", ReprName="Identifier", Type="uint8"),
        Int(CallName="L", ReprName="Length", Type="uint16"),
        ]
    
    def __init__(self, C=1, I=0):
        Layer.__init__(self, CallName='hdr', ReprName='EAP header')
        self.C.Pt = C
        self.I.Pt = I
        self.L.Pt = self.get_payload
        self.L.PtFunc = lambda Pt: len(Pt())+4

        
class EAP_type(Layer):
    constructorList = [
        Int(CallName="type", ReprName="Type", Type="uint8", Dict=method_dict),
        Str(CallName="data", ReprName="Data"),
        ]
    
    def __init__(self, type=1, data=''):
        Layer.__init__(self, CallName='type', ReprName='EAP type')
        self.type.Pt = type
        self.data.Pt = data

class TV():
    constructorList = [
        Int(CallName="T", ReprName="Type", Type="uint8"),
        Str(CallName="V", ReprName="Value", Len=3),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='TV', ReprName='EAP TV attribute')
        
class TLV(Layer):
    constructorList = [
        Int(CallName="T", ReprName="Type", Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="V", ReprName="Value"),
        ]
    
    def __init__(self, V=None):
        Layer.__init__(self, CallName='TLV', ReprName='EAP TLV attribute')
        self.V.Pt = V
        self.V.PtFunc = lambda Value: self.pad( str(Value) )
        self.V.Len = self.L
        self.V.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.V
        self.L.PtFunc = lambda Value: self.len4( len(Value) + 2 )
        
    def pad(self, s='', const=2, padder='\x00'):
        extra = ( len(s) + const ) % 4
        if extra == 0: return s
        else: return s + (4-extra) * padder
    
    def len4(self, slen):
        if slen % 4: return (slen/4)+1
        else: return slen/4
