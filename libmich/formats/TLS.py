# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2014. Benoit Michau. ANSSI.
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
# * File Name : formats/TLS.py
# * Created : 2014-04-24
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

import time
from random import _urandom as urandom
#
from libmich.core.element import Str, Int, Bit, Layer, RawLayer, Block, show
from libmich.core.IANA_dict import IANA_dict

###########
# RFC5246 #
###########

###
# TLS global data block
###

class TLS(Block):
    
    def __init__(self):
        Block.__init__(self, Name='TLS')
        self.append( RecordLayer() )
    
    def parse(self, s=''):
        self.__init__()
        self.remove( 0 )
        while len(s) >= 5:
            self.parse_record(s)
            if isinstance(self[-1], RecordLayer):
                l = self[-1].length()
            elif isinstance(self[-2], RecordLayer):
                l = self[-2].length()
            else:
                break
            s = s[5+l:]
    
    def parse_record(self, s=''):
        #self.__init__()
        self.append( RecordLayer() )
        self[-1].set_hierarchy(0)
        self[-1].map(s)
        #
        t = self[-1].type()
        s = s[5:5+self[-1].length()]
        while len(s) >= 1:
            if t == 20:
                self.append( ChangeCipherSpec() )
            elif t == 21:
                self.append( Alert() )
            elif t == 22 and len(s) >= 4:
                hst = ord(s[0])
                if hst not in _HST_:
                    self.append( RawLayer() )
                self.append( _HST_[hst]() )
            elif t == 23:
                self.append( RawLayer() )
            else:
                break
            self[-1].set_hierarchy(1)
            self[-1].map(s)
            s = s[len(self[-1]):]


###
# TLS various unary structs
###

VersionMajor_dict = {
    3 : 'TLS'
    }
VersionMinor_dict = {
    1 : '1.0',
    2 : '1.1',
    3 : '1.2'
    }

class ProtocolVersion(Layer):
    constructorList = [
        Int('major', Pt=3, Type='uint8', Dict=VersionMajor_dict),
        Int('minor', Pt=1, Type='uint8', Dict=VersionMinor_dict)
        ]

class Random(Layer):
    constructorList = [
        Int('gmt_unix_time', Pt=0, Type='uint32'),
        Str('random_bytes', Pt='', Len=28, Repr='hex'),
        ]
    def __init__(self):
        Layer.__init__(self)
        self.gmt_unix_time.PtFunc = lambda x: int(time.time())
        self.random_bytes.PtFunc = lambda x: urandom(28)

class SessionID(Layer):
    constructorList = [
        Int('sid_length', Pt=0, Type='uint8'),
        Str('sid', Pt=32*'\0', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.sid_length.PtFunc = lambda x: len(self.sid)
        self.sid.Len = self.sid_length
        self.sid.LenFunc = lambda sidl: int(sidl)

CipherSuite_dict = IANA_dict({
    0x0000 : "TLS_NULL_WITH_NULL_NULL",
    0x0001 : "TLS_RSA_WITH_NULL_MD5",
    0x0002 : "TLS_RSA_WITH_NULL_SHA",
    0x0003 : "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004 : "TLS_RSA_WITH_RC4_128_MD5",
    0x0005 : "TLS_RSA_WITH_RC4_128_SHA",
    0x0006 : "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0007 : "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x0008 : "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009 : "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A : "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x000B : "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x000C : "TLS_DH_DSS_WITH_DES_CBC_SHA",
    0x000D : "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    0x000E : "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x000F : "TLS_DH_RSA_WITH_DES_CBC_SHA",
    0x0010 : "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0011 : "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0012 : "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0013 : "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0014 : "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0015 : "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016 : "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0017 : "TLS_DHB5_WITH_DES_CBC_MD5",
    0x0023 : "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    0x0024 : "TLS_KRB5_WITH_RC4_128_MD5",
    0x0025 : "TLS_KRB5_WITH_IDEA_CBC_MD5",
    0x0026 : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    0x0027 : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    0x0028 : "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    0x0029 : "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    0x002A : "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    0x002B : "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    0x002C : "TLS_PSK_WITH_NULL_SHA",
    0x002D : "TLS_DHE_PSK_WITH_NULL_SHA",
    0x002E : "TLS_RSA_PSK_WITH_NULL_SHA",
    0x002F : "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0030 : "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    0x0031 : "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    0x0032 : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033 : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034 : "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035 : "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0036 : "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    0x0037 : "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    0x0038 : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039 : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003A : "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x003B : "TLS_RSA_WITH_NULL_SHA256",
    0x003C : "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D : "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003E : "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    0x003F : "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    0x0040 : "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0041 : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0042 : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x0043 : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0044 : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x0045 : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0046 : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    0x0047 : "Reserved",
    0x0050 : "Reserved",
    0x0059 : "Reserved",
    0x005D : "Unassigned",
    0x0060 : "Reserved",
    0x0067 : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x0068 : "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    0x0069 : "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    0x006A : "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006B : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x006C : "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0x006D : "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x006E : "Unassigned",
    0x0084 : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0085 : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0086 : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0087 : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0088 : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0089 : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    0x008A : "TLS_PSK_WITH_RC4_128_SHA",
    0x008B : "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008C : "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D : "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x008E : "TLS_DHE_PSK_WITH_RC4_128_SHA",
    0x008F : "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0090 : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    0x0091 : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    0x0092 : "TLS_RSA_PSK_WITH_RC4_128_SHA",
    0x0093 : "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0094 : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    0x0095 : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    0x0096 : "TLS_RSA_WITH_SEED_CBC_SHA",
    0x0097 : "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    0x0098 : "TLS_DH_RSA_WITH_SEED_CBC_SHA",
    0x0099 : "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    0x009A : "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    0x009B : "TLS_DH_anon_WITH_SEED_CBC_SHA",
    0x009C : "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D : "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E : "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F : "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A0 : "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
    0x00A1 : "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
    0x00A2 : "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3 : "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x00A4 : "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    0x00A5 : "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    0x00A6 : "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0x00A7 : "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0x00A8 : "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9 : "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0x00AA : "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    0x00AB : "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    0x00AC : "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    0x00AD : "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    0x00AE : "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x00AF : "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0x00B0 : "TLS_PSK_WITH_NULL_SHA256",
    0x00B1 : "TLS_PSK_WITH_NULL_SHA384",
    0x00B2 : "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    0x00B3 : "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    0x00B4 : "TLS_DHE_PSK_WITH_NULL_SHA256",
    0x00B5 : "TLS_DHE_PSK_WITH_NULL_SHA384",
    0x00B6 : "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    0x00B7 : "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    0x00B8 : "TLS_RSA_PSK_WITH_NULL_SHA256",
    0x00B9 : "TLS_RSA_PSK_WITH_NULL_SHA384",
    0x00BA : "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BB : "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BC : "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BD : "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BE : "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BF : "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    0x00C0 : "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C1 : "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C2 : "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C3 : "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C4 : "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C5 : "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C6 : "Unassigned",
    0x00FF : "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x0100 : "Unassigned",
    0xC001 : "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002 : "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003 : "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004 : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005 : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC006 : "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007 : "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008 : "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009 : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00B : "TLS_ECDH_RSA_WITH_NULL_SHA",
    0xC00C : "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D : "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC010 : "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011 : "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012 : "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013 : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014 : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015 : "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC016 : "TLS_ECDH_anon_WITH_RC4_128_SHA",
    0xC017 : "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018 : "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019 : "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC01A : "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    0xC01B : "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC01C : "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    0xC01D : "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    0xC01E : "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    0xC01F : "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    0xC020 : "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    0xC021 : "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    0xC022 : "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    0xC023 : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024 : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025 : "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026 : "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027 : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028 : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029 : "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A : "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B : "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C : "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D : "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E : "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F : "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030 : "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031 : "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032 : "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC033 : "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    0xC034 : "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0xC035 : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036 : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xC037 : "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    0xC038 : "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    0xC039 : "TLS_ECDHE_PSK_WITH_NULL_SHA",
    0xC03A : "TLS_ECDHE_PSK_WITH_NULL_SHA256",
    0xC03B : "TLS_ECDHE_PSK_WITH_NULL_SHA384",
    0xC03C : "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC03D : "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC03E : "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC03F : "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC040 : "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC041 : "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC042 : "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC043 : "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC044 : "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC045 : "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC046 : "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
    0xC047 : "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
    0xC048 : "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC049 : "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04A : "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC04B : "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04C : "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04D : "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC04E : "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04F : "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC050 : "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC051 : "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC052 : "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC053 : "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC054 : "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC055 : "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC056 : "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC057 : "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC058 : "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC059 : "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC05A : "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
    0xC05B : "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
    0xC05C : "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05D : "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC05E : "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05F : "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC060 : "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC061 : "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC062 : "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC063 : "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC064 : "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC065 : "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC066 : "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC067 : "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC068 : "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC069 : "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC06A : "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06B : "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06C : "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06D : "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06E : "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06F : "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC070 : "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC071 : "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC072 : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC073 : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC074 : "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC075 : "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC076 : "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC077 : "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC078 : "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC079 : "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC07A : "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07B : "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07C : "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07D : "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07E : "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07F : "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC080 : "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC081 : "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC082 : "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC083 : "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC084 : "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
    0xC085 : "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
    0xC086 : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC087 : "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC088 : "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC089 : "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08A : "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08B : "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08C : "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08D : "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08E : "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08F : "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC090 : "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC091 : "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC092 : "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC093 : "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC094 : "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC095 : "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC096 : "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC097 : "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC098 : "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC099 : "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09A : "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC09B : "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09C : "TLS_RSA_WITH_AES_128_CCM",
    0xC09D : "TLS_RSA_WITH_AES_256_CCM",
    0xC09E : "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F : "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0A0 : "TLS_RSA_WITH_AES_128_CCM_8",
    0xC0A1 : "TLS_RSA_WITH_AES_256_CCM_8",
    0xC0A2 : "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    0xC0A3 : "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    0xC0A4 : "TLS_PSK_WITH_AES_128_CCM",
    0xC0A5 : "TLS_PSK_WITH_AES_256_CCM",
    0xC0A6 : "TLS_DHE_PSK_WITH_AES_128_CCM",
    0xC0A7 : "TLS_DHE_PSK_WITH_AES_256_CCM",
    0xC0A8 : "TLS_PSK_WITH_AES_128_CCM_8",
    0xC0A9 : "TLS_PSK_WITH_AES_256_CCM_8",
    0xC0AA : "TLS_PSK_DHE_WITH_AES_128_CCM_8",
    0xC0AB : "TLS_PSK_DHE_WITH_AES_256_CCM_8",
    0xC0AC : "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD : "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE : "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF : "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
    })

class CipherSuite(Layer):
    constructorList = [
        Int('cs_length', Pt=0, Type='uint16'),
        ]
    def __init__(self, *args):
        Layer.__init__(self)
        self.cs_length.PtFunc = lambda x: len(self[1:])
        self.add_cs(*args)
     
    def map(self, s=''):
        Layer.__init__(self)
        Layer.map(self, s)
        s = s[2:2+self.cs_length()]
        while len(s) >= 2:
            self.append( Int('cs', Type='uint16', Dict=CipherSuite_dict) )
            self[-1].map(s)
            s = s[2:]
    
    def add_cs(self, *args):
        for i in filter( lambda a: isinstance(a, int), args ):
            self.append( Int('cs', Pt=i, Type='uint16', Dict=CipherSuite_dict) )

CompressionMethod_dict = {
    0 : 'null'
    }

class CompressionMethod(Layer):
    constructorList = [
        Int('cm_length', Pt=0, Type='uint8')
        ]
    def __init__(self, *args):
        Layer.__init__(self)
        self.cm_length.PtFunc = lambda x: len(self[1:])
        self.add_cm(*args)
    
    def map(self, s=''):
        Layer.__init__(self)
        Layer.map(self, s)
        s = s[1:1+self.cm_length()]
        while len(s) >= 1:
            self.append( Int('cm', Type='uint8', Dict=CompressionMethod_dict) )
            self[-1].map(s)
            s = s[2:]
    
    def add_cm(self, *args):
        for i in filter( lambda a: isinstance(a, int), args ):
            self.append( Int('cm', Pt=i, Type='uint8', Dict=CompressionMethod_dict) )

Extension_dict = {
    0x0000 : 'server_name',
    0x0005 : 'status_request',
    0x000a : 'elliptic_curves',
    0x000b : 'ec_point_formats',
    0x000d : 'signature_algorithms',
    0x0023 : 'SessionTicket TLS',
    0x3374 : 'next_protocol_negotiation',
    0xff01 : 'renegotiation_info',
    }

class Extension(Layer):
    constructorList = [
        Int('type', Pt=0, Type='uint16', Dict=Extension_dict),
        Int('length', Type='uint16'),
        Str('data', Pt='')
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.data
        self.length.PtFunc = lambda d: len(d)
        self.data.Len = self.length
        self.data.LenFunc = lambda l: int(l)

#
class CertificateList(Layer):
    constructorList = [
        Int('certs_length', Pt=0, Type='uint24'),
        ]
    def __init__(self, *args):
        Layer.__init__(self)
        self.certs_length.PtFunc = lambda x: len(self[1:])
        self.add_cert(*args)
     
    def map(self, s=''):
        self.__init__()
        Layer.map(self, s)
        s = s[3:3+self.certs_length()]
        while len(s) >= 3:
            self.append( Int('cert_length', Pt=0, Type='uint24') )
            self[-1].map(s)
            self.append( Str('cert', Pt='') )
            self[-1].map(s[3:3+int(self[-2])])
            self[-2].PtFunc = lambda x: len(self[-1])
            self[-1].Len = self[-2]
            self[-1].LenFunc = lambda l: int(l)
            s = s[3+int(self[-2]):]
    
    def add_cert(self, *args):
        for c in filter( lambda a: hasattr(a, __str__), args ):
            self.append( Int('cert_length', Pt=0, Type='uint24') )
            self.append( Str('cert', Pt=c) )
            self[-2].PtFunc = lambda x: len(self[-1])
            self[-1].Len = self[-2]
            self[-1].LenFunc = lambda l: int(l)

###
# TLS Record structs, section 6.2
###

ContentType_dict = {
    20 : 'change_cipher_spec',
    21 : 'alert',
    22 : 'handshake',
    23 : 'application_data'
    }

class RecordLayer(Layer):
    constructorList = [
        Int('type', Pt=0, Type='uint8', Dict=ContentType_dict),
        ProtocolVersion(major=3, minor=1),
        Int('length', Pt=0, Type='uint16'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.type.PtFunc = self.get_content_type
        self.length.PtFunc = lambda x: len(self.get_payload())
    
    def get_content_type(self, x):
        pay = self.get_payload()
        if isinstance(pay, Handshake):
            return 22
        elif isinstance(pay, Alert):
            return 21
        elif isinstance(pay, ChangeCipherSpec):
            return 20
        else:
            return 23

###
# TLS Alerts struct, section
###

AlertLevel_dict = {
    1 : 'warning',
    2 : 'fatal'
    }
AlertDescr_dict = {
    0 : 'close_notify',
    10 : 'unexpected_message',
    20 : 'bad_record_mac',
    21 : 'decryption_failed_RESERVED',
    22 : 'record_overflow',
    30 : 'decompression_failure',
    40 : 'handshake_failure',
    41 : 'no_certificate_RESERVED',
    42 : 'bad_certificate',
    43 : 'unsupported_certificate',
    44 : 'certificate_revoked',
    45 : 'certificate_expired',
    46 : 'certificate_unknown',
    47 : 'illegal_parameter',
    48 : 'unknown_ca',
    49 : 'access_denied',
    50 : 'decode_error',
    51 : 'decrypt_error',
    60 : 'export_restriction_RESERVED',
    70 : 'protocol_version',
    71 : 'insufficient_security',
    80 : 'internal_error',
    90 : 'user_canceled',
    100 : 'no_renegotiation',
    110 : 'unsupported_extension'
    }

class Alert(RawLayer):
    constructorList = [
        Int('level', Pt=0, Type='uint8', Dict=AlertLevel_dict),
        Int('description', Pt=0, Type='uint8', Dict=AlertDescr_dict),
        ]

###
# TLS Change cipher spec struct, section
###

class ChangeCipherSpec(RawLayer):
    constructorList = [
        Int('type', Pt=1, Type='uint8')
        ]

###
# TLS Handshake structs, section 7.4
###

HandshakeType_dict = {
    0 : 'hello_request',
    1 : 'client_hello',
    2 : 'server_hello',
    3 : 'hello_verify_request',
    4 : 'NewSessionTicket',
    11 : 'certificate',
    12 : 'server_key_exchange',
    13 : 'certificate_request',
    14 : 'server_hello_done',
    15 : 'certificate_verify',
    16 : 'client_key_exchange',
    20 : 'finished',
    21 : 'certificate_url',
    22 : 'certificate_status',
    23 : 'supplemental_data'
    }

# generic class
class Handshake(RawLayer):
    constructorList = [
        Int('msg_type', Pt=0, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24'),
        Str('data', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.PtFunc = lambda x: len(self[2:])

# specific classes
class HelloRequest(Handshake):
    constructorList = [
        Int('msg_type', Pt=0, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24')
        ]

class ClientHello(Handshake):
    constructorList = [
        Int('msg_type', Pt=1, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24'),
        ProtocolVersion(major=3, minor=1),
        Random(),
        SessionID(),
        CipherSuite(0),
        CompressionMethod(0),
        ]
    
    def map(self, s=''):
        Layer.map(self, s)
        # map extensions
        if len(s) >= len(self)+2:
            s = s[len(self):]
            # add extensions length
            extl = Int('ext_length', Type='uint16')
            extl.map(s)
            self.append( extl )
            s = s[2:]
            l = extl()
            if len(s) > l:
                # truncate the buffer
                s = s[:l]
            elif len(s) < l:
                # error
                return
            # add extensions
            while s:
                self.append( Extension() )
                self[-1].map(s)
                s = s[len(self[-1]):]
    
    def add_ext(self, ext=Extension()):
        if self[-1].CallName == 'cm':
            self.append( Int('ext_length', Pt=0, Type='uint16') )
            self[-1].PtFunc = lambda x: len(self[7:])
        if isinstance(ext, Extension):
            self.append(ext)

#
class ServerHello(Handshake):
    constructorList = [
        Int('msg_type', Pt=2, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24'),
        ProtocolVersion(major=3, minor=1),
        Random(),
        SessionID(),
        Int('cs', Pt=0, Type='uint16', Dict=CipherSuite_dict),
        Int('cm', Pt=0, Type='uint8', Dict=CompressionMethod_dict),
        ]
    
    def map(self, s=''):
        Layer.map(self, s)
        # map extensions
        if len(s) >= len(self)+2:
            s = s[len(self):]
            # add extensions length
            extl = Int('ext_length', Type='uint16')
            extl.map(s)
            self.append( extl )
            s = s[2:]
            l = extl()
            if len(s) > l:
                # truncate the buffer
                s = s[:l]
            elif len(s) < l:
                # error
                return
            # add extensions
            while s:
                self.append( Extension() )
                self[-1].map(s)
                s = s[len(self[-1]):]
    
    def add_ext(self, ext=Extension()):
        if self[-1].CallName == 'cm':
            self.append( Int('ext_length', Pt=0, Type='uint16') )
            self[-1].PtFunc = lambda x: len(self[7:])
        if isinstance(ext, Extension):
            self.append(ext)


class Certificate(Handshake):
    constructorList = [
        Int('msg_type', Pt=11, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24'),
        CertificateList()
        ]

class ServerKeyExchange(Handshake):
    constructorList = [
        Int('msg_type', Pt=12, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24'),
        # TODO
        ]

class ServerHelloDone(Handshake):
    constructorList = [
        Int('msg_type', Pt=14, Type='uint8', Dict=HandshakeType_dict),
        Int('length', Pt=0, Type='uint24')
        ]

        
_HST_ = {
    0 : HelloRequest,
    1 : ClientHello,
    2 : ServerHello,
    3 : Handshake,
    4 : Handshake,
    11 : Certificate,
    12 : Handshake,
    13 : Handshake,
    14 : ServerHelloDone,
    15 : Handshake,
    16 : Handshake,
    20 : Handshake,
    21 : Handshake,
    22 : Handshake,
    23 : Handshake
    }
#