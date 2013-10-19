# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2011. Benoit Michau. ANSSI.
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
# * File Name : formats/UICC_SecChan.py
# * Created : 2013-08-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
# Implementing parts of ETSI TS 102.225
# Secured Packet Structure for UICC

from binascii import *
from libmich.core.element import *
from libmich.core.IANA_dict import IANA_dict

#
SPI_intt_dict = {
    0 : 'No integrity check',
    1 : 'Redundancy check',
    2 : 'Cryptographic checksum',
    3 : 'Digital signature',
    }
SPI_cntt_dict = {
    0 : 'No counter available',
    1 : 'Counter available, no replay checking',
    2 : 'Process only if counter over receiver value',
    3 : 'Process only if counter by 1 over receiver value',
    }
SPI_sms_dict = {
    0 : 'PoR response using SMS-DELIVER-REPORT',
    1 : 'PoR response using SMS-SUBMIT',
    }
SPI_porc_dict = {
    0 : 'PoR response shall not be ciphered',
    1 : 'PoR response shall be ciphered'
    }
SPI_pori_dict = {
    0 : 'No integrity applied to PoR response',
    1 : 'Redundancy check applied to PoR response',
    2 : 'Cryptographic checksum applied to PoR response',
    3 : 'Digital signature applied to PoR response',
    }
SPI_porr_dict = {
    0 : 'No PoR response',
    1 : 'PoR to be sent',
    2 : 'PoR to be sent on error',
    3 : 'Reserved',
    }

class SPI(Layer):
    constructorList = [
        Bit('reserved', Pt=0, BitLen=3, Repr='hex'),
        Bit('cnt_type', Pt=0, BitLen=2, Repr='hum', Dict=SPI_cntt_dict),
        Bit('ciph_type', Pt=0, BitLen=1, Repr='hum', 
            Dict={0:'No ciphering', 1:'Ciphering'}),
        Bit('int_type', Pt=0, BitLen=2, Repr='hum', Dict=SPI_intt_dict),
        Bit('reserved', Pt=0, BitLen=2, Repr='hex'),
        Bit('sms', Pt=0, BitLen=1, Repr='hum'),
        Bit('por_ciph', Pt=0, BitLen=1, Repr='hum', Dict=SPI_porc_dict),
        Bit('por_int', Pt=0, BitLen=2, Repr='hum', Dict=SPI_pori_dict),
        Bit('por_req', Pt=0, BitLen=2, Repr='hum', Dict=SPI_porr_dict),
        ]

KLc_algt_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'DES',
    2 : 'AES',
    3 : 'proprietary',
    }
KLc_des_dict = {
    0 : 'DES in CBC mode', # before release 8
    1 : 'Triple-DES in outer-CBC mode with 2 keys',
    2 : 'Triple-DES in outer-CBC mode with 3 keys',
    3 : 'DES in ECB mode', # before release 8
    }
KLc_aes_dict = {
    0 : 'AES in CBC mode',
    1 : 'Reserved',
    2 : 'Reserved',
    3 : 'Reserved',
    }
class KIc(Layer):
    constructorList = [
        Bit('keys', Pt=0, BitLen=4, Repr='hex'),
        Bit('alg_subtype', Pt=0, BitLen=2, Repr='hum'),
        Bit('alg_type', Pt=0, BitLen=2, Repr='hum', Dict=KLc_algt_dict)
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.alg_subtype.Dict = self.alg_type
        self.alg_subtype.DictFunc = self._chk_algt
    def _chk_algt(self, t):
        t = self.alg_type()
        if t == 1: return KLc_des_dict
        elif t == 2: return KLc_aes_dict
        else: return {}

#
KID_CC_algt_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'DES',
    2 : 'AES',
    3 : 'proprietary',
    }
KID_CC_des_dict = {
    0 : 'DES in CBC mode', # before release 8
    1 : 'Triple-DES in outer-CBC mode with 2 keys',
    2 : 'Triple-DES in outer-CBC mode with 3 keys',
    3 : 'Reserved',
    }
KID_CC_aes_dict = {
    0 : 'AES in CMAC mode',
    1 : 'Reserved',
    2 : 'Reserved',
    3 : 'Reserved',
    }
class KID_CC(Layer):
    constructorList = [
        Bit('keys', Pt=0, BitLen=4, Repr='hex'),
        Bit('alg_subtype', Pt=0, BitLen=2, Repr='hum'),
        Bit('alg_type', Pt=0, BitLen=2, Repr='hum', Dict=KID_CC_algt_dict)
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.alg_subtype.Dict = self.alg_type
        self.alg_subtype.DictFunc = self._chk_algt
    def _chk_algt(self, t):
        t = self.alg_type()
        if t == 1: return KID_CC_des_dict
        elif t == 2: return KID_CC_aes_dict
        else: return {}
#
KID_RC_algt_dict = {
    0 : 'Algorithm known implicitely',
    1 : 'CRC',
    2 : 'Reserved',
    3 : 'proprietary',
    }
KID_RC_crc_dict = {
    0 : 'CRC-16',
    1 : 'CRC-32',
    2 : 'Reserved',
    3 : 'Reserved',
    }
class KID_RC(Layer):
    constructorList = [
        Bit('GP_specific', Pt=0, BitLen=4, Repr='hex'),
        Bit('alg_subtype', Pt=0, BitLen=2, Repr='hum'),
        Bit('alg_type', Pt=0, BitLen=2, Repr='hum', Dict=KID_RC_algt_dict)
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.alg_subtype.Dict = self.alg_type
        self.alg_subtype.DictFunc = self._chk_algt
    def _chk_algt(self, t):
        t = self.alg_type()
        if t == 1: return KID_RC_crc_dict
        else: return {}

class KID(Layer):
    constructorList = [
        Bit('keys', Pt=0, BitLen=4, Repr='hex'),
        Bit('alg_subtype', Pt=0, BitLen=2, Repr='hum'),
        Bit('alg_type', Pt=0, BitLen=2, Repr='hum')
        ]

class CmdPacket(Layer):
    constructorList = [
        Int('CPI', ReprName='Command Packet Identifier', Pt=0, Type='uint8'),
        # command packet length is actually in BER-TLV format, could be > 1 byte
        Int('CPL', ReprName='Command Packet Length', Pt=0, Type='uint8'),
        # here starts the Command Header
        Int('CHI', ReprName='Command Header Identifier', Pt=0, Type='uint8'),
        # command header length is actually in BER-TLV format, could be > 1 byte
        Int('CHL', ReprName='Command Header Length', Pt=0, Type='uint8'),
        SPI(), # 2 bytes
        KIc(), # 1 byte
        # 3 alternatives for KID, 1 byte each: KID, KID_RC, KID_CC
        KID(),
        #
        Str('TAR', ReprName='Toolkit Application Reference', Pt=3*'\0', \
            Len=3, Repr='hex'), # 3 bytes, check 101.220
        # this is an uint40 counter for replay protection
        Str('CNTR', Pt=5*'\0', Len=5, Repr='hex'),
        # number of padding bytes in case of ciphered data
        Int('PCNTR', ReprName='Padding Counter', Pt=0, Type='uint8'),
        # variable length, check CHL
        Str('Int', ReprName='Integrity check', Pt='', Repr='hex'),
        # here stops the Command Header
        Str('Data', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # Command Header Length and integrity field
        self.CHL.Pt = self.Int
        self.CHL.PtFunc = lambda i: 13+len(i)
        self.Int.Len = self.CHL
        self.Int.LenFunc = lambda c: max(0, c()-13)
        # Command Packet Length and data field
        self.CPL.Pt = (self.CHL, self.Data)
        self.CPL.PtFunc = lambda (c, d): c()+len(d)+1
        self.Data.Len = (self.CPL, self.CHL)
        self.Data.LenFunc = lambda (cpl, chl): max(0, cpl()-chl()-1)
    #
    def map(self, s=''):
        # reinitialize the Secured Packet format
        if hasattr(self, 'KID_CC'):
            self.replace(self.KID_CC, Str('KID', ReprName='Key Identifier', 
                                          Pt='\0', Len=1, Repr='hex'))
        elif hasattr(self, 'KID_RC'):
            self.replace(self.KID_RC, Str('KID', ReprName='Key Identifier', 
                                          Pt='\0', Len=1, Repr='hex'))
        # map it normally
        Layer.map(self, s)
        # check for detailed KID interpretation
        #if self.SPI.int_type() == 2:
        if self.SPI.int_type() != 1:
            kid = KID_CC()
            kid.map(self.KID())
            self.replace(self.KID, kid)
        elif self.SPI.int_type() == 1:
            kid = KID_RC()
            kid.map(self.KID())
            self.replace(self.KID, kid)
#
RespStatus_dict = IANA_dict({
    0x00 : 'PoR OK',
    0x01 : 'RC/CC/DS failed',
    0x02 : 'CNTR low',
    0x03 : 'CNTR high',
    0x04 : 'CNTR Blocked',
    0x05 : 'Ciphering error',
    0x06 : 'Unidentified security error. This code is for the case where the Receiving Entity cannot correctly ' \
           'interpret the Command Header and the Response Packet is sent unciphered with no RC/CC/DS ',
    0x07 : 'Insufficient memory to process incoming message',
    0x08 : 'This status code "more time" should be used if the Receiving Entity/Application needs more time ' \
           'to process the Command Packet due to timing constraints. In this case a later Response Packet ' \
           'should be returned to the Sending Entity once processing has been completed',
    0x09 : 'TAR Unknown',
    0x0A : 'Insufficient security level',
    0x0B : 'Reserved for 3GPP (see TS 131 115 [5])',
    0x0C : 'Reserved for 3GPP (see TS 131 115 [5])',
    0x0D : 'to 0xBF Reserved for future use',
    0xC0 : 'to 0xFE Reserved for proprietary use',
    0xFF : 'Reserved for future use',
    })

class RespPacket(Layer):
    constructorList = [
        Int('RPI', ReprName='Response Packet Identifier', Pt=0, Type='uint8'),
        Int('RPL', ReprName='Response Packet Length', Pt=0, Type='uint8'),
        # here starts the Response Header
        Int('RHI', ReprName='Response Header Identifier', Pt=0, Type='uint8'),
        Int('RHL', ReprName='Response Header Length', Pt=0, Type='uint8'),
        Str('TAR', ReprName='Toolkit Application Reference', Pt=3*'\0', \
            Len=3, Repr='hex'), # 3 bytes, check 101.220
        Str('CNTR', Pt=5*'\0', Len=5, Repr='hex'),
        Int('PCNTR', ReprName='Padding Counter', Pt=0, Type='uint8'),
        Int('Status', Pt=0, Type='uint8', Dict=RespStatus_dict),
        Str('Int', ReprName='Integrity check', Pt='', Repr='hex'),
        # here stops the Response Header
        Str('Data', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # Response Header Length and integrity field
        self.RHL.Pt = self.Int
        self.RHL.PtFunc = lambda i: 9+len(i)
        self.Int.Len = self.RHL
        self.Int.LenFunc = lambda c: max(0, c()-9)
        # Response Packet Length and data field
        self.RPL.Pt = (self.RHL, self.Data)
        self.RPL.PtFunc = lambda (r, d): r()+len(d)+1
        self.Data.Len = (self.RPL, self.RHL)
        self.Data.LenFunc = lambda (rpl, rhl): max(0, rpl()-rhl()-1)
#

class SMSPP_CmdPacket(Layer):
    constructorList = [
        # command packet length is actually in BER-TLV format, could be > 1 byte
        Int('CPL', ReprName='Command Packet Length', Pt=0, Type='uint16'),
        # here starts the Command Header
        # command packet length is actually in BER-TLV format, could be > 1 byte
        Int('CHL', ReprName='Command Header Length', Pt=0, Type='uint8'),
        SPI(), # 2 bytes
        KIc(), # 1 byte
        # 3 alternatives for KID, 1 byte each: KID, KID_RC, KID_CC
        KID(),
        #
        Str('TAR', ReprName='Toolkit Application Reference', Pt=3*'\0', \
            Len=3, Repr='hex'), # 3 bytes, check 101.220
        # this is an uint40 counter for replay protection
        Str('CNTR', Pt=5*'\0', Len=5, Repr='hex'),
        # number of padding bytes in case of ciphered data
        Int('PCNTR', ReprName='Padding Counter', Pt=0, Type='uint8'),
        # variable length, check CHL
        Str('Int', ReprName='Integrity check', Pt='', Repr='hex'),
        # here stops the Command Header
        Str('Data', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # Command Header Length and integrity field
        self.CHL.Pt = self.Int
        self.CHL.PtFunc = lambda i: 13+len(i)
        self.Int.Len = self.CHL
        self.Int.LenFunc = lambda c: max(0, c()-13)
        # Command Packet Length and data field
        self.CPL.Pt = (self.CHL, self.Data)
        self.CPL.PtFunc = lambda (c, d): c()+len(d)+1
        self.Data.Len = (self.CPL, self.CHL)
        self.Data.LenFunc = lambda (cpl, chl): max(0, cpl()-chl()-1)
        # SPI b6 for SMSPP
        self.SPI.sms.Dict=SPI_sms_dict
    #
    def map(self, s=''):
        # reinitiatize the Secured Packet format
        if hasattr(self, 'KID_CC'):
            self.replace(self.KID_CC, Str('KID', ReprName='Key Identifier', 
                                          Pt='\0', Len=1, Repr='hex'))
        elif hasattr(self, 'KID_RC'):
            self.replace(self.KID_RC, Str('KID', ReprName='Key Identifier', 
                                          Pt='\0', Len=1, Repr='hex'))
        # map it normally
        Layer.map(self, s)
        # check for detailed KID interpretation
        #if self.SPI.int_type() == 2:
        if self.SPI.int_type() != 1:
            kid = KID_CC()
            kid.map(self.KID())
            self.replace(self.KID, kid)
        elif self.SPI.int_type() == 1:
            kid = KID_RC()
            kid.map(self.KID())
            self.replace(self.KID, kid)
#
class SMSPP_RespPacket(Layer):
    constructorList = [
        Int('RPL', ReprName='Response Packet Length', Pt=0, Type='uint16'),
        # here starts the Response Header
        Int('RHL', ReprName='Response Header Length', Pt=0, Type='uint8'),
        Str('TAR', ReprName='Toolkit Application Reference', Pt=3*'\0',
            Len=3, Repr='hex'), # 3 bytes, check 101.220
        Str('CNTR', Pt=5*'\0', Len=5, Repr='hex'),
        Int('PCNTR', ReprName='Padding Counter', Pt=0, Type='uint8'),
        Int('Status', Pt=0, Type='uint8', Dict=RespStatus_dict),
        Str('Int', ReprName='Integrity check', Pt='', Repr='hex'),
        # here stops the Response Header
        Str('Data', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # Response Header Length and integrity field
        self.RHL.Pt = self.Int
        self.RHL.PtFunc = lambda i: 9+len(i)
        self.Int.Len = self.RHL
        self.Int.LenFunc = lambda c: max(0, c()-9)
        # Response Packet Length and data field
        self.RPL.Pt = (self.RHL, self.Data)
        self.RPL.PtFunc = lambda (r, d): r()+len(d)+1
        self.Data.Len = (self.RPL, self.RHL)
        self.Data.LenFunc = lambda (rpl, rhl): max(0, rpl()-rhl()-1)
#
