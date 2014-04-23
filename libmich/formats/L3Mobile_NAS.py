# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
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
# * File Name : formats/L3Mobile_NAS.py
# * Created : 2013-10-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 
#!/usr/bin/env python

# exporting
#__all__ = [
#            ]

from libmich.core.element import Element, Str, Int, Bit, Layer, RawLayer, \
     Block, show, log, ERR, WNG, DBG

# library for handling the global mobile Layer3
from L3Mobile_24007 import PD_dict, Layer3
from libmich.formats.L3Mobile_IE import ID, GUTI

try:
    from CryptoMobile.CM import *
    __with_crypto = True
except ImportError:
    print('[WNG] CryptoMobile module not found: ' \
          'LTE NAS security procedures not supported')
    __with_crypto = False

###
# TS 24.301, 11.5.0 specification
# NAS protocol for Evolved Packet System
# EMM procedures in section 5
# ESM procedures in section 6
# message function in section 8
# message format in section 9
###

#
SecHdr_dict = {
    0 : 'No security',
    1 : 'Integrity protected',
    2 : 'Integrity protected and ciphered',
    3 : 'Integrity protected with new EPS security context',
    4 : 'Integrity protected and ciphered with new EPS security context',
    12 : 'Security header for SERVICE REQUEST'
    }
    
###
# NAS protocol security header
# section 9.2
#
# An LTE security context needs to be defined to run all security functions
# a security context at the MME is made of:
# - Kasme (LTE master key)
# - NAS uplink and downlink counters
# - EEA and EIA security algorithms (0:None, 1:SNOW, 2:AES or 3:ZUC)
# -> Kasme is computed from CK, IK, SQN xor AK (all from a 3G auth vector), 
# plus the Serving Network ID (MCC/MNC)
# -> K_NAS_int and K_NAS_enc are derived from Kasme and EEA / EIA identifiers
# -> K_eNB is derived from Kasme and uplink NAS counter
# It is indexed by the KSI.
#
###

class NASSecHeader(Layer):
    constructorList = [
        Bit('SH', ReprName='Security Header Type', Pt=1, BitLen=4, 
            Dict=SecHdr_dict, Repr='hum'),
        Bit('PD', ReprName='Protocol Discriminator', Pt=7, BitLen=4,
            Dict=PD_dict, Repr='hum'),
        Str('MAC', ReprName='Message Authentication Code', Pt=4*'\0', Len=4,
            Repr='hex'),
        Int('SN', ReprName='Sequence Number', Pt=0, Type='uint8')
        ]

class Layer3NAS(Layer3):
    
    constructorList = [ ]
    
    # NAS security algorithm
    EIA = None
    #EIA = EIA1
    EEA = None
    #EEA = EEA1
    
    def __init__(self, with_security=False, **kwargs):
        Layer3.__init__(self, **kwargs)
        if with_security:
            self.ins_sec_hdr()
    
    def ins_sec_hdr(self):
        if not hasattr(self, 'MAC'):
            index = 0
            for ie in NASSecHeader():
                self.insert(index, ie)
                index += 1
    
    def map(self, s=''):
        if not s:
            return
        # check the security header
        s0 = ord(s[0])
        sh, pd = s0>>4, s0&0xF
        # ESM, or EMM with no security header
        if pd == 2 or sh in (0, 12):
            self.__init__(with_security=False)
            Layer3.map(self, s)
            self._map_eps_id()
        # EMM with security header
        elif pd == 7 and sh in (1, 2, 3, 4):
            self.ins_sec_hdr()
            # if no ciphering applied
            if sh in (1, 3): 
            #if sh in (1, 3) or self.EEA not in (EEA1, EEA2, EEA3):
                # if no payload is already there, just add a ciphered-like one
                if len(self.elementList) == 4:
                    self << Str('_enc')
                # map directly the buffer onto the NAS payload
                Layer3.map(self, s)
                self._map_eps_id()
            else:
                # keep track of all IE of the original packet
                self._pay = self[4:]
                # replace them with a dummy string
                for ie in self._pay:
                    self.remove(ie)
                self << Str('_enc')
                Layer3.map(self, s)
        else:
            log(ERR, '[ERR] invalid Security Header value %i' % sh)
        #
    
    def _map_eps_id(self):
        # some additional processing for interpreting EPS_ID as ID or GUTI
        for ie in self[3:]:
            if ie.CallName == 'EPS_ID' and not ie.Trans:
                s = str(ie.V)
                if not s:
                    return
                typ = ord(s[0]) & 0b111
                ident = None
                if typ in (1, 3):
                    ident = ID()
                elif typ == 6:
                    ident = GUTI()
                if ident:
                    ident.map(s)
                    if str(ident) == s:
                        ie.V < None
                        ie.V > ident
    
    ###
    # security procedures
    ###
    
    def verify_mac(self, key=16*'\0', dir=0):
        # key: K_NAS_int
        # cnt: NAS uplink or downlink counter
        # dir: direction (uplink / downlink)
        # using self.EIA
        #
        # if no MAC to check
        sh = self.SH()
        if sh not in (1, 2, 3, 4, 12) \
        or self.EIA not in (EIA1, EIA2, EIA3):
            return True
        #
        if sh in (1, 2, 3, 4):
            # get NAS payload buffer (including NAS count)
            pay = str(self[3:])
            # compute MAC
            mac = self.EIA(key, self.SN(), 0, dir, pay)
            # compare MAC
            if mac != str(self.MAC):
                return False
            else:
                return True
        elif sh == 12:
            pay = str(self[0:4])
            mac = self.EIA(key, self.SN(), 0, dir, pay)
            if mac[2:4] != str(self.MAC):
                return False
            else:
                return True
    
    def compute_mac(self, key=16*'\0', dir=0):
        # if no MAC to apply
        sh = self.SH()
        if sh not in (1, 2, 3, 4, 12) \
        or self.EIA not in (EIA1, EIA2, EIA3):
            # give it null value
            if hasattr(self, 'MAC'):
                self.MAC < None
                self.MAC > '\0\0\0\0'
            return
        #
        if sh in (1, 2, 3, 4):
            # get NAS payload buffer (including NAS count)
            pay = str(self[3:])
            # compute MAC
            mac = self.EIA(key, self.SN(), 0, dir, pay)
            #print('MAC: %s' % repr(mac))
            self.MAC < None
            self.MAC > mac
        elif sh == 12:
            pay = str(self[0:4])
            mac = self.EIA(key, self.SN(), 0, dir, pay)
            self.MAC < None
            self.MAC > mac[2:4]
    
    def decipher(self, key=16*'\0', dir=0):
        # key: K_NAS_enc
        # cnt: NAS uplink or downlink counter
        # dir: direction (uplink / downlink)
        # using self.EEA
        #
        # if no deciphering to apply
        if self.SH() not in (2, 3) \
        or self.EEA not in (None, EEA1, EEA2, EEA3):
            return
        if not hasattr(self, '_pay') \
        or (not isinstance(self[-1], Str) and self[-1].CallName != '_enc'):
            log(ERR, 'Layer3NAS - decipher: not ready for deciphering')
            return
        #
        if self.EEA is None:
            # null ciphering EEA0
            dec = str(self[-1])
        else:
            dec = self.EEA(key, self.SN(), 0, dir, str(self[-1]))
        #
        # get the complete packet buffer
        buf = str(self[:4]) + dec
        # reinsert NAS payload IEs
        self.remove(self[-1])
        self.extend(self._pay)
        # remap the complete deciphered buffer to the NAS layer
        Layer3.map(self, buf)
        self._map_eps_id()
      
    def cipher(self, key=16*'\0', dir=0):
        # if no ciphering to apply
        if self.SH() not in (2, 3) \
        or self.EEA not in (None, EEA1, EEA2, EEA3):
            return
        #
        # keep track of all IE of the original packet
        self._pay = self[4:]
        if self.EEA is None:
            enc = str(self._pay)
        else:
            enc = self.EEA(key, self.SN(), 0, dir, str(self._pay))
        #
        # replace them with a dummy string
        for ie in self._pay:
            self.remove(ie)
        self << Str('_enc')
        self[-1].map(enc)
    
    def protect(self, key_int=16*'\0', key_enc=16*'\0', dir=0):
        self.cipher(key_enc, dir)
        self.compute_mac(key_int, dir)
    
    def unprotect(self, key_int=16*'\0', key_enc=16*'\0', dir=0):
        ret = self.verify_mac(key_int, dir)
        if not ret:
            log(WNG, 'Layer3NAS - unprotect: MAC verificaion failed')
        self.decipher(key_enc, dir)
    
    ###
    # When receiving ciphered NAS messages,
    # there is no way to know which type of Layer3NAS message it is.
    # We need a function that returns a buffer that will be parsed again
    ###
    
    def get_deciphered(self, key=16*'\0', dir=0):
        # this is to get the deciphered stream of a NAS EMM message
        # 
        # no NAS security
        if self.SH() == 0 and not hasattr(self, 'MAC'):
            return str(self)
        #
        # NAS security, only integrity protection
        elif self.SH() in (1, 3) and hasattr(self, 'MAC'):
            return str(self[4:])
        #
        # NAS security, ciphered
        elif self.SH() in (2, 4) and hasattr(self, 'MAC'):
            if self.EEA is None:
                # null ciphering EEA0
                return str(self[4:])
            elif self[-1].CallName == '_enc':
                return self.EEA(key, self.SN(), 0, dir, str(self[-1]))
        #
        log(ERR, 'Layer3NAS - get_deciphered: could not retrieve NAS payload')
        return ''
    
    def get_ciphered(self, key=16*'\0', dir=0):
        # this is to get the ciphered stream of a clear text NAS EMM message
        # 
        # if no correct ciphering algo to apply
        if self.EEA not in (None, EEA1, EEA2, EEA3):
            return ''
        #
        if self.EEA is None:
            return str(self)
        else:
            return self.EEA(key, self.SN(), 0, dir, str(self))


