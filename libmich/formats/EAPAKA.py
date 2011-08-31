# −*− coding: UTF−8 −*−
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
# * File Name : formats/EAPAKA.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# generic imports
from libmich.core.element import Str, Int, Layer, Block, show
from libmich.core.IANA_dict import IANA_dict

SIMAKASubtype = IANA_dict({
    0 : "Reserved",
    1 : "AKA-Challenge",
    2 : "AKA-Authentication-Reject",
    3 : "Unassigned",
    4 : "AKA-Synchronization-Failure",
    5 : "AKA-Identity",
    6 : "Unassigned",
    10 : "SIM-Start",
    11 : "SIM-Challenge",
    12 : "AKA-Notification and SIM-Notification",
    13 : "AKA-Reauthentication and SIM-Reauthentication",
    14 : "AKA-Client-Error and SIM-Client-Error",
    15 : "Unassigned",
    255 : "Unassigned",
    })
    
SIMAKAAttribute = IANA_dict({
    0 : "Reserved",
    1 : "AT_RAND",
    2 : "AT_AUTN",
    3 : "AT_RES",
    4 : "AT_AUTS",
    5 : "Unassigned",
    6 : "AT_PADDING",
    7 : "AT_NONCE_MT",
    8 : "Unassigned",
    10 : "AT_PERMANENT_ID_REQ",
    11 : "AT_MAC",
    12 : "AT_NOTIFICATION",
    13 : "AT_ANY_ID_REQ",
    14 : "AT_IDENTITY",
    15 : "AT_VERSION_LIST",
    16 : "AT_SELECTED_VERSION",
    17 : "AT_FULLAUTH_ID_REQ",
    18 : "Unassigned",
    19 : "AT_COUNTER",
    20 : "AT_COUNTER_TOO_SMALL",
    21 : "AT_NONCE_S",
    22 : "AT_CLIENT_ERROR_CODE",
    23 : "AT_KDF_INPUT",
    24 : "AT_KDF",
    25 : "Unassigned",
    129 : "AT_IV",
    130 : "AT_ENCR_DATA",
    131 : "Unassigned",
    132 : "AT_NEXT_PSEUDONYM",
    133 : "AT_NEXT_REAUTH_ID",
    134 : "AT_CHECKCODE",
    135 : "AT_RESULT_IND",
    136 : "AT_BIDDING",
    137 : "Unassigned",
    255 : "Unassigned",
    })
    
SIMAKANot = IANA_dict({
    0 : "General failure after authentication",
    1 : "Unassigned",
    1026 : "User has been temporarily denied access",
    1027 : "Unassigned",
    1031 : "User has not subscribed to the requested service",
    1032 : "Unassigned",
    16384 : "General failure",
    16385 : "Unassigned",
    32768 : "Success",
    32769 : "Unassigned",
    65535 : "Unassigned",
    })
    
SIMAKAError = IANA_dict({
    0 : "unable to process packet",
    1 : "unsupported version",
    2 : "insufficient number of challenges",
    3 : "RANDs are not fresh",
    4 : "Unassigned",
    })
    

# specific imports
from libmich.formats.EAP import code_dict, method_dict
try:
    from Crypto.Cipher import AES
except ImportError:
    print '[WNG] pycrypto AES library not found'
import hmac, hashlib, struct

#EAP AKA and EAP SIM description
class EAPAKA(Block):
    
    def __init__(self, C=1, I=0):
        Block.__init__(self, Name="EAP-AKA")
        self.append( EAPAKA_hdr(C=C, I=I) )
    
    def parse(self, s):
        # parse EAP header
        self[0].map(s)
        s = s[4:]
        # if no EAP error / success, should continue with EAPAKA header
        if len(s) > 0:
            self << EAPAKA_meth()
            self[-1].map(s)
            s = s[4:]
        # loop on the length of string to parse EAPAKA attributes
        # use ATCall dictionnary  with attribute identifier to instantiate the right Layer
        while len(s) > 0:
            at = struct.unpack( '!B', s[0] )[0]
            if at in ATCall.keys():
                self.append( ATCall[ struct.unpack( '!B', s[0] )[0] ]() )
            else: self.append( TLV() )
            self[-1].hierarchy = 2
            self[-1].map(s)
            s = s[ int(self[-1].L)*4 : ]
    
    # take data from AT_ENCR_DATA payload (hierarchy + 1), pad it with AT_PADDING for having a 16-bytes multiple stream
    # cipher the data stream with AT_ENCR_DATA.cipher(data, key=K_encr, iv) and put it in AT_ENCR_DATA.encr
    # finally fill AT_MAC attribute, with the MAC computed with HMAC-SHA1-128 and K_aut 
    def protect(self, K_encr=4*'mich', K_aut=4*'mich', msg_concat=''):
        # check if AT_ENCR_DATA and AT_IV:
        if hasattr(self, 'ENCR') and hasattr(self, 'IV'):
            # pad the AT_ENCR_DATA payload with AT_PADDING if needed:
            pay = self.ENCR.get_payload()
            padlen = ( 16 - (len(pay)%16) ) % 16
            # get index of first and last ENCR payload:
            for lay in self:
                if str(lay) == str(pay[0]): 
                    first_index = lay.get_index()
                    #print '[DBG] get first_index: %s' % first_index
                if str(lay) == str(pay[-1]): 
                    last_index = lay.get_index()
                    #print '[DBG] get last_index: %s' % last_index
            # add AT_PADDING if necessary
            if padlen != 0:
                # necessaire d'avoir l'index des 1er et dernier layer du payload pour les remover apres
                self.insert( last_index + 1, AT_PADDING( pad=(padlen-2)*'\x00' ) )
                self[last_index + 1].hierarchy = self[last_index].hierarchy
            # get AT_ENCR_DATA payload, iv from AT_IV, and cipher
            s = self.ENCR.cipher( str(self.ENCR.get_payload()), K_encr, str(self.IV.iv) )
            self.ENCR.encr.Pt = s
            self.remove(first_index, last_index + 2)
        # check if AT_MAC present, if yes, overwrite any Pt value with the correct MAC
        if hasattr(self, 'MAC'):
            self.MAC.mac.Pt = 16*'\x00'
            mac = hmac.new( K_aut, str(self) + msg_concat, hashlib.sha1 ).digest()[:16]
            self.MAC.mac.Pt = mac
        
    def unprotect(self, K_encr=4*'mich', K_aut=4*'mich', msg_concat=''):
        # verify AT_MAC, computed with HMAC-SHA1-128 and K_aut 
        if hasattr(self, 'MAC'):
            mac = str(self.MAC.mac)
            self.MAC.mac.Val = 16*'\x00'
            if mac != hmac.new( K_aut, str(self) + msg_concat, hashlib.sha1 ).digest()[:16]:
                print '[WNG] MAC is not correct'
            self.MAC.mac.Val = mac    
        # check if AT_ENCR_DATA and AT_IV:
        # if yes, check and get IV from AT_IV
        if hasattr(self, 'ENCR') and hasattr(self, 'IV'):
            # uncipher the data stream from AT_ENCR_DATA.encr with AT_ENCR_DATA.uncipher(data, key, iv)
            s = self.ENCR.uncipher( str(self.ENCR.encr), K_encr, str(self.IV.iv) )
            # empty the encrypted field value
            self.ENCR.encr.Val = ''
            # parse the result into new EAPAKA TLV attributes and insert it with hierarchy(ENCR) + 1
            index = self.ENCR.get_index() + 1
            hierarchy = self[index-1].hierarchy + 1
            while len(s) > 0:
                at = struct.unpack( '!B', s[0] )[0]
                if at in ATCall.keys():
                    self.insert( index, ATCall[ struct.unpack('!B', s[0])[0] ]() )
                else: 
                    self.insert( index, TLV() )
                self[index].hierarchy = hierarchy
                self[index].map(s)
                s = s[ int(self[index].L)*4 : ]
                index += 1
    

class EAPSIM(EAPAKA):

    def __init__(self, C=1, I=0):
        Block.__init__(self, Name="EAP-SIM")
        self.append( EAPSIM_hdr(C=C, I=I) )
    

class EAPAKA_hdr(Layer):
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

class EAPSIM_hdr(EAPAKA_hdr):
    constructorList = [
        Int(CallName="C", ReprName="Code", Type="uint8", Dict=code_dict),
        Int(CallName="I", ReprName="Identifier", Type="uint8"),
        Int(CallName="L", ReprName="Length", Type="uint16"),
        ]

class EAPAKA_meth(Layer):
    constructorList = [
        Int(CallName="type", ReprName="Type", Type="uint8", Dict=method_dict),
        Int(CallName="sub", ReprName="Subtype", Type="uint8", Dict=SIMAKASubtype),
        Str(CallName="res", ReprName="Reserved", Pt='\x00\x00', Len=2, Repr="hex"),
        ]
    
    def __init__(self, type=method_dict["aka"], sub=5):
        Layer.__init__(self, CallName='meth', ReprName='EAP method')
        self.type.Pt = type
        self.sub.Pt = sub

class EAPSIM_meth(Layer):
    constructorList = [
        Int(CallName="type", ReprName="Type", Type="uint8", Dict=method_dict),
        Int(CallName="sub", ReprName="Subtype", Type="uint8", Dict=SIMAKASubtype),
        Str(CallName="res", ReprName="Reserved", Pt='\x00\x00', Len=2, Repr="hex"),
        ]
    
    def __init__(self, type=method_dict["sim"], sub=10):
        Layer.__init__(self, CallName='meth', ReprName='EAP method')
        self.type.Pt = type
        self.sub.Pt = sub

class TLV(Layer):
    constructorList = [
        Int(CallName="T", ReprName="Type", Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="V", ReprName="Value"),
        ]
    
    def __init__(self, V=''):
        Layer.__init__(self, CallName='TLV', ReprName='EAP TLV attribute')
        self.V.Pt = V
        self.V.PtFunc = lambda Value: self.pad4( str(Value) )
        self.V.Len = self.L
        self.V.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.V
        self.L.PtFunc = lambda Value: self.len4( len(Value) + 2 )
        
    def pad4(self, s='', const=2, padder='\x00'):
        extra = ( len(s) + const ) % 4
        if extra == 0: return s
        else: return s + (4-extra) * padder
    
    def len4(self, slen):
        if slen % 4: return (slen/4)+1
        else: return slen/4
    
class AT_PERMANENT_ID_REQ(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=10, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='perm_ID', ReprName='AT_PERMANENT_ID_REQ')
        self.res.PtFunc = lambda res: self.pad4( str(res) )
        self.res.Len = self.L
        self.res.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 2 )

class AT_ANY_ID_REQ(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=13, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='any_ID', ReprName='AT_ANY_ID_REQ')
        self.res.PtFunc = lambda res: self.pad4( str(res) )
        self.res.Len = self.L
        self.res.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 2 )

class AT_FULLAUTH_ID_REQ(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=17, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='full_ID', ReprName='AT_FULLAUTH_ID_REQ')
        self.res.PtFunc = lambda res: self.pad4( str(res) )
        self.res.Len = self.L
        self.res.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 2 )

class AT_IDENTITY(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=14, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="idLen", ReprName="Actual Identity Length", Type="uint16"),
        Str(CallName="id", ReprName="Identity"),
        ]
    
    def __init__(self, id=''):
        Layer.__init__(self, CallName='ID', ReprName='AT_IDENTITY')
        self.id.Pt = id
        self.id.PtFunc = lambda id: self.pad4( str(id), const=4 )
        self.id.Len = self.idLen
        self.id.LenFunc = lambda l: int(l)
        self.idLen.Pt = self.id
        self.idLen.PtFunc = lambda id: len(id.Pt)
        self.L.Pt = self.id
        self.L.PtFunc = lambda id: self.len4( len(id) + 4 )
        
class AT_RAND(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=1, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="rand", ReprName="RAND", Repr="hex"),
        ]
    
    def __init__(self, rand=4*'mich'):
        Layer.__init__(self, CallName='RAND', ReprName='AT_RAND')
        self.rand.Pt = rand
        self.rand.PtFunc = lambda rand: self.pad4( str(rand), const=4 )
        self.rand.Len = self.L
        self.rand.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.rand
        self.L.PtFunc = lambda rand: self.len4( len(rand) + 4 )

class AT_AUTN(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=2, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="autn", ReprName="AUTN", Repr="hex"),
        ]
    
    def __init__(self, autn=''):
        Layer.__init__(self, CallName='AUTN', ReprName='AT_AUTN')
        self.autn.Pt = autn
        self.autn.PtFunc = lambda autn: self.pad4( str(autn), const=4 )
        self.autn.Len = self.L
        self.autn.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.autn
        self.L.PtFunc = lambda autn: self.len4( len(autn) + 4 )

class AT_RES(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=3, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="resLen", ReprName="RES Bits Length", Type="uint16"),
        Str(CallName="res", ReprName="RES", Repr="hex"),
        ]
    
    def __init__(self, res=''):
        Layer.__init__(self, CallName='RES', ReprName='AT_RES')
        self.res.Pt = res
        self.res.PtFunc = lambda res: self.pad4( str(res), const=4 )
        self.res.Len = self.resLen
        self.res.LenFunc = lambda l: int(l)/8
        self.resLen.Pt = self.res
        self.resLen.PtFunc = lambda res: len(res.Pt)*8
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 4 )

class AT_AUTS(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=4, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="auts", ReprName="AUTS", Repr="hex"),
        ]
    
    def __init__(self, auts=''):
        Layer.__init__(self, CallName='AUTS', ReprName='AT_AUTS')
        self.auts.Pt = auts
        self.auts.PtFunc = lambda auts: self.pad4( str(auts) )
        self.auts.Len = self.L
        self.auts.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.auts
        self.L.PtFunc = lambda auts: self.len4( len(auts) + 2 )

class AT_NEXT_PSEUDONYM(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=132, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="pseuLen", ReprName="Actual Pseudonym Length", Type="uint16"),
        Str(CallName="pseu", ReprName="Pseudonym"),
        ]
    
    def __init__(self, pseu=''):
        Layer.__init__(self, CallName='Pseudo', ReprName='AT_NEXT_PSEUDONYM')
        self.pseu.Pt = pseu
        self.pseu.PtFunc = lambda pseu: self.pad4( str(pseu), const=4 )
        self.pseu.Len = self.pseuLen
        self.pseu.LenFunc = lambda l: int(l)
        self.pseuLen.Pt = self.pseu
        self.pseuLen.PtFunc = lambda pseu: len(pseu.Pt)
        self.L.Pt = self.pseu
        self.L.PtFunc = lambda pseu: self.len4( len(pseu) + 4 )

class AT_NEXT_REAUTH_ID(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=133, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="reautLen", ReprName="Actual Re-auth Identity Length", Type="uint16"),
        Str(CallName="reaut", ReprName="Next Fast Re-authentication Username"),
        ]
    
    def __init__(self, reaut=''):
        Layer.__init__(self, CallName='reaut_ID', ReprName='AT_NEXT_REAUTH_ID')
        self.reaut.Pt = reaut
        self.reaut.PtFunc = lambda reau: self.pad4( str(reaut), const=4 )
        self.reaut.Len = self.reautLen
        self.reaut.LenFunc = lambda l: int(l)
        self.reautLen.Pt = self.reaut
        self.reautLen.PtFunc = lambda reaut: len(reaut.Pt)
        self.L.Pt = self.reaut
        self.L.PtFunc = lambda reaut: self.len4( len(reaut) + 4 )

class AT_IV(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=129, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="iv", ReprName="IV", Repr="hex"),
        ]
    
    def __init__(self, iv=''):
        Layer.__init__(self, CallName='IV', ReprName='AT_IV')
        self.iv.Pt = iv
        self.iv.PtFunc = lambda iv: self.pad4( str(iv), const=4 )
        self.iv.Len = self.L
        self.iv.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.iv
        self.L.PtFunc = lambda iv: self.len4( len(iv) + 4 )

class AT_PADDING(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=6, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="pad", ReprName="Padding", Repr="hex"),
        ]
    
    def __init__(self, pad=''):
        Layer.__init__(self, CallName='PAD', ReprName='AT_PADDING')
        self.pad.Pt = pad
        self.pad.PtFunc = lambda pad: self.pad4( str(pad) )
        self.pad.Len = self.L
        self.pad.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.pad
        self.L.PtFunc = lambda pad: self.len4( len(pad) + 2 )
    
class AT_ENCR_DATA(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=130, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="encr", ReprName="Encrypted Data", Repr="hex"),
        ]
    
    def __init__(self, encr=''):
        Layer.__init__(self, CallName='ENCR', ReprName='AT_ENCR_DATA')
        self.encr.Pt = encr
        self.encr.PtFunc = lambda encr: self.pad4( str(encr), const=4 )
        self.encr.Len = self.L
        self.encr.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.encr
        self.L.PtFunc = lambda encr: self.len4( len(encr) + 4 )
    
    # encryption must use AES-CBC-128 with IV from AT_IV
    # Encrypted Data: contains nested EAP-AKA TLV attributes     # MANAGED AT THE BLOCK LEVEL
    # The length of the Encrypted Data must be a multiple of 16 bytes   # MANAGED AT THE BLOCK LEVEL
    # >>> if needed AT_PADDING is used as the last nested attribute for padding to a 16-bytes multiple.     #  MANAGED AT THE BLOCK LEVEL:
    
    def cipher(self, data, key=4*'mich', iv=4*'mich'):
        if len(key) != 16: print '[WNG]: key must be 16 bytes long'
        if len(iv) != 16: print '[WNG]: iv must be 16 bytes long'
        if len(data) == 0 or len(data) % 16 != 0: print '[WNG]: data must be 16 bytes long and not null'
        return AES.new(key=key, mode=2, IV=iv).encrypt(data)
    
    def uncipher(self, data, key=4*'mich', iv=4*'mich'):
        if len(key) != 16: print '[WNG]: key must be 16 bytes long'
        if len(iv) != 16: print '[WNG]: iv must be 16 bytes long'
        if len(data) == 0 or len(data) % 16 != 0: print '[WNG]: data must be 16 bytes long and not null'
        return AES.new(key=key, mode=2, IV=iv).decrypt(data)
        
class AT_CHECKCODE(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=134, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="ck", ReprName="Checkcode", Repr="hex"),
        ]
    
    def __init__(self, ck=''):
        Layer.__init__(self, CallName='Check', ReprName='AT_CHECKCODE')
        self.ck.Pt = ck
        self.ck.PtFunc = lambda ck: self.pad4( str(ck), const=4 )
        self.ck.Len = self.L
        self.ck.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.ck
        self.L.PtFunc = lambda ck: self.len4( len(ck) + 4 )

class AT_RESULT_IND(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=135, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Pt=1, Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='res_IND', ReprName='AT_RESULT_IND')
        self.res.PtFunc = lambda res: self.pad4( str(res) )
        self.res.Len = self.L
        self.res.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 2 )
        
class AT_MAC(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=11, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="mac", ReprName="MAC", Repr="hex"),
        ]
    
    def __init__(self, mac=''):
        Layer.__init__(self, CallName='MAC', ReprName='AT_MAC')
        self.mac.Pt = mac
        self.mac.PtFunc = lambda mac: self.pad4( str(mac), const=4 )
        self.mac.Len = self.L
        self.mac.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.mac
        self.L.PtFunc = lambda mac: self.len4( len(mac) + 4 )

class AT_COUNTER(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=19, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="count", ReprName="Counter", Type="uint16"),
        ]
    
    def __init__(self, count=0):
        Layer.__init__(self, CallName='Count', ReprName='AT_COUNTER')
        self.count.Pt = count
        self.L.Pt = self.count
        self.L.PtFunc = lambda count: self.len4( len(count) + 2 )

class AT_COUNTER_OVERFLOW(TLV):
    # this is a special attribute for being able to overflow the counter value with extended data
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=19, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="count", ReprName="Counter", Repr="hex"),
        ]
    
    def __init__(self, count='\x00\x00'):
        Layer.__init__(self, CallName='Count_OF', ReprName='AT_COUNTER_OVERFLOW')
        self.count.Pt = count
        self.count.PtFunc = lambda count: self.pad4( str(count) )
        self.count.Len = self.L
        self.count.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.count
        self.L.PtFunc = lambda count: self.len4( len(count) + 2 )
        
class AT_COUNTER_TOO_SMALL(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=20, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='Small', ReprName='AT_COUNTER_TOO_SMALL')
        self.res.PtFunc = lambda res: self.pad4( str(res) )
        self.res.Len = self.L
        self.res.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.res
        self.L.PtFunc = lambda res: self.len4( len(res) + 2 )

class AT_NONCE_S(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=21, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="n_s", ReprName="NONCE_S", Repr="hex"),
        ]
    
    def __init__(self, n_s=''):
        Layer.__init__(self, CallName='N_S', ReprName='AT_NONCE_S')
        self.n_s.Pt = n_s
        self.n_s.PtFunc = lambda n_s: self.pad4( str(n_s), const=4 )
        self.n_s.Len = self.L
        self.n_s.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.n_s
        self.L.PtFunc = lambda n_s: self.len4( len(n_s) + 4 )

class AT_NOTIFICATION(TLV):
    # NOT msg 1st bit "S": S==0 indicates FAILURE, S==1 for SUCCESS
    # NOT msg 2nd bit "P": P==0 indicates AFTER CHALLENGE ROUND, P==1 for BEFORE CHALLENGE ROUND
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=12, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="notif", ReprName="Notification Code", Type="uint16", Dict=SIMAKANot),
        ]
    
    def __init__(self, notif=0x4000):
        Layer.__init__(self, CallName='NOT', ReprName='AT_NOTIFICATION')
        self.notif.Pt = notif
        self.L.Pt = self.notif
        self.L.PtFunc = lambda notif: self.len4( len(notif) + 2 )

class AT_NOTIFICATION_OVERFLOW(TLV):
    # this is a special attribute for being able to overflow the notification value with extended data
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=12, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="notif", ReprName="Notification Code", Repr="hex"),
        ]
    
    def __init__(self, notif='\x40\x00'):
        Layer.__init__(self, CallName='NOT_OF', ReprName='AT_NOTIFICATION_OVERFLOW')
        self.notif.Pt = notif
        self.notif.PtFunc = lambda notif: self.pad4( str(notif) )
        self.notif.Len = self.L
        self.notif.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.notif
        self.L.PtFunc = lambda notif: self.len4( len(notif) + 2 )

class AT_CLIENT_ERROR_CODE(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=22, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="err", ReprName="Client Error Code", Type="uint16", Dict=SIMAKAError),
        ]
    
    def __init__(self, err=0x0000):
        Layer.__init__(self, CallName='ERR', ReprName='AT_CLIENT_ERROR_CODE')
        self.err.Pt = err
        self.L.Pt = self.err
        self.L.PtFunc = lambda err: self.len4( len(err) + 2 )

class AT_CLIENT_ERROR_CODE_OVERFLOW(TLV):
    # this is a special attribute for being able to overflow the client error code value with extended data
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=22, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="err", ReprName="Client Error Code", Repr="hex"),
        ]
    
    def __init__(self, err='\x00\x00'):
        Layer.__init__(self, CallName='ERR_OF', ReprName='AT_CLIENT_ERROR_CODE_OVERFLOW')
        self.err.Pt = err
        self.err.PtFunc = lambda err: self.pad4( str(err) )
        self.err.Len = self.L
        self.err.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.err
        self.L.PtFunc = lambda err: self.len4( len(err) + 2 )

class AT_NONCE_MT(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=7, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Str(CallName="res", ReprName="Reserved", Pt="\x00\x00", Len=2, Repr="hex"),
        Str(CallName="n_mt", ReprName="NONCE_MT", Repr="hex"),
        ]
    
    def __init__(self, n_mt=''):
        Layer.__init__(self, CallName='N_MT', ReprName='AT_NONCE_MT')
        self.n_mt.Pt = n_mt
        self.n_mt.PtFunc = lambda n_mt: self.pad4( str(n_mt), const=4 )
        self.n_mt.Len = self.L
        self.n_mt.LenFunc = lambda L: ( int(L)*4 ) - 4
        self.L.Pt = self.n_mt
        self.L.PtFunc = lambda n_mt: self.len4( len(n_mt) + 4 )
    
class AT_VERSION_LIST(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=15, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Type="uint8"),
        Int(CallName="listLen", ReprName="Length of Version List", Type="uint16"),
        Str(CallName="list", ReprName="List of Supported Version", Repr="hex"),
        ]
    
    def __init__(self, list="\x00\x01"):
        Layer.__init__(self, CallName='VER_LIST', ReprName='AT_VERSION_LIST')
        self.list.Pt = list
        self.list.PtFunc = lambda list: self.pad4( str(list), const=4 )
        self.list.Len = self.listLen
        self.list.LenFunc = lambda l: int(l)
        self.listLen.Pt = self.list
        self.listLen.PtFunc = lambda list: len(list.Pt)
        self.L.Pt = self.list
        self.L.PtFunc = lambda list: self.len4( len(list) + 4 )
    
class AT_SELECTED_VERSION(TLV):
    constructorList = [
        Int(CallName="T", ReprName="Type", Pt=16, Type="uint8", Dict=SIMAKAAttribute),
        Int(CallName="L", ReprName="Length", Pt=1, Type="uint8"),
        Str(CallName="ver", ReprName="Reserved", Repr="hex"),
        ]
    
    def __init__(self, ver="\x00\x01"):
        Layer.__init__(self, CallName='SEL_VER', ReprName='AT_SELECTED_VERSION')
        self.ver.Pt = ver
        self.ver.PtFunc = lambda vr: self.pad4( str(ver) )
        self.ver.Len = self.L
        self.ver.LenFunc = lambda L: ( int(L)*4 ) - 2
        self.L.Pt = self.ver
        self.L.PtFunc = lambda ver: self.len4( len(ver) + 2 )
    

# define a dictionnary to call EAP-AKA attribute Layer object from their identifier
ATCall = {
    1 : AT_RAND,
    2 : AT_AUTN,
    3 : AT_RES,
    4 : AT_AUTS,
    6 : AT_PADDING,
    7 : AT_NONCE_MT,
    10 : AT_PERMANENT_ID_REQ,
    11 : AT_MAC,
    12 : AT_NOTIFICATION,
    13 : AT_ANY_ID_REQ,
    14 : AT_IDENTITY,
    15 : AT_VERSION_LIST,
    16 : AT_SELECTED_VERSION,
    17 : AT_FULLAUTH_ID_REQ,
    19 : AT_COUNTER,
    20 : AT_COUNTER_TOO_SMALL,
    21 : AT_NONCE_S,
    22 : AT_CLIENT_ERROR_CODE,
    23 : TLV, #AT_KDF_INPUT, # not implemented at this time, used for EAP-AKA'
    24 : TLV, #AT_KDF, # not implemented at this time, used for EAP-AKA'
    129 : AT_IV,
    130 : AT_ENCR_DATA,
    132 : AT_NEXT_PSEUDONYM,
    133 : AT_NEXT_REAUTH_ID,
    134 : AT_CHECKCODE,
    135 : AT_RESULT_IND,
    136 : TLV, #AT_BIDDING, # not implemented at this time, used for EAP-AKA'
    }
    


''' 
# some EAPAKA requests / responses:
[+] computed EAP-K_encr: 9e4d8a4fb994d966f50b1d5c4f6d4552
'\x9eM\x8aO\xb9\x94\xd9f\xf5\x0b\x1d\\OmER'
[+] computed EAP-K_aut: eec61fe938cbac5584152c6506941d84
'\xee\xc6\x1f\xe98\xcb\xacU\x84\x15,e\x06\x94\x1d\x84'

'\x02\x03\x00@\x17\x01\x00\x00\x03\x03\x00@\xedsk\xf8\xd2\x1d\x0f\x04\x86\x06\x00\x00\xf8m\xd5\x8d\xbbT\xf8V\x80A\xcaMFl\xe3\x95\x90\xff\xf9\x95\x0b\x05\x00\x00\xa5\xcd\xefa\xf1\xff\xa4]\x9f=M\x1c\x8e\xde\xbaL'

'\x01\x03\x00\x9c\x17\x01\x00\x00\x82\x11\x00\x00\xd2\xb1[\x93P\t\xd7\\_\x0b\xd7XVl)\xb9-\xe3\x81\xea\xfc\x1c\xd4\xd2\xd0}\xe1r\xf8\xda\x8b[\x8d\xcf\xd0H)%x\xab\xea\xee@G\xa7\xd6I\xc2X`\xe88\n\xf4\xfc\x82\x86\xb2\xf7@\xb4\x18\xa7a\x81\x05\x00\x00\xf7\xf7\xbd`\xb0DCro!\xc2\xf6\xb3\xdc\x85\x94\x01\x05\x00\x00T$=\xc7@\xb4\xc9\xb5\xaa\xb3\x88\x11\xbe\xfc!\xb2\x02\x05\x00\x00o\x85(\xe8\xdae\x00\x00I\xc2\xf6O\x19\x07n\xd0\x0b\x05\x00\x00G\x81\x1dDZC\x171r\xc36|I\xb1<\x10'
'''
