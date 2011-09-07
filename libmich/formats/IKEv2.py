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
# * File Name : formats/IKEv2.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Layer, Block, show
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.IP import IP_prot
from random import _urandom as urandom
from struct import pack, unpack
from binascii import hexlify # for some debugging
from socket import inet_ntoa
import hmac, hashlib # support for MD5 and SHA1
try:
    from Crypto.Cipher import AES, DES, DES3
except ImportError:
    print '[WNG] pycrypto not found:'\
          '.protect() / .unprotect() will fail'
# TODO: some data lengths still hardcoded in protect() / unprotect() methods


PayloadType = IANA_dict({
    0 : "None",
    1 : "Reserved",
    33 : ("Security Association", "SA"),
    34 : ("Key Exchange", "KE"),
    35 : ("Identification - Initiator", "IDi"),
    36 : ("Identification - Responder", "IDr"),
    37 : ("Certificate", "CERT"),
    38 : ("Certificate Request", "CERTREQ"),
    39 : ("Authentication", "Auth"),
    40 : ("Nonce", "N"),
    41 : ("Notify", "Not"),
    42 : ("Delete", "Del"),
    43 : ("Vendor ID", "V"),
    44 : ("Traffic Selector - Initiator", "TSi"),
    45 : ("Traffic Selector - Responder", "TSr"),
    46 : ("Encrypted", "Enc"),
    47 : ("Configuration", "CP"),
    48 : ("Extensible Authentication", "EAP"),
    49 : "Unassigned",
    128 : "Private",
    255 : "Private",
    })
    
ExchangeType = IANA_dict({
    0 : "Reserved",
    34 : "IKE_SA_INIT",
    35 : "IKE_AUTH",
    36 : "CREATE_CHILD_SA",
    37 : "INFORMATIONAL",
    38 : "Unassigned",
    39 : "Private",
    255 : "Private"
    })
    
ProtocolID = IANA_dict({
    0 : "Reserved",
    1 : ("Internet Key Exchange", "IKE"),
    2 : ("Authentication Header", "AH"),
    3 : ("Encapsulating Security Payload", "ESP"),
    4 : "FC_ESP_HEADER",
    5 : "FC_CT_AUTHENTICATION",
    6 : "Unassigned",
    201 : "Private",
    255 : "Private"
    })
    
TransformType = IANA_dict({
    0 : "Reserved",
    1 : ("Encryption Algorithm", "ENCR"),
    2 : ("Pseudo-random Function", "PRF"),
    3 : ("Integrity Algorithm", "INTEG"),
    4 : ("Diffie-Hellman Group", "DH"),
    5 : ("Extended Sequence Numbers", "ESN"),
    6 : "Unassigned",
    241 : "Private",
    255 : "Private"
    })
    
TransformID = {
    1 : IANA_dict({
        0 : "Reserved",
        1 : "ENCR_DES_IV64",
        2 : ("ENCR_DES", "des"),
        3 : ("ENCR_3DES", "3des"),
        4 : "ENCR_RC5",
        5 : "ENCR_IDEA",
        6 : "ENCR_CAST",
        7 : "ENCR_BLOWFISH",
        8 : "ENCR_3IDEA",
        9 : "ENCR_DES_IV32",
        10 : "Reserved",
        11 : ("ENCR_NULL", "null"),
        12 : ("ENCR_AES_CBC", "aes-cbc"),
        13 : "ENCR_AES_CTR",
        14 : "ENCR_AES-CCM_8",
        15 : "ENCR-AES-CCM_12",
        16 : "ENCR-AES-CCM_16",
        17 : "Unassigned",
        18 : "AES-GCM_8",
        19 : "AES-GCM_12",
        20 : "AES-GCM_16",
        21 : "ENCR_NULL_AUTH_AES_GMAC",
        22 : "XTS-AES",
        23 : "ENCR_CAMELLIA_CBC",
        24 : "ENCR_CAMELLIA_CTR",
        25 : "ENCR_CAMELLIA_CCM_8",
        26 : "ENCR_CAMELLIA_CCM_12",
        27 : "ENCR_CAMELLIA_CCM_16",
        28 : "Unassigned",
        1024 : "Private",
        65535 : "Private"
        }),
    
    2 : IANA_dict({
        0 : "Reserved",
        1 : ("PRF_HMAC_MD5", "hmac-md5"),
        2 : ("PRF_HMAC_SHA1", "hmac-sha1"),
        3 : "PRF_HMAC_TIGER",
        4 : "PRF_AES128_XCBC",
        5 : "PRF_HMAC_SHA2_256",
        6 : "PRF_HMAC_SHA2_384",
        7 : "PRF_HMAC_SHA2_512",
        8 : "PRF_AES128_CMAC",
        9 : "Unassigned",
        1024 : "Private",
        65535 : "Private"
        }),
    
    3 : IANA_dict({
        0 : ("NONE", "none"),
        1 : ("AUTH_HMAC_MD5_96", "hmac-md5-96"),
        2 : ("AUTH_HMAC_SHA1_96", "hmac-sha1-96"),
        3 : "AUTH_DES_MAC",
        4 : "AUTH_KPDK_MD5",
        5 : "AUTH_AES_XCBC_96",
        6 : "AUTH_HMAC_MD5_128",
        7 : "AUTH_HMAC_SHA1_160",
        8 : "AUTH_AES_CMAC_96",
        9 : "AUTH_AES_128_GMAC",
        10 : "AUTH_AES_192_GMAC",
        11 : "AUTH_AES_256_GMAC",
        12 : "AUTH_HMAC_SHA2_256_128",
        13 : "AUTH_HMAC_SHA2_384_192",
        14 : "AUTH_HMAC_SHA2_512_256",
        15 : "Unassigned",
        1024 : "Private",
        65535 : "Private"
        }),
    
    4 : IANA_dict({
        0 : "NONE",
        1 : "768-bit MODP Group",
        2 : ("1024-bit MODP Group", "modp-1024"),
        3 : "Reserved",
        5 : ("1536-bit MODP Group", "modp-1536"),
        6 : "Unassigned",
        14 : "2048-bit MODP Group",
        15 : "3072-bit MODP Group",
        16 : "4096-bit MODP Group",
        17 : "6144-bit MODP Group",
        18 : "8192-bit MODP Group",
        19 : "256-bit random ECP Group",
        20 : "384-bit random ECP Group",
        21 : "521-bit random ECP group",
        22 : "1024-bit MODP Group with 160-bit Prime Order Subgroup",
        23 : "2048-bit MODP Group with 224-bit Prime Order Subgroup",
        24 : "2048-bit MODP Group with 256-bit Prime Order Subgroup",
        25 : "192-bit Random ECP Group",
        26 : "224-bit Random ECP Group",
        27 : "Unassigned",
        1024 : "Private",
        65535 : "Private"
        }),
    
    5 : IANA_dict({
        0 : "No ESN",
        1 : "ESN",
        2 : "Reserved",
        65535 : "Reserved"
        })
    }
    
TransAttType = IANA_dict({
    0 : "Reserved",
    14 : "Key Length",
    15 : "Reserved",
    18 : "Unassigned",
    16384 : "Private",
    32767 : "Private",
    32768 : "Reserved",
    32782 : "Key Length",
    32783 : "Reserved",
    32786 : "Unassigned",
    49152 : "Private",
    65535 : "Private"
    })
    
IdentityType = IANA_dict({
    0 : "Reserved",
    1 : ("ID_IPV4_ADDR", "IPv4"),
    2 : ("ID_FQDN", "FQDN"),
    3 : ("ID_RFC822_ADDR", "822"),
    4 : "Unassigned",
    5 : ("ID_IPV6_ADDR", "IPv6"),
    6 : "Unassigned",
    9 : "ID_DER_ASN1_DN",
    10 : "ID_DER_ASN1_GN",
    11 : "ID_KEY_ID",
    12 : "ID_FC_NAME",
    13 : "Unassigned",
    201 : "Private",
    255 : "Private"
    })
    
CertificateEncoding = IANA_dict({
    0 : "Reserved",
    1 : ("PKCS #7 wrapped X.509 certificate", "PKCS7"),
    2 : ("PGP Certificate", "PGP"),
    3 : ("DNS Signed Key", "DNS"),
    4 : ("X.509 Certificate - Signature", "X509"),
    5 : "Reserved",
    6 : ("Kerberos Token", "Kerb"),
    7 : ("Certificate Revocation List", "CRL"),
    8 : ("Authority Revocation List", "ARL"),
    9 : ("SPKI Certificate", "SPKI"),
    10 : ("X.509 Certificate - Attribute", "X509Attr"),
    11 : ("Raw RSA Key", "RSA"),
    12 : "Hash and URL of X.509 certificate",
    13 : "Hash and URL of X.509 bundle",
    14 : ("OCSP Content", "OCSP"),
    15 : "Unassigned",
    201 : "Private ",
    255 : "Private",
    })
    
AuthMethod = IANA_dict({
    0 : "Reserved",
    1 : ("RSA digital signature", "RSA"),
    2 : ("Shared Key Message Integrity Code", "PSK"),
    3 : ("DSS digital signature", "DSS"),
    4 : "Unassigned",
    9 : ("ECDSA with SHA-256 on the P-256 curve", "ECDSA256"),
    10 : ("ECDSA with SHA-384 on the P-384 curve", "ECDSA 384"),
    11 : ("ECDSA with SHA-512 on the P-521 curve", "ECDSA 512"),
    12 : "Unassigned",
    201 : "Private",
    255 : "Private",
    })

NotifyType = IANA_dict({
    0 : "Reserved",
    1 : "UNSUPPORTED_CRITICAL_PAYLOAD",
    2 : "Reserved",
    4 : "INVALID_IKE_SPI",
    5 : "INVALID_MAJOR_VERSION",
    6 : "Reserved",
    7 : "INVALID_SYNTAX",
    8 : "Reserved",
    9 : "INVALID_MESSAGE_ID",
    10 : "Reserved",
    11 : "INVALID_SPI",
    12 : "Reserved",
    14 : "NO_PROPOSAL_CHOSEN",
    15 : "Reserved",
    17 : "INVALID_KE_PAYLOAD",
    18 : "Reserved",
    24 : "AUTHENTICATION_FAILED",
    25 : "RESERVED",
    34 : "SINGLE_PAIR_REQUIRED",
    35 : "NO_ADDITIONAL_SAS",
    36 : "INTERNAL_ADDRESS_FAILURE",
    37 : "FAILED_CP_REQUIRED",
    38 : "TS_UNACCEPTABLE",
    39 : "INVALID_SELECTORS",
    40 : "UNACCEPTABLE_ADDRESSES",
    41 : "UNEXPECTED_NAT_DETECTED",
    42 : "USE_ASSIGNED_HoA",
    43 : "Unassigned",
    8192 : "Private",
    16384 : "INITIAL_CONTACT",
    16385 : "SET_WINDOW_SIZE",
    16386 : "ADDITIONAL_TS_POSSIBLE",
    16387 : "IPCOMP_SUPPORTED",
    16388 : "NAT_DETECTION_SOURCE_IP",
    16389 : "NAT_DETECTION_DESTINATION_IP",
    16390 : "COOKIE",
    16391 : "USE_TRANSPORT_MODE",
    16392 : "HTTP_CERT_LOOKUP_SUPPORTED",
    16393 : "REKEY_SA",
    16394 : "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395 : "NON_FIRST_FRAGMENTS_ALSO",
    16396 : "MOBIKE_SUPPORTED",
    16397 : "ADDITIONAL_IP4_ADDRESS",
    16398 : "ADDITIONAL_IP6_ADDRESS",
    16399 : "NO_ADDITIONAL_ADDRESSES",
    16400 : "UPDATE_SA_ADDRESSES",
    16401 : "COOKIE2",
    16402 : "NO_NATS_ALLOWED",
    16403 : "AUTH_LIFETIME",
    16404 : "MULTIPLE_AUTH_SUPPORTED",
    16405 : "ANOTHER_AUTH_FOLLOWS",
    16406 : "Unassigned",
    40960 : "Private",
    65535 : "Private",
    })
    
CompressionType = IANA_dict({
    0 : "Reserved",
    1 : "IPCOMP_OUI",
    2 : "IPCOMP_DEFLATE",
    3 : "IPCOMP_LZS",
    4 : "IPCOMP_LZJH",
    5 : "Unassigned",
    241 : "Private",
    255 : "Private"
    })
    
TSType = IANA_dict({
    0 : "Reserved",
    7 : ("TS_IPV4_ADDR_RANGE", "IPv4"),
    8 : ("TS_IPV6_ADDR_RANGE", "IPv6"),
    9 : ("TS_FC_ADDR_RANGE", "FC"),
    10 : "Unassigned",
    241 : "Private",
    255 : "Private",
    })
    
CfgType = IANA_dict({
    0 : "Reserved",
    1 : ("CFG_REQUEST", "REQ"),
    2 : ("CFG_REPLY", "REP"),
    3 : ("CFG_SET", "SET"),
    4 : ("CFG_ACK", "ACK"),
    5 : "Unassigned",
    128 : "Private",
    255 : "Private",
    })
    
CfgAttType = IANA_dict({
    0 : "Reserved",
    1 : ("INTERNAL_IP4_ADDRESS", "IPv4"),
    2 : ("INTERNAL_IP4_NETMASK", "IPv4NM"),
    3 : ("INTERNAL_IP4_DNS", "IPv4DNS"),
    4 : ("INTERNAL_IP4_NBNS", "IPv4NBNS"),
    5 : ("INTERNAL_ADDRESS_EXPIRY", "EXPIR"),
    6 : ("INTERNAL_IP4_DHCP", "IPv4DHCP"),
    7 : ("APPLICATION_VERSION", "VERS"),
    8 : ("INTERNAL_IP6_ADDRESS", "IPv6"),
    9 : "Reserved",
    10 : ("INTERNAL_IP6_DNS", "IPv6DNS"),
    11 : ("INTERNAL_IP6_NBNS", "IPv6NBNS"),
    12 : ("INTERNAL_IP6_DHCP", "IPv6DHCP"),
    13 : ("INTERNAL_IP4_SUBNET", "IPv4SN"),
    14 : ("SUPPORTED_ATTRIBUTES", "SUPP"),
    15 : ("INTERNAL_IP6_SUBNET", "IPv6SN"),
    16 : ("MIP6_HOME_PREFIX", "MIPv6HP"),
    17 : "Unassigned",
    16384 : "Private",
    32768 : "Invalid",
    65535 : "Invalid",
    })



class IKEv2(Block):
    
    def __init__(self, SPIi=8*'\x00', SPIr=8*'\x00', type=34, flag='\x08', msgID=0):
        Block.__init__(self, Name="IKEv2")
        self.append( IKEv2_hdr(SPIi, SPIr, type, flag, msgID) )
    
    # manages "next payload" value:
    def pull_np(self, newLayer):
        #check the last layer in self which has np attribute and take it
        if hasattr(newLayer, "Ptype"):
            index = newLayer.get_index()
            while not hasattr(self[index-1], "np"): 
                index -= 1
                if index == 0: return
            self[index-1].np.Pt = int(newLayer.Ptype)
    
    # manages last or not for SA Proposals, and Proposal number:
    def pull_PropLast(self, newLayer):
        if isinstance(newLayer, Prop):
            i = newLayer.get_index()
            while i > 0: 
                i -= 1
                if isinstance(self[i], Prop):
                    self[i].last > 2 # more proposals to come
                    newLayer.Pnum.Pt += 1
                elif isinstance(self[i], pay_SA):
                    i = 0
    
    # manages last or not and SA Proposal Transforms:
    def pull_TransLast(self, newLayer):
        if isinstance(newLayer, Trans):
            i = newLayer.get_index()
            while i > 0:
                i -= 1
                if isinstance(self[i], Trans):
                    self[i].last > 3 # more transforms to come
                elif isinstance(self[i], Prop):
                    i = 0
    
    # overrides Block.append() method
    def append(self, layer):
        if isinstance( layer, Layer ):
            self.layerList.append(layer)
            layer.inBlock = True
            layer.Block = self
            self.pull_np(layer)
            self.pull_PropLast(layer)
            self.pull_TransLast(layer)
    
    def __lt__(self, newLayer):
        # to use when appending a payload with hierarchy 1
        self.append(newLayer)
        self[-1].hierarchy = self[0].hierarchy + 1
    
    # parser for SA Proposals:
    def parseProp(self, s):
        # create a Proposal Block where Prop() is the "header":
        Proposal = Block("Proposal")
        Proposal.append( Prop() ) #hierarchy = 0
        Proposal[0].map( s )
        # get the string with the Proposal content:
        s = s[ len(Proposal[0]) : int(Proposal[0].len) ]
        Tnum = int(Proposal[0].Tnum)
        
        # loop for the "num" Transforms referenced in the Proposal
        while Tnum > 0:
            Proposal.append( Trans() )
            Proposal[-1].hierarchy = 1
            Proposal[-1].map( s )
            s = s[ 8 : ]
            Tnum -= 1
            
            # check for errors in the Transform parsing process:
            if Tnum > 0 and Proposal[-1].last == 0:
                print '[WNG] error in parsing the SA proposal'
            elif Tnum == 0 and Proposal[-1].last == 3:
                print '[WNG] error in parsing the SA proposal'
            if int(Proposal[-1].last) not in (0, 3):
                print '[WNG] strange Transorm format...'
            
            # parse possible attributes 
            # (multiple attributes possible for 1 transform):
            attlen = int(Proposal[-1].len) - 8
            atts = s[:attlen]    # string for Transform's attributes
            s = s[attlen:]    # string for next Transform
            while len(atts) > 0:
                #determine type of attribute: TV or TLV:
                if int(atts[0].encode('hex'), 16) >= 0x80:
                    # TV format:
                    Proposal.append( TransTV() )
                    Proposal[-1].hierarchy = 2
                    Proposal[-1].map( atts )
                    atts = atts[ 4 : ]
                else:
                    # TLV format:
                    Proposal.append( TransTLV() )
                    Proposal[-1].hierarchy = 2
                    Proposal[-1].map( atts )
                    atts = atts[ len(Proposal[-1]) : ]
        
        # finally returns the Proposal Block for extending the IKEv2 Block with
        return Proposal
    
    # parser for IKEv2 payload: manage specific payloads wich need extra layers
    def parsePay(self, s, np, enc_iv_len=16, mac_len=12):
        # parse IKEv2 payload:
        self.append( payCall[np]() )
        self[-1].hierarchy = 1
        # for encrypted payload, align the length of the init vector, 
        # depends of the chosen encryption algorithm
        if type(self[-1]) is pay_Enc: self[-1].iv.Pt = enc_iv_len
        # map the string on the layer
        #print '\n[DBG] possible parsing (map) issue with:\nLayer: %s\nString: %s\n' \
        #       % ( type(self[-1]), s )
        self[-1].map( s )
        # define info for next payload:
        np = int(self[-1].np)
        # tuncate the remaining string for the next layer
        s = s[ len(self[-1]) : ]
        
        # specific processing for extended payloads: SA, TS, CP
        if type(self[-1]) is pay_SA:
            # parse Proposals until the last one:
            last = 2
            SA_hierarchy = self[-1].hierarchy
            while last != 0:
                prop = self.parseProp( s )
                last = int(prop[0].last)
                prop.inc_hierarchy( SA_hierarchy )
                self.extend( prop )
                s = s[ int(prop[0].len) : ]
            
        elif type(self[-1]) in (pay_TSi, pay_TSr):
            # parse Traffic Selectors until the last one:
            TSnum = int(self[-1].TSnum)
            while TSnum > 0:
                self.append( TS() )
                self[-1].hierarchy = 2
                self[-1].map( s )
                TSnum -= 1
                s = s[ int(self[-1].Slen) : ]
            
        elif type(self[-1]) is pay_CP:
            # parse Configuration attributes (TLV fashion) until the last one:
            cflen = int(self[-1].len) - 8
            while cflen > 0:
                self.append( Cfg() )
                self[-1].hierarchy = 2
                self[-1].map( s )
                cflen -= len(self[-1])
                s = s[ len(self[-1]) : ]
            
        elif type(self[-1]) is pay_Enc:
            # parse with Enc() layer
            enc_len = int(self[-1].len) - len(self[-1]) - mac_len
            self.append( Enc() )
            self[-1].hierarchy = 1
            self[-1].Enc.Len = enc_len
            self[-1].map( s )
            s = s[ len(self[-1]) : ]
            
            if len(s) != mac_len: "[WNG] strange remaining length for MAC"
            # finalize with a MAC() layer
            self.append( MAC() )
            self[-1].hierarchy = 1
            self[-1].MAC.Len = mac_len
            self[-1].map(s)
            # when not decrypted: 
            # return not to continue to parse following IKEv2 payloads
            return '', 0
        
        # return remaining string, and next payload code
        return s, np
    
    # IKEv2 global parser: build the right IKEv2 block with correct layers, 
    # while mapping the submitted string
    def parse(self, s, mac_len=12, enc_iv_len=16):
        # parse IKEv2 header
        self[0].map(s)
        s = s[ len(self[0]) : ]
        np = int( self[-1].np )
        # loop for parsing payloads
        while np != 0:
            s, np = self.parsePay(s, np, mac_len=mac_len, enc_iv_len=enc_iv_len)
        if len(s) > 0: print '[WNG] parsing let some remaining string...'
    
    # cipher payloads after the pay_Enc() one, and add MAC
    def protect(self, enc_key, mac_key, enc_alg=12, mac_alg=2):
        # must take all IKEv2 payloads after pay_Enc(), 
        # cipher the corresponding string, pad it, put it into Enc() layer, 
        # and append MAC() layer
        index = 0
        while type(self[index]) != pay_Enc:
            index += 1
        
        # cipher data, remove existing payloads, and put everything in Enc()
        data = ''
        for layer in self[ index+1 : ]: 
            data += str(layer)
        #print '\n[DBG] data to cipher and length: %s, %s\n' \
        #       % ( len(data), hexlify(data) )
        encr_data = self[index].cipher( data, enc_key, enc_alg )
        self.remove( index+1, self.num() )
        self.append( Enc(encr_data) )
        self[-1].hierarchy = self[index].hierarchy
        
        # append a null MAC so that the length reported in the IKEv2 header is correct, 
        # but do not compute the MAC over this null value: ...whatelse
        self.append( MAC(12*'\x00') )
        self[-1].hierarchy = self[index].hierarchy
        #print '[DBG]', len(self), str(self)
        # warning: MAC length hardcoded
        mac = self[index].computeMAC( str(self)[:-12], mac_key, mac_alg )
        # put the right MAC value in the MAC layer
        self.MAC.MAC.Pt = mac
    
    # verify MAC, and decipher the pay_Enc() content
    def unprotect(self, enc_key, mac_key, enc_alg=12, mac_alg=2):
        # must verifiy MAC() layer content and remove MAC() layer, 
        # take Enc() layer content and remove Enc() layer, decipher it and parse it
        index = 0
        while type(self[index]) != pay_Enc:
            index += 1
        # verify MAC (last layer of the block)
        if mac_alg != 0:
            mac = str(self[-1].MAC)
            self[-1].MAC < 12*'\0'
            # warning: MAC length hardcoded
            if self[index].computeMAC(str(self)[:-12], mac_key, mac_alg) != mac:
                print '[WNG] MAC is not correct'
                # return
            self.remove(self.num()-1)
        # uncipher Enc() (last layer of the block)
        data = str( self[-1] )
        data = self[index].uncipher( data, enc_key, enc_alg )
        # remove last layer ( Enc() )
        self.remove( self.num()-1 )
        # parse the IKEv2 payloads remaining
        s = data
        np = int(self[index].np)
        while np != 0:
            # TODO: MAC and IV length hardcoded
            s, np = self.parsePay(s, np, mac_len=12, enc_iv_len=16)
        if len(s) > 0: print '[WNG] parsing let some remaining string...'
    


class IKEv2_hdr(Layer):
    # first define the layout of your layer 
    constructorList = [
        Str(CallName='SPIi', ReprName='SPI initiator', Len=8, Repr="hex"),
        Str(CallName='SPIr', ReprName='SPI responder', Len=8, Repr="hex"),
        Int(CallName='np', ReprName='Next Payload', Type='uint8', Dict=PayloadType),
        Str(CallName='ver', ReprName='Version', Pt='\x20', Len=1, Repr="hex"),
        Int(CallName='type', ReprName='Exchange Type', Type='uint8', Dict=ExchangeType),
        Str(CallName='flag', ReprName='Flags', Len=1, Repr="hex"),
        Int(CallName='msgID', ReprName='Message Identifier', Type="uint32"),
        Int(CallName='len', ReprName='Length', Type="uint32"),
        ]
    
    # then define the instantiation process when initializing
    def __init__(self, SPIi=8*'\x00', SPIr=8*'\x00', type=34, flag='\x08', msgID=0):
        # first call the instantiation method from the parent object "Layer"
        Layer.__init__(self, CallName='hdr', ReprName='IKEv2 header')
        # define the parameters given for initialization
        self.SPIi.Pt = SPIi
        self.SPIr.Pt = SPIr
        self.type.Pt = type
        self.flag.Pt = flag
        self.msgID.Pt = msgID
        # finally define relationships between fields 
        # for some automation (here: length parameter)
        self.len.Pt = self.get_payload
        #self.len.Pt = 36
        #self.len.PtFunc = lambda Pt: len(Pt())+28
        self.len.PtFunc = lambda pay: 4 + len(pay()) + len(self.SPIi) + \
            len(self.SPIr) + len(self.np) + len(self.ver) + \
            len(self.type) + len(self.flag) + len(self.msgID)

class pay_gene(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=1, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='gene', ReprName='generic')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda Pt: len(Pt())+4

class pay_SA(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=33, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='SA', ReprName='Security Association')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda Pt: len(Pt())+4

class Prop(Layer):
    constructorList = [
        Int(CallName='last', Pt=0, Type='uint8', Dict={0:"last", 2:"more"}),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='Pnum', ReprName='Proposal number', Pt=1, Type='uint8'),
        Int(CallName='pID', ReprName='Protocol ID', Type='uint8', Dict=ProtocolID),
        Int(CallName='SPIs', ReprName='SPI size', Type='uint8'),
        Int(CallName='Tnum', ReprName='number of Transforms', Type='uint8'),
        Str(CallName='SPI', Repr="hex"),
        ]
    
    def __init__(self, pID=1, SPI=''):
        Layer.__init__(self, CallName='Prop', ReprName='Proposal')
        self.pID.Pt = pID
        self.SPI.Pt = SPI
        self.SPI.Len = self.SPIs
        self.SPI.LenFunc = lambda SPIs: int(SPIs)
        self.SPIs.Pt = self.SPI
        self.SPIs.PtFunc = lambda SPI: len(SPI)
        self.Tnum.Pt = 0
        self.Tnum.PtFunc = lambda pay: self.__count_Tnum()
        self.len.Pt = (self.get_payload, self.SPI)
        self.len.PtFunc = lambda (pay, SPI): len(pay())+8+len(SPI)
    
    def __count_Tnum(self):
        i = 0
        for l in self.get_payload():
            if type(l) is Trans: i+=1
        return i
    
class Trans(Layer):
    constructorList = [
        Int(CallName='last', Pt=0, Type='uint8', Dict={0:"last", 3:"more"}),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='type', ReprName='Transform type', Type='uint8', \
            Dict=TransformType),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='tID', ReprName='Transform ID', Type='uint16'),
        ]
    
    def __init__(self, type=1, tID=11):
        Layer.__init__(self, CallName='Trans', ReprName='Transform')
        self.type.Pt = type
        self.tID.Pt = tID
        self.tID.Dict = TransformID[int(self.type)]
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8
    
    # really dirty way to manage pseudo-dynamically the tID dictionnary, 
    # depending on the type of transformation...
    def __repr__(self):
        self.tID.Dict = TransformID[int(self.type)]
        return Layer.__repr__(self)
    
    def show(self):
        self.tID.Dict = TransformID[int(self.type)]
        return Layer.show(self)
    
    def map(self, string=''):
        Layer.map(self, string)
        self.tID.Dict = TransformID[int(self.type)]

class TransTV(Layer):
    constructorList = [
        Int(CallName='T', ReprName='Type', Type='uint16', Dict=TransAttType),
        Str(CallName='V', ReprName='Value', Len=2, Repr='hex'),
        ]
    
    def __init__(self, T=14+0x8000, V=None):
        Layer.__init__(self, CallName='TransTV', ReprName='Transform Attribute TV')
        self.T.Pt = T
        self.V.Pt = V

class TransTLV(Layer):
    constructorList = [
        Int(CallName='T', ReprName='Type', Type='uint16', Dict=TransAttType),
        Int(CallName='L', ReprName='Length', Type='uint16'),
        Str(CallName='V', ReprName='Value'),
        ]
    
    def __init__(self, T=0x4000, V=None):
        Layer.__init__(self, CallName='TransTLV', ReprName='Transform Attribute TLV')
        self.T.Pt = T
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)

class pay_KE(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=34, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='dhg', ReprName='DH Group', Type='uint16', Dict=TransformID[4]),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00', Len=2, Repr="hex"),
        Str(CallName='ked', ReprName='Key Exchange Data', Repr="hex"), 
        ]
    
    def __init__(self, dhg=2, ked=None):
        Layer.__init__(self, CallName='KE', ReprName='Key Exchange')
        self.dhg.Pt = dhg
        self.ked.Pt = ked
        self.ked.Len = self.len
        self.ked.LenFunc = lambda len: int(len)-8
        self.len.Pt = self.ked
        self.len.PtFunc = lambda ked: len(ked)+8

class pay_IDi(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=35, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='idt', ReprName='ID Type', Pt=1, Type='uint8', Dict=IdentityType),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        Str(CallName='idd', ReprName='Identification Data'), 
        ]
    
    def __init__(self, idt=1, idd=None):
        Layer.__init__(self, CallName='IDi', ReprName='Initiator Identification')
        self.idt.Pt = idt
        self.idd.Pt = idd
        self.idd.Len = self.len
        self.idd.LenFunc = lambda len: int(len)-8
        self.len.Pt = self.idd
        self.len.PtFunc = lambda idd: len(idd)+8

class pay_IDr(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=36, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='idt', ReprName='ID Type', Type='uint8', Dict=IdentityType),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        Str(CallName='idd', ReprName='Identification Data'), 
        ]
    
    def __init__(self, idt=1, idd=None):
        Layer.__init__(self, CallName='IDr', ReprName='Responder Identification')
        self.idt.Pt = idt
        self.idd.Pt = idd
        self.idd.Len = self.len
        self.idd.LenFunc = lambda len: int(len)-8
        self.len.Pt = self.idd
        self.len.PtFunc = lambda idd: len(idd)+8

class pay_CERT(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=37, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='ce', ReprName='Certificate Encoding', Type='uint8', \
            Dict=CertificateEncoding),
        Str(CallName='cd', ReprName='Certificate Data'),
        ]
    
    def __init__(self, ce=1, cd=None):
        Layer.__init__(self, CallName='CERT', ReprName='Certificate')
        self.ce.Pt = ce
        self.cd.Pt = cd
        self.cd.Len = self.len
        self.cd.LenFunc = lambda len: int(len)-5
        self.len.Pt = self.cd
        self.len.PtFunc = lambda cd: len(cd)+5

class pay_CERTREQ(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=38, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='ce', ReprName='Certificate Encoding', Type='uint8', \
            Dict=CertificateEncoding),
        Str(CallName='ca', ReprName='Certificate Authority'),
        ]
    
    def __init__(self, ce=1, ca=None):
        Layer.__init__(self, CallName='CERTREQ', ReprName='Certificate Request')
        self.ce.Pt = ce
        self.ca.Pt = ca
        self.ca.Len = self.len
        self.ca.LenFunc = lambda len: int(len)-5
        self.len.Pt = self.ca
        self.len.PtFunc = lambda ca: len(ca)+5

class pay_Auth(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=39, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='am', ReprName='Authentication Method', Type='uint8', \
            Dict=AuthMethod),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        Str(CallName='ad', ReprName='Authentication Data'),
        ]
    
    def __init__(self, am=2, ad=None):
        Layer.__init__(self, CallName='Auth', ReprName='Authentication')
        self.am.Pt = am
        self.ad.Pt = ad
        self.ad.Len = self.len
        self.ad.LenFunc = lambda len: int(len)-8
        self.len.Pt = self.ad
        self.len.PtFunc = lambda ad: len(ad)+8
    
class pay_N(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=40, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Str(CallName='n', ReprName='Nonce', Repr="hex"),
        ]
    
    def __init__(self, n=None):
        Layer.__init__(self, CallName='N', ReprName='Nonce')
        self.n.Pt = n
        self.n.Len = self.len
        self.n.LenFunc = lambda len: int(len)-4
        self.len.Pt = self.n
        self.len.PtFunc = lambda n: len(n)+4
    
class pay_Not(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=41, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='pID', ReprName='Protocol ID', Type='uint8', Dict=ProtocolID),
        Int(CallName='SPIs', ReprName='SPI size', Type='uint8'),
        Int(CallName='nott', ReprName='Notify Type', Type='uint16', Dict=NotifyType),
        Str(CallName='SPI', Repr="hex"),
        Str(CallName='notm', ReprName='Notify Message'),
        ]
    
    def __init__(self, pID=1, nott=0, SPI='', notm=None):
        Layer.__init__(self, CallName='Not', ReprName='Notify')
        self.pID.Pt = pID
        self.nott.Pt = nott
        self.SPI.Pt = SPI
        self.SPI.Len = self.SPIs
        self.SPI.LenFunc = lambda SPIs: int(SPIs)
        self.notm.Pt = notm
        self.notm.Len = (self.len, self.SPIs)
        self.notm.LenFunc = lambda (len, SPIs): int(len)-int(SPIs)-8
        self.SPIs.Pt = self.SPI
        self.SPIs.PtFunc = lambda SPI: len(SPI)
        self.len.Pt = (self.SPI, self.notm)
        self.len.PtFunc = lambda (SPI, notm): len(SPI)+len(notm)+8

class pay_Del(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=42, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='pID', ReprName='Protocol ID', Type='uint8', Dict=ProtocolID),
        Int(CallName='SPIs', ReprName='SPI size', Type='uint8'),
        Int(CallName='Snum', ReprName='number of SPIs',Type='uint16'),
        Str(CallName='SPI', Repr="hex"),
        ]
    
    def __init__(self, pID=1, Snum=1, SPI=''):
        Layer.__init__(self, CallName='Del', ReprName='Delete')
        self.pID. Pt = pID
        self.Snum.Pt = Snum
        self.SPI.Pt = SPI
        self.SPI.Len = (self.SPIs, self.Snum)
        self.SPI.LenFunc = lambda (SPIs, Snum): int(SPIs)*int(Snum)
        self.SPIs.Pt = (self.SPI, self.Snum)
        self.SPIs.PtFunc = lambda (SPI, Snum): len(SPI)*int(Snum)
        self.len.Pt = self.SPI
        self.len.PtFunc = lambda SPI: len(SPI)+8

class pay_V(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=43, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Str(CallName='vid', ReprName='Vendor ID'),
        ]
    
    def __init__(self, vid=None):
        Layer.__init__(self, CallName='V', ReprName='Vendor ID')
        self.vid.Pt = vid
        self.vid.Len = self.len
        self.vid.LenFunc = lambda len: int(len)-4
        self.len.Pt = self.vid
        self.len.PtFunc = lambda vid: len(vid)+4

class pay_TSi(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=44, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='TSnum', ReprName='number of TS', Type='uint8'),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='TSi', ReprName='Initiator Traffic Selectors')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8
        self.TSnum.Pt = self.get_payload
        self.TSnum.PtFunc = lambda pay: pay().num()

class pay_TSr(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=45, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='TSnum', ReprName='number of TS', Type='uint8'),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='TSr', ReprName='Responder Traffic Selectors')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8
        self.TSnum.Pt = self.get_payload
        self.TSnum.PtFunc = lambda pay: pay().num()

class TS(Layer):
    constructorList = [
        Int(CallName='TSt', ReprName='TS Type', Type='uint8', Dict=TSType),
        Int(CallName='IPpID', ReprName='IP protocol ID', Type='uint8', Dict=IP_prot),
        Int(CallName='Slen', ReprName='Selector Length', Type='uint16'),
        Int(CallName='sp', ReprName='Start Port', Type='uint16'),
        Int(CallName='ep', ReprName='End Port', Type='uint16'),
        Str(CallName='sa', ReprName='Start Address'),
        Str(CallName='ea', ReprName='End Address'),
        ]
    
    def __init__(self, TSt=7, IPpID=0, sp=0, ep=65535, sa=None, ea=None):
        Layer.__init__(self, CallName='TS', ReprName='Traffic Selector')
        self.TSt.Pt = TSt
        self.IPpID.Pt = IPpID
        self.sp.Pt = sp
        self.ep.Pt = ep
        self.sa.Pt = sa
        self.sa.Len = self.Slen
        self.sa.LenFunc = lambda Slen: (int(Slen)-8)/2
        self.ea.Pt = ea
        self.ea.Len = self.Slen
        self.ea.LenFunc = lambda Slen: (int(Slen)-8)/2
        self.Slen.Pt = (self.sa, self.ea)
        self.Slen.PtFunc = lambda (sa, ea): len(sa)+len(ea)+8
        
    # represent the address in a nice IPv4 format, if possible
    def __repr__(self):
        if len(self.sa) == 4: self.sa.Repr = 'ipv4'
        if len(self.ea) == 4: self.ea.Repr = 'ipv4'
        return Layer.__repr__(self)

class pay_Enc(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=46, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Str(CallName='iv', ReprName='Initialization Vector', Len=16, Repr="hex"),
        ]
    
    # padding bytes
    pad = '\x00'
    # from TransformID[1]: encryption algorithms, provides a 3-tuples of 
    # ( key length, IV length, max padding length -block length-)
    enc_alg = {
        11 : (0, 0, 0), # null
        2 : (8, 8, 8), # des
        3 : (24, 8, 8), # 3des
        12 : (16, 16, 16), # aes-cbc
        }
    # TransformID[3]: MAC algorithms
    mac_alg = [ 0, # none
                1, # hmac-md5-96
                2, # hmac-sha1-96
               ]
    
    def __init__(self, iv=None):
        Layer.__init__(self, CallName='Enc', ReprName='Encrypted')
        self.iv.Pt = iv
        # encrypt all layers appended after pay_Enc(), 
        # does not need to check for payloads
        self.len.Pt = self.get_index
        self.len.PtFunc = lambda ind: self.__get_length( ind() )
    
    def __get_length(self, index):
        length = 4 + self.iv.Len
        if hasattr(self, "Block"):
            for layer in self.Block[ index+1 : ]:
                length += len(layer)
        return length
        
    def cipher(self, data, key, alg=12):
        if alg not in self.enc_alg.keys(): 
            print '[WNG]: encryption algorithm not supported'
        if len(key) != self.enc_alg[alg][0]: 
            print '[WNG]: key must be %s bytes long' % self.enc_alg[alg][0]
        # adjust IV length
        self.iv.Len = self.enc_alg[alg][1]
        # manage IV automatically
        if self.iv.Pt is None: 
            self.iv.Pt = urandom( self.enc_alg[alg][1] )
        elif len(self.iv) != self.iv.Len: 
            self.iv.Pt += (self.iv.Len - len(self.iv)) * self.pad
        
        if len(data) >= 1:
            # pad data with padding bytes, adjust with the max padding length
            if alg != 11:
                pad_num = self.enc_alg[alg][2] - 1 - (len(data) % self.enc_alg[alg][2])
                data += pad_num * self.pad
                data += pack('!B', pad_num)
                # initialize algorithm
                if alg == 12: alg = AES.new(key=key, mode=2, IV=str(self.iv))
                elif alg == 2: alg = DES.new(key=key, mode=2, IV=str(self.iv))
                elif alg == 3: alg = DES3.new(key=key, mode=2, IV=str(self.iv))
                # add more algs to support here; taken from pycrypto
                ciph = alg.encrypt(data)
            else: ciph = data
            return ciph
        else: 
            print '[WNG]: .cipher(data, key): needs data of minimum length 1'
            return ''
    
    def uncipher(self, data, key, alg=12):
        if alg not in self.enc_alg: 
            print '[WNG]: encryption algorithm not supported'
        if len(key) != self.enc_alg[alg][0]: 
            print '[WNG]: key must be %s bytes long' % self.enc_alg[alg][0]
        if self.iv.Len != self.enc_alg[alg][1]: 
            print '[WNG]: IV must be %s bytes long' % self.enc_alg[alg][1]
        
        if len(data) >= 1:
            if alg != 11:
                if alg == 12: alg = AES.new(key=key, mode=2, IV=str(self.iv))
                elif alg == 2: alg = DES.new(key=key, mode=2, IV=str(self.iv))
                elif alg == 3: alg = DES3.new(key=key, mode=2, IV=str(self.iv))
                # add more algs to support here; taken from pycrypto
                unciph = alg.decrypt(data)
                # remove padding bytes
                pad_num = unpack('!B', unciph[len(unciph)-1:])[0]
                unciph = unciph[ : len(unciph)-pad_num-1]
            else: unciph = data
            return unciph
        else: 
            print '[WNG]: .cipher(data, key): needs data of minimum length 1'
            return ''
        
    def computeMAC(self, data, key, alg=2):
        # must compute the MAC on the all IKEv2 block with MAC as padding,
        #print 'MAC alg:', alg
        if alg not in self.mac_alg: 
            print '[WNG]: MAC algorithm not supported'
            mac = ''
        if alg == 0: 
            mac = ''
        elif alg == 1:
            mac = hmac.new(key, data, hashlib.md5).digest()[0:12]
        elif alg == 2:
            mac = hmac.new(key, data, hashlib.sha1).digest()[0:12]
        return mac

# defines RawLayer for encrypted payload and MAC
class Enc(Layer):
    constructorList = [
        Str(CallName="Enc", Pt=""),
        ]
    
    def __init__(self, Enc=""):
        Layer.__init__(self, CallName="Enc")
        self.Enc.Pt = Enc

class MAC(Layer):
    constructorList = [
        Str(CallName="MAC", Pt="", Repr="hex"),
        ]
    
    def __init__(self, MAC=""):
        Layer.__init__(self, CallName="MAC")
        self.MAC.Pt = MAC


class pay_CP(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=47, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Int(CallName='cft', ReprName='Configuration Type', Type='uint8', Dict=CfgType),
        Str(CallName='res2', ReprName='Reserved2', Pt='\x00\x00\x00', Len=3, Repr="hex"),
        ]
    
    def __init__(self, cft=1):
        Layer.__init__(self, CallName='CP', ReprName='Configuration')
        self.cft.Pt = cft
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+8

class Cfg(Layer):
    constructorList = [
        Int(CallName='T', ReprName='Type', Type='uint16', Dict=CfgAttType),
        Int(CallName='L', ReprName='Length', Type='uint16'),
        Str(CallName='V', ReprName='Value'),
        ]
    
    def __init__(self, T=1, V=None):
        Layer.__init__(self, CallName='Cfg', ReprName='Configuration Attribute')
        self.T.Pt = T
        self.V.Pt = V
        self.V.Len = self.L
        self.V.LenFunc = lambda L: int(L)
        self.L.Pt = self.V
        self.L.PtFunc = lambda V: len(V)

class pay_EAP(Layer):
    constructorList = [
        Int(CallName='Ptype', ReprName="Payload Type", Pt=48, Type='uint8', \
            Dict=PayloadType, Trans=True),
        Int(CallName='np', ReprName='Next Payload', Pt=0, Type='uint8', \
            Dict=PayloadType),
        Str(CallName='res', ReprName='Reserved', Pt='\x00', Len=1, Repr="hex"),
        Int(CallName='len', ReprName='Length', Type='uint16'),
        Str(CallName='eapd', ReprName='EAP Data'),
        ]
    
    def __init__(self, eapd=None):
        Layer.__init__(self, CallName='EAP', \
            ReprName='Extensible Authentication Protocol')
        self.eapd.Pt = eapd
        self.eapd.Len = self.len
        self.eapd.LenFunc = lambda len: int(len)-4
        self.len.Pt = self.eapd
        self.len.PtFunc = lambda eapd: len(eapd)+4

# define the dictionnary to call IKEv2 payload Layer object from their identifier 
payCall = {
    33 : pay_SA,
    34 : pay_KE,
    35 : pay_IDi,
    36 : pay_IDr,
    37 : pay_CERT,
    38 : pay_CERTREQ,
    39 : pay_Auth,
    40 : pay_N,
    41 : pay_Not,
    42 : pay_Del,
    43 : pay_V,
    44 : pay_TSi,
    45 : pay_TSr,
    46 : pay_Enc,
    47 : pay_CP,
    48 : pay_EAP,
    }


# and finally, a testing function:
def test(num=3):
    from binascii import unhexlify
    
    tests = [
    #IKE_SA_INIT_REQ:
    "2ceb0cf84910117600000000000000002120220800000000000000ec220000300000002c010100040300000c0100000c800e00800300000802000002030000080300000200000008040000022800008800020000567f1b3671ba76bb0f7f58f484d60058573350c48ff90f2ed1e5b53e803b99a88f043c0239b07799d67f16a23c99ddd6b5c2d5f8122e6540559021baa35cce5b0259a5fd834b1782cd606575029a772d506a0922bef60f41ce5116c2f811e8dbde7dfd168c12a15b80e975a5bfa35e17eff446bf1fe2f3d3ec7d5c62145ce567000000189bf6d53d9628dffbfc2cca392710112c39d99752",
    #IKE_SA_INIT_RES:
    "2ceb0cf84910117640448616060000d42120222000000000000000e8220000300000002c010100040300000c0100000c800e00800300000802000002030000080300000200000008040000022800008800020000e9488abebb2c4ccf361f078a0572c727ad04fd83a84ab9f975630d499a8b306a3513d8f80f8ff387386db47fc5ddd4e37fba54a995c0b8904a701f25fd377a05590656f9148c5e6f718eeed281d851b1f4e9b7eb1eed72327935d02659594bfbf9e505ce49e5986b8e530ff7299b97d27f3d4b6ea032851965dd7fdfcbbcec92000000144a603a2719cdc69ba66fb58f30bf16b7",
    #IKE_AUTH_REQ1:
    "2ceb0cf84910117640448616060000d42e202308000000010000015c23000140070983d4b7c45c0899920e243c30c131bdc8a86dfd6abfdb94f1c1cae7f10638ff4872bbf9d1f04923025caf24b35a608b04a236d3ffc19f4b3d1da998f31429debf7e1646c72a32d7b03462141332accc8ce07131b126c7b677d874e3a52b8f630ab2378960ef9dfc2d648fc6a8e67049103cc9e78b10db430107080daff289e6fa0f6da273d5592cb68294db19ad60fda98610e642590925c6a52fd0bd6a54b23d1772c389affc5313a692f6983f4ab9fa713d98935e8dc6e1fd7a6aa2309d38426c63ca8e63f1556e6f8118b6149a1a7d5ca0f7a3a9934fa0c5372e09c78c6b4ae55f222b78f1dae88f0adbcb8c6b8dcd9eaa2c4d5faa73979c5b6bdb8bcd0457e1cf68470c6ecc312940bdd6a8d56200751ae20d41e32d35f51edf136a4944f58fe6c8d390cff466bd75dbc27cb204e357302ec63490ce4e0296",
    #IKE_AUTH_RES1:
    "2ceb0cf84910117640448616060000d42e202320000000010000044c2400043033491b183a9262fd3b7f7e5712ab3996112668a25d5bec067f410a40e822449cc2b29d64c333c86cc6a90298634cf07756647943f02a09b8ce9c68685971b3f641469118b2c6eafe797dca456f72b3a083493d91131ce081a2231a1674f453e0e45dc7dcff3bbfd4b106ee5da147fce9df503135f0d3ca95fe5d3d054e92038d346e71f6261c6131e27105f3e1cb6681ee34525884a0a524f3fd1602438e70291fe396a2efa9f6222541f2bcfe840a097140e1921ab40764c9eefbd67bafcf6370772771018741db1e8c498a60221f25b84a4813df082fbf585fe6551ad25f01269f0c5e06c5b1f818d4a59a94ba9c5ec4ccf90afdfae53be4dcfe716a909fe813e746337cd75c3b46e5a4e069800ba6061de1354ad32c9c53bc9f5848e8a95536c439a6f1f621e48c79f212230a3289046be289b1357f7b660b0700b1ad4a8634793eacf4c39a564f9d6f87c078eea3edf1b10d59d81d1ce6fc665038f1d0ef12060e872a11030b2ec1cd7246c316a89ec51b622418b55006cff5848a719ace50702585db5d77f92c66c47f84af2a7d9ba7d4c06479814cd105ffd5bd1e504cfbb2f401e3822703fe00ebb3940fe20452d1779530fb3d9f00eeb493ff48ccc6d3e6cf5ae0c98459f73948fc6ff9b4fad4cb05c20028c41e91ec7830a13fa7fbdc62e3eeffab6849d26bbdf9b45b07af4aec131376093587ef6da60a5b049c9e8b82703cbca9a0eb82b1ce868ad489b02b435726523f7bc6d1aa771b0b24a51aa88a701674f42ef723cd51153fee51d4849a5e3426c2c059b632b990d4b5aab83af6de31dc62a4e8f19364070d3994402659f4cd05ca9dfdedf59b42628497e2b0b2d8f9bef5aedf26b8824ba71719e2bb57459ea057ae7795482007f5e420c382aea2fc7e0a1eaac7e7ae7d0c415cf8b11a25ce2871327dffdab58b30f36296974936aafb78749cdf942df5ab97f73e7a80f80382f4b44ff917d6aa67df303a832df4b8b37537133165977ac323618f394212dc7049aa345c6a3ccd67012201ff389f07dcded49fb46686aff17f450650ca5265c81229107516b082e8c40c3b5c0b01e1c2de72810a4901121c034f32e3bef63b3a6fe71c9dabf69cec387a3fec98a7c29f998670b661d0f5d6a041b7f844a24827fb027178cfb5630be0ff0c0aaf64e66f5c9c909ffd1eb48ce385dccad0d5d0f2200279a074a1ae11fa09410e3355694dbafb0ea61623c0104704a81d1cc20835406e0595935e2e7fbf04bd9c9dfcb14af3a02053ac909540df53bb6897b299f1a2ab2f170a459f40291b6aff4fb5ba98aa7b87a85805f66b848a1fe4743fee112e6f142fb8469ab4cdd5524e98dcae974b0e13df42e4fb156a7970125225b7953a15b6f877a3eea5df9df2b1110a80c7de9ac37e613caf5c77291d4de105902134a8c11ac795e3d100925198cbfab84acfce74a6cdece4b98ac719e6b6dc495e6567c55af1e63c79de5f403f3bd27987256c97fe3aba0b",
    #IKE_AUTH_REQ2:
    "2ceb0cf84910117640448616060000d42e202308000000020000008c30000070d0e3faab1a6252611daf638483e2e7ad1a0777a3236e467a0c36c9693cde12b275d56534a5a4b2db9800453b42d6ac02663f13a9911b0b7cb5757195d5a6e2e97ea8c7a3336ad7cd5f693ff0ec8ba1a14a4abdcba2b212fbc35dcbd46d466b344da5e5e6dce021753f11446b",
    #IKE_AUTH_RES2:
    "2ceb0cf84910117640448616060000d42e20232000000002000000ec300000d0314333cba2283c2182593a92e13a6344170906b7012020625277d52487a340af8e2c483ec703d907d9aa88714b2e0dba188447025ff4ba7392d42a15a29a573c07c91e3790c20d6f4ddbdca61013cea2abd07ea16385601d058dfb8035e6cff46fe44067cd8db47885fffe1a27e03be62bc70ae468404dcefe94c932d513eec2acd2dc1d9ab03b154d242873f97b806e7506142eaf8749295434f8d3c8c38b39f4289213e5c845312ca654fb2b8938062fd5e7b897638bc7e452bbda33bf74fbbc4f5e2062e90e1bd543f58e",
    #IKE_AUTH_REQ3:
    "2ceb0cf84910117640448616060000d42e202308000000030000008c30000070d07a003fe6bde33bf1dfd8df2c77af13f990206121f1d6805b302832ae90605e4121c1c85bbf0f881138eabbc51a23a08526b6814d6945dc8fdd186f8d028d9082109f81c60f041f723af5fd63374b47fc653c399fed0afb6d88e3b4146bdfd66a79503147139523d2a61cf7",
    #IKE_AUTH_RES3:
    "2ceb0cf84910117640448616060000d42e202320000000030000004c30000030af440673d4ab82bc9833a7cfd6319288d237f902fd2b5c35403abda4c88e959e9accb1c038f15b88e34e6f06",
    #IKE_AUTH_REQ4:
    "2ceb0cf84910117640448616060000d42e202308000000040000005c27000040709ec0f632b632b78941b9b6a11759e13fc0ab69fccb6244f3419675e8d1cc79f05d39f526e22bf2323d7ffb0cab9d29eaf496e36b507cc14e92bdd4",
    #IKE_AUTH_RES4:
    "2ceb0cf84910117640448616060000d42e20232000000004000000dc270000c0b9712be8201a72d2abab23d1cdd71ac80765451c7334f79bed84a90792388e7677210423604046a0b64ab1d0f219b17e2e2936b4c5f52378ef8c2bf4643e8d6948a5b9273c6769fbe09c2fd725f9764f51cdaac3e21e204d98ec22d6ab2875b0b000053059a39173053f6b4dfda48049b9b57926666947d403032b09393f33b0583f69d35f1bd40a38c64ab2d927351b290c33793acf09407d4eebdcb46e58b50ec69e44fb48918e4a90439972f88f4084a85c48ce4fe8b2e5c01353",
    ]
    
    SK_d  = "de94c4d7d4b8fae742d86764bb178ba4d0aa6f11"
    SK_ai = "08b981c9dcb4eea8aa53ec090dbf3f32635c79c6"
    SK_ar = "39ea2c84951e088562619c77b021cd84cc59eccf"
    SK_ei = "accaf419052691542c083641cdd18129"
    SK_er = "ea009b9f7c145fa0593139c518299801"
    SK_pi = "03195cf5f156eea8f5ad56dbe05b9b61bf904a51"
    SK_pr = "db0733411135ebeeb4153beb992c939cda56221d"
    
    stream = unhexlify( tests[num] )
    if num % 2: 
        keys = ( unhexlify(SK_er), unhexlify(SK_ar) )
    else: 
        keys = ( unhexlify(SK_ei), unhexlify(SK_ai) )
    
    return stream, keys

