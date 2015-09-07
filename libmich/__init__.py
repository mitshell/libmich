'''
#------------------------------------------------------------------------------#
#                                 libmich                                      #
#                  Python protocols and communication toolkit                  #
#                     https://github.com/mitshell/libmich                      #
#                        http://michau.benoit.free.fr/                         #
#------------------------------------------------------------------------------#

Provides "core" directory with:
- element: core library which implements elements (Str, Int, Bit), Layer and Block objects
    # Str() basic element to manage string or stream fields
    # Int() basic element to manage integer fields
    # Bit() basic element to manage bit fields; get a concrete string representation only within a Layer() object
    # Layer() which manages a list of basic Str(), Int(), Bit() elements and Layer() -yes, it's recursive!-
    # RawLayer()
    # Block() which manages a list of Layer() with hierarchy aspects and other facilities
- IANA_dict: library which provides the "IANA_dict" object for reverse dictionnary
- fuzz: library to generate mutations on basic element and Layer() and Block()
- shtr: library to easily shift python strings like integers
- shar: library to handle efficiently bit-strings, possibly using numpy's arrays to fasten processing
- CSN1: library to help handling CSN1 messages building and parsing (mainly used in GPRS)

Provides "utils" directory with:
- CRC16: function to compute CRC-16 checksum, taken from the Internet
- CRC32C: function to compute CRC-32C checksum, taken from google code
- DH: class to compute Diffe-Hellman keys, taken from the python OpenID project
- PRF1862: class to compute NIST 186-2 pseudo random generation, derived from SHA1.py
- inet: IP / TCP checksum routines, taken from scapy
- conv: routines for converting network addresses
- perf: tests for checking execution at parsing / building messages, with time measurement
- CrcMoose: large sets of CRC checksums, taken from the Ray Burr on the Internet (but not use in any part of the project, yet)
- IntEncoder: returns encoding format required for integral values (used in asn1)
- repr: contains functions (originally in core/element) to print elements in various ways (show, hex, bin, ...)
- pointer: to handle reference in a dynamic way with Python dict

Provides "asn1" directory with:
- ASN1: basic ASN.1 objects handling with the ASN1Obj class
- utils: little routines and global variables for ASN.1 processing
- parsers: functions to parse ASN.1 syntax
- PER: PER aligned / unaligned encoder and decoder
- processor: main function to work with ASN.1, compile(), inline(), load_module(), ...
- test: test suite for ASN.1 objects generation, compilation, assignation, PER encoding / decoding
- asn directory: contains ASN.1 protocol definition for various 3GPP RAN interfaces
    # ranap_25413-c10: UMTS RANAP protocol (TS 25.413, rel. C10) for Iu-CS and Iu-PS signalling
    # rrc3g_25331-c10: UMTS RRC signalling (TS 25.331, rel. C10) for the UMTS air interface RRC signalling
    # rrclte_36331-c10: LTE RRC signalling (TS 36.331, rel. C10) for the LTE air interface RRC signalling
    # s1ap_36413-C10: LTE S1AP protocol (TS 36.413, rel. C10) for the LTE S1 interface signalling
    # x2ap_36423-C10: LTE X2AP protocol (TS 36.423, rel. C10) for the LTE X2 interface signalling
    # test.asn: just some ASN.1 kung-fu for testing the compiler

Provides "formats" repo with:
# IP-oriented protocols:
- BGPv4: BGP-4 (RFC 4271) messages format
- EAP: EAP header messages format
- EAPAKA: EAP-SIM (RFC 4186) and EAP-AKA (RFC 4187) messages formats with some crypto automation
- IKEv2: IKEv2 (RFC 5996) messages format with some crypto automation
- IP: Ethernet, 8021Q, IPv4, IPv6, TCP and UDP headers format
- PPP: few Point-to-Point Protocol headers format
- RTP: Real-Time Protocol headers format
- SCTP: SCTP (RFC 4960) headers and messages format
- SIGTRAN: M2UA (RFC 3331), M3UA (RFC 4666) and SUA (RFC 3868) basic header format implementation
- TLS: TLS (RFC 5246) basic messages format without crypto support
# mobile-oriented protocols:
- GTP: GTPv1 and GTPv2 signalling messages and user-plane headers format (TS 29.060 and 29.281)
- L1CTL: wrapper for L1CTL protocol from libosmocore, as used in osmocom-bb serial communication
- L2GSM: LAPDm (TS 44.006) signalling header format
- L3GSM_IE: Information Element specific to GSM / GPRS L3 signalling (TS 44.018)
- L3GSM_rest: CSN.1 Rest Octets for GSM broadcasting (TS 44.018)
- L3GSM_RR: GSM / GPRS Radio Ressource signalling messages (TS 44.018)
- L3Mobile: global container for all L3Mobile signalling protocols
    # It contains a function parse_L3() to parse any L3 mobile signalling packet magically
- L3Mobile_24007: L3 mobile basic building structures and routines (TS 24.007) 
- L3Mobile_MM: L3 mobile Mobility Management CS signalling messages (TS 24.008)
- L3Mobile_CC: L3 mobile Call Control CS signalling messages (TS 24.008)
- L3Mobile_SMS: L3 mobile Short Message Service messages (headers in TS 24.011, application layer in TS 23.040)
- L3Mobile_SS: L3 mobile Supplementary Services messages (TS 24.080)
- L3Mobile_GMM: L3 mobile GPRS Mobility Management PS signalling messages (TS 24.008)
- L3Mobile_SM: L3 mobile Session Management PS signalling messages (TS 24.008)
- L3Mobile_NAS: L3 mobile EPS Non-Access Stratum basic messages and security routines (TS 24.301)
    # It requires the CryptoMobile library
- L3Mobile_EMM: L3 mobile EPS Mobility Management signalling messages (TS 24.301)
- L3Mobile_ESM: L3 mobile EPS Session Management signalling messages (TS 24.301)
- MCCMNC: dictionaries for Mobile Country Code / Mobile Network Code and network countries and names lookup
- RANAP: minimal 3G Iu-CS / Iu-PS protocol implementation, no ASN.1 (see in asn1/ for a complete implementation)
- S1AP: minimal LTE S1AP protocol implementation, no ASN.1 (see in asn1/ for a complete implementation)
- UICC_SecChan: UICC (SIM / USIM) secure channel APDU format
    # mostly adapted to be used with card library, or for parsing SIM-Toolkit SMS
- UMA: Universal Mobile Access (TS 44.318) messages format
# radio-oriented protocols and formats:
- IEEE80211: 802.11 (Wi-Fi) MAC headers without crypto support
- IEEE802154: 802.15.4 radio PHY and MAC headers
# file and media container formats:
- BMP: image container format
- ELF: ELF main, section and program headers format
- JPEG: image container format
- MPEG2: transport stream format
- MPEG4: stream container format
- pcap: pcap and gsmtap headers format
- PNG: image container format

Provides "mobnet" repo with some core-network features:
- utils: common function to the mobnet library
- AuC: HLR Authentication Center, to authenticate with SIM and USIM
- GTPmgr: handle GTP-U tunnels for Mobile data connectivity
- MME: to run a minimal MME, handling eNodeB thanks to ENBmgr and UE thanks to UEmgr, UES1proc and UENASproc
- ENBmgr: to handle S1 procedures related to eNodeB
- UEmgr: to handle S1, NAS and all important procedures related to UE
- UES1proc: to support S1AP procedures related to UE
- UENASproc: to support NAS EMM and ESM procedures related to UE
'''

__all__ = ['core', 'utils', 'formats', 'asn1', 'mobnet']
__version__ = '0.2.3'
