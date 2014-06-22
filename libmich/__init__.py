
'''
The LibMich!!!
Python protocols and communication toolkit

provides "core" repo with:
- element: core library which implements elements (Str and Int), Layer and Block objects
    # Str() basic element to manage string or stream fields
    # Int() basic element to manage integer fields
    # Bit() basic element to manage bit fields; get a concrete string representation only within a Layer() object
    # Layer() which manages a list of basic Bit(), Str(), Int() elements and Layer() -yes, it's recursive!-
    # RawLayer()
    # Block() which manages a list of Layer() with hierarchy aspects and other facilities
- IANA_dict: library which provides the "IANA_dict" object for reverse dictionnary
- fuzz: library to generate mutations on basic element and Layer() and Block()
- shtr: library to easily shift python strings like integers
- CSN1: library to help handling with CSN1 message building and parsing (mainly used in GPRS)

provides "utils" repo with:
- CRC16: function to compute CRC-16 checksum, taken from the Internet
- CRC32C: function to compute CRC-32C checksum, taken from google code
- DH: class to compute Diffe-Hellman keys, taken from the python OpenID project
- PRF1862: class to compute NIST 186-2 pseudo random generation, derived from SHA1.py
- inet: IP / TCP checksum routines (taken from scapy)
- conv: routines for network addresses
- perf: few tests for checking execution at parsing / building messages

provides "asn1" repo with:
- ASN1_BER: implements only the basic BER-TLV ASN.1 structure
- ASN1_PER: implements basic ASN.1 objects PER encoding / decoding
 
provides "formats" repo with:
- IP: Ethernet, 8021Q, IPv4, IPv6, TCP and UDP headers format
- EAP: EAP header messages format
- EAPAKA: EAP-SIM and EAP-AKA messages formats with some crypto automation
(would need some little extension for EAP-AKA')
- IKEv2: messages format with some crypto automation
- TLS: messages format (no crypto)
- SCTP: SCTP headers and messages format
- BGPv4: messages format
- pcap: pcap and gsmtap headers format
- PPP: few Point-to-Point Protocol headers format
- RTP: headers format
- UMA: messages format
- SIGTRAN: very basic header format implementation
- RANAP: minimal 3G Iu protocol implementation (RNC to MSC / SGSN), no ASN.1 (yet)
- S1AP: minimal LTE S1AP protocol implementation, no ASN.1 (yet)
- GTP: GTPv1 and GTPv2 messages and headers format
- L2GSM, L3GSM_*: LAPDm and Layer 3 GSM signalling messages format
- L3Mobile_*: mobile layer 3 signalling messages format (TS 24.008)
- MCCMNC: big dictionnary with all mobile country / network codes
- L1CTL: osmocom-bb serial communication messages format
- UICC_SecChan: UICC secure channel APDU format
- IEEE802154: 802.15.4 radio PHY and MAC headers
- MPEG4: stream container format
- MPEG2: stream transport message format
- PNG: image container format
- BMP: image container format
- JPEG: image container format
- ELF: ELF main, section and program headers format

provides "mobnet" repo with some core-network features:
- utils: common function to the mobnet library
- AuC: HLR Authentication Center, to authenticate with SIM and USIM
- GTPmgr: handle GTP-U tunnels for Mobile data connectivity
'''

__all__ = ['core', 'utils', 'formats', 'asn1', 'mobnet']
__version__ = '0.2.3'

