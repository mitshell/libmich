
'''
The LibMich!!!
Python protocols and communication toolkit

provides "core" repo with:
- "element" core library which implements elements (Str and Int), Layer and Block objects
    # Str() basic element to manage string or stream fields
    # Int() basic element to manage integer fields
    # Bit() basic element to manage bit fields; get a concrete string representation only within a Layer() object
    # Layer() which manages a list of basic Bit(), Str(), Int() elements and Layer() -yes, it's recursive!-
    # RawLayer()
    # Block() which manages a list of Layer() with hierarchy aspects and other facilities
- "IANA_dict" library which provides the "IANA_dict" object for reverse dictionnary
- "fuzz" library to generate mutations on basic element and Layer() and Block()
- "shtr" library to easily shift python strings like integers
- "CSN1" library to help handling with CSN1 message building and parsing (mainly used in GPRS)

provides "utils" repo with:
- "CRC32C" function to compute CRC32C checksum, taken from google code
- "DH" class to compute Diffe-Hellman keys, taken from the python OpenID project
- "PRF186-2" class to compute NIST 186-2 pseudo random generation, derived from SHA1.py

provides "formats" repo with:
- IP: Ethernet, 8021Q, IPv4, IPv6, TCP and UDP headers format
- EAP: EAP header messages format
- EAPAKA: EAP-SIM and EAP-AKA messages formats with some crypto automation
(would need some little extension for EAP-AKA')
- IKEv2: messages format with some crypto automation
- SCTP: SCTP headers and messages format
- BGPv4: messages format
- pcap: pcap and gsmtap headers format
- PPP: few Point-to-Point Protocol headers format
- RTP: headers format
- UMA: messages format
- UMA_femto: proprietary extension of UMA developped by Kineto and Ubiquisys for femtocells
- SIGTRAN: very basic header format implementation
- GTP: GTPv1 and GTPv2 messages and headers format
- L2GSM, L3GSM_*: layer 2 and 3 signalling messages format
- L3Mobile_* : layer 3 signalling messages format
- L1CTL: osmocom-bb serial communication messages format
- IEEE802154: 802.15.4 radio phy and mac headers
- MPEG4: stream container format
- MPEG2: stream transport message format
- PNG: image container format
- BMP: image container format
- JPEG: image container format

provides "machines" repo with:
- EAPAKA library with helpful EAP-AKA/SIM key manager functions and a not too uncomplete EAP-AKA/SIM client implementation
- IKEv2 library with helpful key manager functions, and an attempt to bring some commodity for making an IKEv2 client
- UMA very basic library with "discover" and "register" methods only
- pyosmo library to make kung-fu with GSM networks on top of an osmocom-bb phone
- UMA_femto library to handle an ubiquisys femtocell and run your own 3G core network
- GTPU library for running a micro GGSN / GTP tunnel handler
'''

__all__ = ['core', 'utils', 'formats', 'machines', 'tools']
__version__ = '0.2.2'
