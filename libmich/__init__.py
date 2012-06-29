'''
The LibMich!!!
Python protocols and communication toolkit

provides "core" repo with:
- "element" core library which implements elements (Str and Int), Layer and Block objects
    # Str() basic element to manage string or stream fields
    # Int() basic element to manage integer fields
    # Bit() basic element to manage bit fields; get a concrete string representation only within a Layer() object
    # Layer() which manages a list of basic Bit(), Str(), Int() elements and Layer()
    # RawLayer()
    # Block() which manages a list of Layer() with hierarchy aspects and other facilities
- "IANA_dict" library which provides the "IANA_dict" object for reverse dictionnary
- "fuzz" library to generate mutations on basic element and Layer() and Block()

provides "utils" repo with:
- "CRC32C" function to compute CRC32C checksum, taken from google code
- "DH" class to compute Diffe-Hellman keys, taken from the python OpenID project
- "PRF186-2" class to compute NIST 186-2 pseudo random generation, derived from SHA1.py

provides "formats" repo with:
- IP attempt library implementing Ethernet, 8021Q, IPv4, IPv6, TCP, UDP headers
- EAP library to build and parse EAP header messages
- EAPAKA library to build and parse EAP-SIM and EAP-AKA messages (need some little extension for EAP-AKA').
- IKEv2 library to build and parse IKEv2 messages
- SCTP library to build and parse SCTP messages
- UMA library
- SIGTRAN basic format implem
- GTPv1 and GTPv2 format implem
- TS24007 and L3Mobile_* : Layer 3 Mobile signalling from TS 24.007 and TS 24.008
- MPEG4: container format
- PNG: container format
- ...
'''

__all__ = ['core', 'utils', 'formats']
__version__ = '0.2.2'
