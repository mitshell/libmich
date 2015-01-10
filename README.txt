###########
# libmich #
###########
# READ ME #
###########

This library is being developped since 2009, when I started to work with some 
telecoms and mobile protocols. France Telecom SA, my employer at this time, has 
kindly accepted me to publish it over GPLv2. My current employer has allowed me
to continue maintaining and extending it.

1) How to install?
Actually, nothing specific is required in addition to Python 2 (at least version 
2.6, or better version 2.7): see http://www.python.org/. 
For formats making use of ciphering (i.e. IKEv2, EAPAKA), the Python cryptography 
library pycrypto is used: see https://www.dlitz.net/software/pycrypto/.
For the LTE / EPC L3 signalling (i.e. L3Mobile_NAS, L3Mobile_EMM, L3Mobile_ESM),
the CryptoMobile library is used: see https://github.com/mitshell/CryptoMobile.

Then, you only need to place the 'libmich' sub-directory with its files in your
PYTHONPATH. You can for example place it in the python's 'sitepackage' directory,
or anywhere else your python engine is configured to look and load external modules
from.
You can also use the setup script for the installation:
# python setup.py install

Archlinux users can download the libmich-git PKGBUILD from the AUR
(https://aur.archlinux.org/packages.php?ID=52015), thanks to s1gma.

1bis) How to check if it is working?
First, it is possible to generate all ASN.1 modules; for this, start Python and 
run:
>>> from libmich.asn1.processor import *
>>> generate_modules()
[...]
This must generate Python pickled modules in libmich/asn1/modules/, corresponding
to ASN1 files in libmich/asn1/asn/

Then, it is possible to test different libmich formats encoding and decoding with
the following command:
>>> from libmich.utils.perf import *
>>> main()
[...]
If everything goes well during these steps, every important part of the library
should work properly.

2) Why Python?
Because it is a language easy to learn, well and actively maintained, with a lot 
of contributions and support.

3) Why not Python 3?
Most of the code in the library can NOT be run with Python 3.
The main reason is the way the Python __str__ built-in is used in the library to 
manipulate data just like buffers. Python 3 changes with the string encoding makes 
it quite hard to change the library to support it.

4) What does it do?
Initially, this library was seen as a poor and rachitic clone of scapy, in the 
sense that it is made to build easily any types of digital format (by defining 
data structures, similarly than in C with struct).
Once a format is properly defined, it becomes very easy to build messages based 
on it, and to parse binary streams or buffers to fit into it.

Automating fields is very easy (primarily thanks to python).
For example, defining a Tag-Length-Value format is straightforward: the 'Tag' 
field can reference a dictionnary to print human-readable information instead of 
integer value; the 'Length' field computation, when creating a message, is defined 
very easily by referencing the 'Value' field into one of its specific attribute.

5) Why not introducing all these formats directly into scapy?
At the time I started to work with this (2009), scapy was exclusively network 
oriented. Formats are stacked: what comes first is considered header of what comes 
after, that is considered as payload.
I got so much headaches when I initially worked on the IKEv2 format, that I decided 
to make a proper little library to manage it. I introduced a notion of hierarchy 
between the different layers that are used into the IKEv2 format. 
With the time, I introduced new tips to make it even more convinient (see how 
L3Mobile* modules are made).

I also found that automatic field computation in scapy was not always done in the 
way I needed.

6) A short demo is always better than a long speak:

    $ ipython
    Python 2.7.2 (default, Jun 29 2011, 11:10:00) 
    Type "copyright", "credits" or "license" for more information.

    IPython 0.11 -- An enhanced Interactive Python.
    ?         -> Introduction and overview of IPython's features.
    %quickref -> Quick reference.
    help      -> Python's own help system.
    object?   -> Details about 'object', use 'object??' for extra details.

# first import the core.element basis, which contains the testTLV layer
# for testing purpose

    In [1]: from libmich.core.element import *

    In [2]: testTLV?
    Type:       type
    Base Class: <type 'type'>
    String Form:<class 'libmich.core.element.testTLV'>
    Namespace:  Interactive
    File:       /home/mich/python/libmich/core/element.py
    Definition: testTLV(self)
    Docstring:  <no docstring>
    Constructor information:
     Definition:testTLV(self, name='test', T=5, V='blablabla')

# instantiate the format

    In [4]: test = testTLV()

# 'show' is a special command in the element module
# it makes the layer human-readable

    In [5]: show(test)
    ### [test] ###
    <Tag [T] : 'Tag5'>
    <Flag1 [F1] : 0b0>
    <Flag2 [F2] : 0b1>
    <Reserved [res] : 0b00000000000000>
    <Length [L] : 12>
    <Value [V] : 'blablabla'>

# every fields can be called as attribute of the testTLV instance

    In [6]: test.T
    Out[6]: 'Tag5'

# Each field is composed of not more than a dozen special attributes that
# makes everything working well

    In [7]: test.T.showattr()
    CallName : 'T'
    ReprName : 'Tag'
    Pt : 5
    PtFunc : None
    Val : None
    Len : 1
    Type : 'uint8'
    Dict : <type 'dict'>
    DictFunc : None
    Repr : 'hum'
    Trans : False
    TransFunc : None

# 3 types of field can be used: 'Str' for data stream, 'Int' for integer,
# and 'Bit' for binary data (in general, for fields that are not byte-aligned)

    In [8]: test.F1
    Out[8]: 0b0

    In [9]: test.F1.showattr()
    CallName : 'F1'
    ReprName : 'Flag1'
    Pt : 0
    PtFunc : None
    Val : None
    BitLen : 1
    BitLenFunc : None
    Dict : None
    DictFunc : None
    Repr : 'bin'
    Trans : False
    TransFunc : None

    In [10]: test.V
    Out[10]: 'blablabla'

# the value 'V' can be updated with a new data stream
# the length 'L' will be updated automatically

    In [11]: test.V > 20*'blu'

    In [12]: show(test)
    ### [test] ###
    <Tag [T] : 'Tag5'>
    <Flag1 [F1] : 0b0>
    <Flag2 [F2] : 0b1>
    <Reserved [res] : 0b00000000000000>
    <Length [L] : 63>
    <Value [V] : 'blublublublublublublublublublublublublublublublublublublublu'>

# python basic objects' methods are override to bring the standard commands
# to our objects; here 'str' and 'len'.

    In [13]: str(test)
    Out[13]: '\x05@\x00?blublublublublublublublublublublublublublublublublublublublu'

    In [14]: len(test)
    Out[14]: 64

# The length 'L' field is actually referencing the 'V' field in its .Pt attribute.
# The .PtFunc attribute references a python lambda function that evaluates the 
# correct length of the whole layer

    In [15]: test.L.showattr()
    CallName : 'L'
    ReprName : 'Length'
    Pt : 'blublublublublublublublublublublublublublublublublublublublu'
    PtFunc : <function <lambda> at 0x2148938>
    Val : None
    Len : 1
    Type : 'uint8'
    Dict : None
    DictFunc : None
    Repr : 'hum'
    Trans : False
    TransFunc : None

    In [16]: test.L.Pt == test.V
    Out[16]: True

# The automation of the 'L' field can be overriden with a raw integer value
# in this case, the behavior of .Pt and .PtFunc attributes are overridden by
# the .Val attribute
 
    In [17]: test.L < 20

    In [18]: show(test)
    ### [test] ###
    <Tag [T] : 'Tag5'>
    <Flag1 [F1] : 0b0>
    <Flag2 [F2] : 0b1>
    <Reserved [res] : 0b00000000000000>
    <Length [L] : 20>
    <Value [V] : 'blublublublublublublublublublublublublublublublublublublublu'>

    In [19]: str(test)
    Out[19]: '\x05@\x00\x14blublublublublublublublublublublublublublublublublublublublu'

# The definition of the testTLV format is the following:
#
#class testTLV(Layer):
#    constructorList = [
#        Int(CallName="T", ReprName="Tag", Type="uint8", \
#            Dict={0:"Reserved", 1:"Tag1", 2:"Tag2", 5:"Tag5"}),
#        Bit(CallName='F1', ReprName="Flag1", Pt=0, BitLen=1),
#        Bit(CallName='F2', ReprName="Flag2", Pt=1, BitLen=1),
#        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=14),
#        Int(CallName="L", ReprName="Length", Type="uint8" ),
#        Str(CallName="V", ReprName="Value", Pt='default value'),
#        ]
#
#    def __init__(self, name='test', T=5, V='blablabla'):
#        Layer.__init__(self, CallName=name)
#        self.T.Pt = T
#        self.L.Pt = self.V
#        self.L.PtFunc = lambda X: len(X)+3
#        self.V.Pt = V
#        self.V.Len = self.L
#        self.V.LenFunc = lambda X: int(X)-3
#
# When instantiated, relationships are established between 'L' and 'V'
# 'L' references 'V' in .Pt and uses a simple function referenced by .PtFunc
# to evaluate the length of the layer each time it is called
# 'V' references 'L' in .Len and uses a simple function referenced by .LenFunc
# to evaluate its own length when a data stream is mapped on our format

# Here, we get an error when mapping a dummy string, because the 'r' character
# is mapped to the 'L' field. The map returns before mapping the rest of the 
# data stream and 'V' is keeping its old value

    In [21]: test.map('azertyuioopqsdfggjhk')
    [ERR] String buffer not long enough for V

    In [22]: show(test)
    ### [test] ###
    <Tag [T] : 97>
    <Flag1 [F1] : 0b0>
    <Flag2 [F2] : 0b1>
    <Reserved [res] : 0b11101001100101>
    <Length [L] : 114>
    <Value [V] : 'blublublublublublublublublublublublublublublublublublublublu'>

# When the 'L' field is mapped with a coherent value (here, 5), everything 
# works fine

    In [24]: test.map('azr\x05tyuioopqsdfggjhk')

    In [25]: show(test)
    ### [test] ###
    <Tag [T] : 97>
    <Flag1 [F1] : 0b0>
    <Flag2 [F2] : 0b1>
    <Reserved [res] : 0b11101001110010>
    <Length [L] : 5>
    <Value [V] : 'ty'>


7) OK, this is the very basic principle, where to look to go further with this 
library?
It's python: source code is the best documentation.
Some classes and objects have docstrings.
There is an examples directory which contains few examples on how to use it.


8) What are the worse formats?
In the beginning, I considered IKEv2 quite painful (especially with the crypto).
L3Mobile_NAS / EMM / ESM is also painful (again with the crypto). TLS, JPEG, lots
of CSN.1 based mobile protocols, some ASN.1 kung-fu and its PER codec. SCTP, IPv4 
(yes... IPv4), IPv6 either (too much options...).
Only few protocols or formats are made to be just SIMPLE (PNG is one of this).
 
9) Where can I get some support?
You can drop me an email at: michau (dot) benoit (at) gmail (dot) com
Do not hesitate to send me an email if you have any question about the library.
And do not hesitate to contribute.

10) What is exactly implemented in the library?
There are few directories in the libmich, each of which contains several Python 
files, each implementing specific classes and functions.

The list below, taken from the libmich root directory docstring, provides a complete
list of what is currently implemented:

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
