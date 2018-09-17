Update (july 2017)
==================

[pycrate](https://github.com/p1sec/pycrate) has just been released, 
intending to replace libmich. Hence, the development of libmich is stopped, 
and all efforts will be put on pycrate yet.


What is libmich
===============

Libmich is a library written for Python 2, that primarily supports encoding and
decoding several digital formats, making a binary file or network stream easily 
understandable for a human, and easier to process within applications.
Many formats and routines are tailored for helping to deal with mobile-network
protocols and traffic. Moreover, it has a simple ASN.1 compiler plus BER and PER
encoders for dealing with all formats defined in ASN.1.


Installation
============


Operating systems and Python version
------------------------------------

The library is made to work with Python 2.7.
Python 3 is not supported, mainly because all binary buffers are handled with 
the Python *str* object.
It works on Windows and Linux, and should work on any other operating system
running Python 2.


Dependencies
------------

There is no mandatory package dependency.
There are two optional package dependencies:
* [pycrypto](https://www.dlitz.net/software/pycrypto/) is used for handling the
   cryptographic operations within IKEv2 and EAPAKA formats
* [CryptoMobile](https://github.com/mitshell/CryptoMobile/) is used for handling
   the cryptographic operations within L3Mobile_NAS format for LTE


Automatic installation
----------------------

An installation script is available.
It precompiles all ASN.1 modules before installing the whole library within your 
Python package directory:

```
python setup.py install
```


Manual installation
-------------------

You can also install the library manually.
For this, just copy the whole *libmich/* sub-directory into one of your 
directory which is referenced within your PYTHONPATH environment variable.
E.g. you can copy it in your *$Python_install_dir/Lib/site-packages/* directory.
If you need to use ASN.1 modules, you will have to compile them, too.
Just look at the [ASN.1 README](https://github.com/mitshell/libmich/blob/master/README_ASN1.md#static-compilation-of-modules)
for this.


Testing the library
-------------------

The *libmich/utils/perf.py* file provides some routines for testing the speed
of some encoders / decoders.
It can be used to check if the library works correctly:

```python
>>> from libmich.utils.perf import *
>>> main()
[...]
total duration: 38.8725 sec.
```

If something breaks here, this means something is wrong with the current code
or the installation step.


License
=======

The whole library is licensed under GPLv2: all licensed files have an header
making it self-explanatory.

The few files which have been imported from external projects have not this
explicit license header.
Here is the list of external files, or code derived from external projects:
* *libmich/utils/CRC16.py*
* *libmich/utils/CRC32C.py*
* *libmich/utils/CrcMoose.py*
* *libmich/utils/DHold.py*
* *libmich/utils/inet.py*
* *libmich/utils/PRF1862.py*
* *libmich/formats/MCCMNC.py*


Contact and support
==================

As the unique developper of the library, I am the only person to contact:
michau \[dot\] benoit \[at\] gmail \[dot\] com


Extending the library
=====================

If you are willing to extend the library, do not hesitate to contact me by
email or through the github service. Any patch or submission is very welcome!
Moreover, in case you are using this library in any of your project and you
find it useful, do not hesitate to drop me an email.
It is always a pleasure to know where code provided on the Internet can end 
up...


Authors
=======

Benoit Michau

Thanks to [FlUxIuS](https://github.com/FlUxIuS) for providing routines for SMS
encoding and decoding.


A little bit of history
=======================

The initial version of the library made public after my former employer *France
Telecom* allowed me to do so.
My current employer *ANSSI* has also allowed me to continue extending it, 
providing support for more and more formats.


Usage
=====

For the most important library objects, docstrings are provided within the code.
The following list provide information of what to expect of core and important
parts of the library.


Main basic core objects
-----------------------

The main objects for the library are defined in *libmich/core/element.py*.
Those objects are used to specify fields of bytes or bits, that form a binary
file or stream.

Here are the most basic elements:
* **Str** to manage byte-aligned string (actually buffer) fields
* **Int** to manage byte-aligned, arbitrary size, signed or unsigned, little or 
   big endian, integer fields
* **Bit** to manage bit fields, possibly byte-unaligned, which values are 
   actually handled like unsigned integers

Those 3 basic elements have common attributes and methods:
* **CallName** (default to Class name) is the name of the field, and to be 
   used to call the element when inserted within a Layer.
* **ReprName** (optional) is an extended name of the field; in case you want 
   to use shorten CallName, ReprName will be used to provide a more readable 
   name to the element when printed on screen.
* **Pt** (default, depends of the element type) to point to a given value; to 
   be used when assigning a value manually to an element. If you want to assign 
   a value to an element which has no automation, you should use this **Pt**
   attribute. Moreover, the character **>** does just this assignment.
* **PtFunc** (optional) to automate the value of the given element; when set, 
   the value of the element is computed with **PtFunc(Pt)** and not directly 
   **Pt**
* **Val** (optional) to overwrite the value manually set in **Pt**; it is used 
   e.g. when mapping a raw buffer to the element. If you want to assign a value 
   to an element which has some automation defined or to overwrite a value 
   already defined, you should use the **Val** attribute. Moreover, the 
   character **<** does this assignment.
* **Trans** (default to False) to declare an element that is transparent; when 
   set to True, the element is not appearing explicitely in the Layer it is part 
   of.
* **TransFunc** (optional) to automate the transparency behavior; when set, 
   the transparency of the element is determined with **TransFunc(Trans)** 
   and not directly with **Trans**.
* **Repr** (default to 'hum') to set the way o represent the value of the 
   element; 'hum' for human-readable, 'hex' for hexadecimal, 'bit' for binary 
   (taking the **Int** endianess into account).
* To get back the value assigned, you can just **call** the element (a 
   **\_\_call\_\_** method is defined).
* To get the buffer representation of the element, you can use **str** onto 
   the element (a **\_\_str\_\_** method is defined).
* To get the length of the buffer representation of the element, you can use
   **len** onto the element (a **\_\_len\_\_** method is defined).
* To unpack a buffer to the given element, you must use the **map** method, 
   passing the string (actually byte-array) of the buffer. This method uses the
   **Val** attribute, if you want to re-assign a value with the **Pt** 
   attribute, you must first unassign this **Val** attribute.
* To get the hexadecimal representation of the element, a **\_\_hex\_\_**
   method is defined. You can use the function **hex** from the 
   *libmich/utils/repr.py* file for calling it.
* To get the binary represenation of the element, a **\_\_bin\_\_** method is 
   defined. You can use the function **bin** from the *libmich/utils/repr.py* 
   file for calling it.
* To get a nice human-readable representation of the element, a **show** 
   method is defined. You can use the function **show** from the 
   *libmich/utils/repr.py* file for calling it.
* **showattr** method prints all internal attributes' value.

**Str** element has specific attributes:
* **Len** (optional) to enforce a specific length in bytes to the given 
   element; if the value set to the element is over the given length, it will be 
   truncated.
* **LenFunc** (optional) to automate the length in bytes; when set, the length 
   of the element is computed with **LenFunc(Len)** and not directly **Len**.

**Int** element has specific attributes:
* **Type** (default to 'int32') to specify the type of integer; it can be *int* 
   or *uint* plus a length which is a multiple of 8 bits (e.g. 'uint272').
* **Dict** (optional) to specify a dictionnary that will be looked-up for 
   representing the value when **Repr** is set to 'hum'.
* **DictFunc** (optional) to automate the type of dictionnary that will be 
   looked-up; when set, the dictionnary is obtained by calling 
   **DictFunc(Dict)** and not directly from **Dict**.
* **_endian** (defaut to 'big') to set the endianess.
The attribute **Len** is computed automatically from the **Type** when the 
**Int** element is instantiated.

**Bit** element has specific attributes:
* **BitLen** (default to 1) to specify the length in bits of the given element; 
   if the integer value set to it overflows the length in bits, it will be 
   rounded.
* **BitLenFunc** to automate the length in bits; when set, the length of the 
   element is computed with **BitLenFunc(BitLen)** and not directly 
   **BitLen**
* **Dict** (optional) to specify a dictionnary that will be looked-up for.
   representing the value when **Repr** is set to 'hum'.
* **DictFunc** (optional) to automate the type of dictionnary that will be 
   looked-up for representing the value; when set, the dictionnary is obtained
   by calling **DictFunc(Dict)** and not directly from **Dict**.


```python
>>> from libmich.core.element import *
>>> from libmich.utils.repr import show, bin, hex
>>>
>>> a = Str('MyStream', Pt='azerty1234', Len=10)
>>> a
'azerty1234'
>>> a()
'azerty1234'
>>> str(a)
'azerty1234'
>>> show(a)
<[MyStream] : 'azerty1234'>
>>> a.Repr='hex'
>>> show(a)
<[MyStream] : 0x617a6572747931323334>
>>> a.Repr='bin'
>>> show(a)
<[MyStream] : 0b01100001011110100110010101110010011101000111100100110001001100100011001100110100>
>>> a.map('qsdfgh4567')
>>> a()
'qsdfgh4567'
>>> str(a)
'qsdfgh4567'
>>> show(a)
<[MyStream] : 0b01110001011100110110010001100110011001110110100000110100001101010011011000110111>
>>> a.Repr='hum'
>>> show(a)
<[MyStream] : 'qsdfgh4567'>
>>>
>>> b = Int('MyInt', Pt=25, Type='int96', Dict={0:'none', 1:'more'})
>>> b
25
>>> b()
25
>>> show(b)
<[MyInt] : 25>
>>> str(b)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19'
>>> b._endian = 'little'
>>> str(b)
'\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> hex(b)
'190000000000000000000000'
>>> bin(b)
'000110010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
>>> b.map('abcdefghijkl')
>>> show(b)
<[MyInt] : 33554238638682438954073154145>
>>> b()
33554238638682438954073154145L
>>> b.showattr()
CallName : 'MyInt'
ReprName : ''
Pt : 25
PtFunc : None
Val : 33554238638682438954073154145L
Len : 12
Type : 'int96'
Dict : <type 'dict'>
DictFunc : None
Repr : 'hum'
Trans : False
TransFunc : None
>>> b.map('\x01'+11*'\0')
>>> show(b)
<[MyInt] : '1 : more'>
>>> b()
1
>>>
>>> c = Bit('MyBits', Pt=3, BitLen=7)
>>> c
0b0000011
>>> c()
3
>>> show(c)
<[MyBits] : 0b0000011>
>>> c > 109
>>> show(c)
<[MyBits] : 0b1101101>
>>> c()
109
>>> str(c)
'\xda'
>>> c.map('\x82')
>>> show(c)
<[MyBits] : 0b1000001>
>>> c()
65
>>> c < None
>>> c > 7
>>> show(c)
<[MyBits] : 0b0000111>
>>> c()
7
```


Main constructed core objects
----------------------------

All these 3 basic core objects can be assembled into **Layer** objects.
Each **Layer** element can contain **Str**, **Int** and **Bit** elements, 
plus other **Layer** elements (the class is a recursive object).

The main attribute of the **Layer** element is the **constructorList** for 
the object itself, which is converted to **elementList** during object 
instantiation.
It is a list containing elements which will be handled in the given ordered and 
grouped way.
A **Layer** can be enforced to be byte-aligned (default behavior), or not (in 
case you have byte-unaligned **Bit** elements inside).
Lots of attributes and methods are exposed in order to manage **Layer** 
elements similarly than basic elements, but also like lists or dictionnaries.
Another important method is the **reautomatize** one, which restores all 
elements to are automated within the **Layer** instance.

As a quick example, the **testTLV** class from the *libmich/core/element.py* 
can be used. Here is its definition:
```python
class testTLV(Layer):
    _byte_aligned = True
    constructorList = [
        Int('T', ReprName='Tag', Type='uint8', Dict={0:'Reserved', 1:'Tag1', 2:'Tag2', 5:'Tag5'}),
        Bit('F1', ReprName='Flag1', Pt=0, BitLen=1),
        Bit('F2', ReprName='Flag2', Pt=1, BitLen=2),
        Bit('res', ReprName='Reserved', Pt=0, BitLen=13),
        # length in bytes (including header, excepted Tag)
        Int('L', ReprName='Length', Type='uint8' ),
        Str('V', ReprName='Value', Pt='default value'),
        ]

    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # automating the computation of Length at runtime
        self.L.Pt = self.V
        self.L.PtFunc = lambda X: len(X)+3
        # automating the parsing of Value when calling .map(buffer)
        self.V.Len = self.L
        self.V.LenFunc = lambda X: int(X)-3
```

Here is how it is behaving within Python:
```python
>>> t = testTLV()
>>> t
<[testTLV]: T(Tag):None, F1(Flag1):0b0, F2(Flag2):0b01, res(Reserved):0b0000000000000, L(Length):16, V(Value):'default value'>
>>> show(t)
### [testTLV] ###
 <Tag [T] : None>
 <Flag1 [F1] : 0b0>
 <Flag2 [F2] : 0b01>
 <Reserved [res] : 0b0000000000000>
 <Length [L] : 16>
 <Value [V] : 'default value'>
>>> str(t)
'\x00 \x00\x10default value'
>>> t()
'\x00 \x00\x10default value'
>>> len(t)
17
>>> t.T() # getting the Tag value
0
>>> t.F1() # getting the F1 flag value
0
>>> t.T > 5 # setting the Tag value to 5
>>> t.F1 > 1
>>> t.V > 'this is an damned example'
>>> show(t)
### [testTLV] ###
 <Tag [T] : '5 : Tag5'>
 <Flag1 [F1] : 0b1>
 <Flag2 [F2] : 0b01>
 <Reserved [res] : 0b0000000000000>
 <Length [L] : 28>
 <Value [V] : 'this is an damned example'>
>>> str(t)
'\x05\xa0\x00\x1cthis is an damned example'
>>> hex(t)
'05a0001c7468697320697320616e2064616d6e6564206578616d706c65'
>>> bin(t)
'0000010110100000000000000001110001110100011010000110100101110011001000000110100101110011001000000110000101101110001000000110010001100001011011010110111001100101011001000010000001100101011110000110000101101101011100000110110001100101'
>>> show(t[0]) # showing the 1st contained element
<Tag [T] : 5>
>>> show(t[1]) # showing the 2nd contained element
<Flag1 [F1] : 0b1>
>>> show(t[-1]) # showing the last contained element
<Value [V] : 'this is an damned example'>
>>>
>>> t.map('\x02\x40\0\x21'+30*'A')
>>> show(t)
### [testTLV] ###
 <Tag [T] : '2 : Tag2'>
 <Flag1 [F1] : 0b0>
 <Flag2 [F2] : 0b10>
 <Reserved [res] : 0b0000000000000>
 <Length [L] : 33>
 <Value [V] : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'>
>>> t.map('\x02\x40\0\x21'+80*'A') # the mapping of the Value buffer gets truncated due to Length
>>> show(t)
### [testTLV] ###
 <Tag [T] : '2 : Tag2'>
 <Flag1 [F1] : 0b0>
 <Flag2 [F2] : 0b10>
 <Reserved [res] : 0b0000000000000>
 <Length [L] : 33>
 <Value [V] : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'>
>>> len(t)
34
>>> len(t.V)
30
>>> t.reautomatize() # restore the automatic computation of Length
```

Lastly, the **Block** object helps to manage multiple **Layer** objects with a 
hierarchy. It allows to define dependencies between them, like headers and 
payloads.

You can find more examples of how to use **Layer** and **Block** objects at 
the end of the *libmich/core/element.py* file, within the *examples* 
sub-directory (with png, IKEv2, MPEG2), and more globally in all formats 
definition provided within the *libmich/formats/* sub-directory.


Other core objects
------------------

Other files are provided in the *libmich/core/* sub-directory. Here is the list
of them without much more explanation:

* *libmich/core/IANA_dict.py*: provides the **IANA_Dict** class, very similar 
   to a Python dictionnary, but able to handle integral value keys that are not
   entirely defined.
* *libmich/core/shtr.py*: provides the **decompose** function to get all 
   factors of a given integral value, and the **shtr** class for handling 
   strings that you can shift (very useful when dealing with byte-unaligned 
   protocols).
* *libmich/core/CSN1.py*: provides the **CSN1** and **LHFlag** classes for 
   helping with CSN1-defined structures (for GPRS signalling). Some examples on 
   how it is used are available in *libmich/formats/L3GSM_rest.py*.
* *libmich/core/fuzz.py*: provides **Mutor** class for fuzzing basic elements' 
   value and **Layor** fuzzing all elements within a **Layer** instance. This 
   is a quite untested part.
* *libmich/core/shar.py*: provides **byte_to_bit** and **bit_to_byte** 
   functions and the **shar** class for dealing with bit stream. It is 
   optimized to make use of numpy when present.


Formats supported
-----------------

The *libmich/formats/* sub-directory contains many Python files defining lots
of digital formats. Here is the list of files with a tiny explanation on what it
does. For further explanations, see the docstrings or directly the source code.

IP-oriented protocols:
* IP: Ethernet, 8021Q, IPv4, IPv6, TCP and UDP headers format (including CRC
   computation)
* PPP: few Point-to-Point Protocol headers format
* SCTP: SCTP (RFC 4960) headers and messages format (including CRC computation)
* SIGTRAN: M2UA (RFC 3331), M3UA (RFC 4666) and SUA (RFC 3868) basic header 
   format implementation
* BGPv4: BGP-4 (RFC 4271) messages format
* TLS: TLS (RFC 5246) basic messages format without crypto support 
   (unfinished / untested implementation)
* RTP: Real-Time Protocol headers format
* EAP: EAP header messages format
* EAPAKA: EAP-SIM (RFC 4186) and EAP-AKA (RFC 4187) messages formats with some 
   crypto automation
* IKEv2: IKEv2 (RFC 5996) messages format with some crypto automation


Mobile-network-oriented protocols:
* GTP: GTPv1 and GTPv2 signalling messages and user-plane headers format 
   (TS 29.060 and 29.281)
* L1CTL: wrapper for L1CTL protocol from libosmocore, as used in osmocom-bb 
   serial communication
* L2GSM: LAPDm (TS 44.006) signalling header format
* L3GSM_IE: Information Element specific to GSM / GPRS L3 signalling 
   (TS 44.018)
* L3GSM_rest: CSN.1 Rest Octets for GSM broadcasting (TS 44.018)
* L3GSM_RR: GSM / GPRS Radio Ressource signalling messages (TS 44.018)
* L3Mobile: global container for all L3Mobile signalling protocols. It contains 
   a function **parse_L3()** to parse any L3 mobile signalling packet 
   magically.
* L3Mobile_24007: L3 mobile basic building structures and routines (TS 24.007) 
* L3Mobile_MM: L3 mobile Mobility Management CS signalling messages (TS 24.008)
* L3Mobile_CC: L3 mobile Call Control CS signalling messages (TS 24.008)
* L3Mobile_SMS: L3 mobile Short Message Service messages (headers in TS 24.011, 
   application layer in TS 23.040)
* L3Mobile_SS: L3 mobile Supplementary Services messages (TS 24.080)
* L3Mobile_GMM: L3 mobile GPRS Mobility Management PS signalling messages 
   (TS 24.008)
* L3Mobile_SM: L3 mobile Session Management PS signalling messages (TS 24.008)
* L3Mobile_NAS: L3 mobile EPS Non-Access Stratum basic messages and security 
   routines (TS 24.301). It requires the CryptoMobile library.
* L3Mobile_EMM: L3 mobile EPS Mobility Management signalling messages 
   (TS 24.301)
* L3Mobile_ESM: L3 mobile EPS Session Management signalling messages 
   (TS 24.301)
* MCCMNC: dictionaries for Mobile Country Code / Mobile Network Code and 
   network countries and names lookup
* RANAP: minimal 3G Iu-CS / Iu-PS protocol implementation, no ASN.1 (see in 
   asn1/ for a complete RANAP implementation)
* S1AP: minimal LTE S1AP protocol implementation, no ASN.1 (see in asn1/ for a 
   complete S1AP implementation)
* UICC_SecChan: UICC (SIM / USIM) secure channel APDU format. Mostly adapted 
   to be used with *card* library, or for parsing SIM-Toolkit SMS
* UMA: Universal Mobile Access (TS 44.318) messages format

Radio-oriented protocols and formats:
* IEEE80211: 802.11 (Wi-Fi) MAC headers without crypto support (unfinished / 
   untested implementation)
* IEEE802154: 802.15.4 radio PHY and MAC headers (including CRC computation)

File and media container formats:
* BMP: image container format
* ELF: ELF main, section and program headers format
* JPEG: image container format
* MPEG2: transport stream format
* MPEG4: stream container format
* pcap: pcap and gsmtap headers format
* PNG: image container format (including CRC computation)


ASN1 objects and modules
------------------------

Libmich provides a tiny ASN.1 compiler, capable of compiling most of the ETSI /
3GPP specifications.
Furthermore, PER and BER encoders are provided too.
All ASN.1 protocols and Python files are in *libmich/asn1/*.
Please refer to the dedicated 
[ASN.1 README](https://github.com/mitshell/libmich/blob/master/README_ASN1.md) 
for further information.

Currently, the following ASN.1 protocols are supported and directly available 
from the library:
* MAP: Mobile Application Part
* SS: Supplementary Services
* RRC3G: Radio Ressources Configuration for 3G
* RANAP: Radio Access Network Application Protocol for 3G
* RRCLTE: Radio Ressources Configuration for LTE
* S1AP: Radio Access Network Application Protocol for LTE (eNodeB - MME)
* X2AP: Radio Access Network Application Protocol for LTE (eNodeB - eNodeB)
* LPP: LTE Positionning Protocol


Other useful routines
--------------------

Basic utility functions and classes are provided in the *libmich/utils/* 
sub-directory:
* CRC16: function to compute CRC-16 checksum, taken from the Internet
* CRC32C: function to compute CRC-32C checksum, taken from google code
* CrcMoose: large sets of CRC checksums, taken from the Ray Burr website (but 
   not use in any part of the project, yet)
* DH: class to compute Diffe-Hellman shared keys
* PRF1862: class to compute NIST 186-2 pseudo random generation, derived from 
   SHA1.py
* inet: IP / TCP checksum routines, taken from scapy
* conv: routines for converting network addresses
* perf: tests for checking execution at parsing / building messages, with time 
   measurement
* IntEncoder: returns encoding format required for integral values (used in 
   asn1)
* repr: contains functions (originally in core/element) to print elements in 
   various ways (show, hex, bin, ...)
* pointer: to handle reference in a dynamic way with Python dict


The library provides routines and EPC network stacks that can be of interest to 
developers working with mobile network applications.
The *libmich/mobnet/* sub-directory provides the following files:
* utils: common functions required for the rest of the mobnet library
* AuC: HLR Authentication Center, to authenticate with SIM and USIM, making 
   use of the *CryptoMobile* library
* GTPmgr: to handle GTP-U tunnels for Mobile data connectivity
* MME: to run a minimal MME, handling eNodeB thanks to ENBmgr and UE thanks to
   UEmgr, UES1proc and UENASproc
* ENBmgr: to handle S1 procedures related to eNodeB
* UEmgr: to handle S1, NAS and all important procedures related to UE
* UES1proc: to support S1AP procedures related to UE
* UENASproc: to support NAS EMM and ESM procedures related to UE
