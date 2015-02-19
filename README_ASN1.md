What is ASN.1
=============

ASN.1 means *Abstract Syntax Notation 1*.

This is a language to describe data types and structures in a 
machine-independent way. Information described with the ASN.1 language can then 
be transferred  between machines thanks to encoding / decoding rules, such as 
BER (Basic Encoding Rules), PER (Packed Encoding Rules), DER (Distinguished 
Encoding Rules), XER (XML Encoding Rules), ...


Where can I find online ressources about ASN.1
==============================================

ASN.1 language and most of the associated encoding rules are standardized by the 
ITU-T. Those specifications, even if freely available, are unfortunately not 
very easy to read and not the best way to understand how ASN.1 works.

The best way to understand the ASN.1 language and the associated encoding rules 
is to read the two main books, which are available for free on the Internet:
* *ASN.1 - Communication Between Heterogeneous Systems*, by Olivier Dubuisson 
   and translated by Philippe Fouquart;
* *ASN.1 Complete*, by John Larmouth.

The first one is quite complete about the syntax and the semantic of the ASN.1 
language, whereas the second one is quite easy and practical, especially for
a quick understanding of the encoding rules. Other available ressources can also
be useful:
* OSS Nokalva provides an online ASN.1 compiler, plus multiple encoders and 
   decoders at the [asn1-playground](http://asn1-playground.oss.com).
* Lev Walkin proposes [asn1c](http://lionet.info/asn1c/), a very complete ASN.1
   to C and C++ compiler plus multiple encoders and decoders (and also an online 
   one).
* Fabrice Bellard proposes [ffasn1](http://bellard.org/ffasn1), which has a free
   ASN.1 message converter and editor which supports many encoding rules too.
* ITU-T has a complete web page referencing tools and softwares supporting ASN.1
   at the [ITU-T ASN.1 tools](http://www.itu.int/en/ITU-T/asn1/Pages/Tools.aspx).


Why supporting ASN.1
====================

ASN.1 is used to describe several protocols and data formats, especially in the
domain of the telecommunications:
* X.509, LDAP, Kerberos, SNMP are examples of Internet-oriented protocols using
   the ASN.1 language and BER, CER or DER encoding rules.
* UMTS radio access protocols (RRC, RANAP, RNSAP, NBAP, RUA, HNBAP) are using
   the ASN.1 language and PER encoding rules.
* LTE radio access protocols (RRC, S1, X2, M2, M3) are also using the ASN.1 
   language and PER encoding rules.
* 2G and 3G mobile core network signalling protocols (MAP, CAP, LI) are using 
   the ASN.1 language and BER encoding rules.

As libmich tend to get more and more complete in order to support mobile network
protocols, supporting ASN.1 is a clear and useful target.


What is supported by libmich
============================

At the current time (march 2015), libmich supports:
* compiling ASN.1 specification to Python objects
* storing ASN.1 Python objects thanks to Python pickle
* BER encoding / decoding rules
* PER aligned and unaligned encoding / decoding rules

The level of support is sufficient to compile and encode / decode most of the 
UMTS and LTE radio access network procotols, and the MAP protocol. The library
currently provides ready-to-use ASN.1 modules:
* MAP_29002-bb0: Mobile Application Part protocol, specified in the 3GPP TS 
   29.002, release bb0.
* SS_24080-c00: Supplementary Services protocol (making use of many sub-modules
   of MAP), specified in the 3GPP TS 24.080, release c00.
* RRC3G_25331-c10: 3G Radio Ressource Control protocol, specified in the epic
   3GPP TS 25.331, release c10.
* RANAP_25413-c10: 3G Radio Access Network Application Part protocol, specified
   in the 3GPP TS 25.413, release c10.
* RRCLTE_36331-c10: LTE Radio Ressource Control protocol, specified in the 3GPP
   TS 36.331, release c10.
* S1AP_36413-c10 and X2AP_36423-c10: LTE radio access network protocols, 
   specified in the 3GPP TS 36.413 and 423, releases c10.

On the other side, many ASN.1 basic types (e.g. Relative-OID, specific String, 
Real, ...) which are not common in mobile network protocols are not supported 
yet by libmich.


How does the compiler works
===========================

The largest part of the static and dynamic compiler is available in the 
*processor.py* file.

The compiler can work on a list of ASN.1 files, placed in the asn/ 
sub-directory, or on an ASN.1 text directly passed to it within the Python 
intepreter.
Every ASN.1 object compiled to Python is placed in the Python **GLOBAL** 
object. **GLOBAL** has actually 3 distincts attributes:
* **TYPE**: a dictionnary which holds all user-defined ASN.1 subtypes. 
* **VALUE**: a dictionnary which holds all user-defined ASN.1 values. 
* **SET**: a dictionnary which holds all user-defined ASN.1 set of values.

**GLOBAL** is the main and only directory which receives all ASN.1 objects 
processed by the compiler.

Static compilation of modules
-----------------------------

In order to compile a serie of ASN.1 modules statically, a new directory needs
to be created in the asn/ sub-directory. One or multiple files containing the 
ASN.1 definitions need to be copied here. An ASN.1 module has always the 
following format:

```
ASN1-Test-Module DEFINITIONS ::=
BEGIN
[...]
END
```

Then a dedicated file *load.txt* must be created, that lists the ASN.1 files
that need to be processed in the right order to compile the serie of ASN.1 
modules. For example for the S1AP protocol:

``` 
# Ordered list of LTE S1AP modules
# to be loaded sequentially
S1AP-CommonDataTypes.asn
S1AP-Constants.asn
S1AP-Containers.asn
S1AP-IEs.asn
S1AP-PDU-Contents.asn
S1AP-PDU-Descriptions.asn
```

A single file can contain multiple ASN.1 modules, however, this is not easy to 
maintain. Therefore, in the current asn/ sub-directory, all ASN.1 files are
containing only a single ASN.1 module. To compile one serie of modules (or all 
series) of it, the function *generate_modules* must be used.
All the ASN.1 modules described in the files listed in *load.txt* are compiled 
into the Python **GLOBAL** object, and then pickled and stored into a new file 
in the modules/ sub-directory.

For example for the S1AP protocol:

```python
>>> from libmich.asn1.processor import *
>>> generate_modules({'S1AP':'S1AP_36413-c10'})
processing S1AP-CommonDataTypes.asn
[proc] ASN.1 module S1AP-CommonDataTypes: 7 assignments processed (4 pass)
[proc] ASN.1 modules scanned: ['S1AP-CommonDataTypes']
processing S1AP-Constants.asn
[proc] ASN.1 module S1AP-Constants: 258 assignments processed (10 pass)
[proc] ASN.1 modules scanned: ['S1AP-Constants']
processing S1AP-Containers.asn
[proc] ASN.1 module S1AP-Containers: 15 assignments processed (6 pass)
[proc] ASN.1 modules scanned: ['S1AP-Containers']
processing S1AP-IEs.asn
[proc] ASN.1 module S1AP-IEs: 340 assignments processed (15 pass)
[proc] ASN.1 modules scanned: ['S1AP-IEs']
processing S1AP-PDU-Contents.asn
[proc] ASN.1 module S1AP-PDU-Contents: 216 assignments processed (11 pass)
[proc] ASN.1 modules scanned: ['S1AP-PDU-Contents']
processing S1AP-PDU-Descriptions.asn
[proc] ASN.1 module S1AP-PDU-Descriptions: 58 assignments processed (12 pass)
[proc] ASN.1 modules scanned: ['S1AP-PDU-Descriptions']
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\S1AP.pck
>>> 
```

All the S1AP ASN.1 modules get compiled and finally stored into the *S1AP.pck* 
file. The argument of the *generate_modules* function is a dictionnary of 
{targeted Python module name, ASN.1 modules directory}. By default, it takes the 
*MODULES* variable which lists all already-available protocols in asn/. This 
way, in order to compile all available protocols, It is simply possible to do:

```python
>>> generate_modules()
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\MAP.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\RRCLTE.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\SS.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\RANAP.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\RRC3G.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\X2AP.pck
[...]
modules successfully stored in C:\Users\benoit\Python\libmich\asn1\modules\S1AP.pck
```

After ASN.1 modules have been compiled, it is possible to load them with the
*load_module* function, providing the name of the Python module as argument. 
When loading a module, the Python **GLOBAL** object gets populated with all 
user-defined ASN.1 objects from the corresponding ASN.1 modules. In order to 
avoid ASN.1 objects override, it is possible to clear the **GLOBAL** object
when willing to load a different module.

```python
>>> load_module('S1AP')
S1AP: 894 objects loaded into GLOBAL
>>> len(GLOBAL.TYPE), len(GLOBAL.VALUE), len(GLOBAL.SET)
(406, 308, 180)
>>> GLOBAL.clear()
>>> load_module('RRCLTE')
RRCLTE: 859 objects loaded into GLOBAL
>>> len(GLOBAL.TYPE), len(GLOBAL.VALUE), len(GLOBAL.SET)
(793, 66, 0)
>>> dcch_dl = GLOBAL.TYPE['DL-DCCH-Message']
>>> dcch_dl
<DL-DCCH-Message (SEQUENCE type)>
>>> GLOBAL.clear()
```

If you want to have all ASN.1 Python objects directly available into the Python
interpreter, it is possible to export all the content of the **GLOBAL** object 
into the scope of your workspace. In this case, all dashes characters included
in ASN.1 objects' name get translated to underscore. The function *export* can
be used for this, passing the intended scope of destination as argument. 

```python
>>> load_module('S1AP')
S1AP: 894 objects loaded into GLOBAL
>>> len(GLOBAL.TYPE), len(GLOBAL.VALUE), len(GLOBAL.SET)
(406, 308, 180)
>>> export(globals())
>>> GLOBAL.TYPE['S1AP-PDU']
<S1AP-PDU (CHOICE type)>
>>> S1AP_PDU
<S1AP-PDU (CHOICE type)>
>>> S1AP_PDU == GLOBAL.TYPE['S1AP-PDU']
True
>>> CauseRadioNetwork
<CauseRadioNetwork (ENUMERATED type)>
>>> EmergencyAreaID_Broadcast_Item
<EmergencyAreaID-Broadcast-Item (SEQUENCE type)>
```


Dynamic compilation of an ASN.1 object
--------------------------------------

Contrary to the static compilation which works over large text containing ASN.1
modules definitions, it is also possible to compile dynamically ASN.1 
definitions with the *inline* function. It compiles the ASN.1 definition to a 
Python object, make it available through the **GLOBAL** object, ans returns it 
to the Python interpreter.

```python
>>> GLOBAL.clear()
>>> TestInt = inline('''TestInt ::= INTEGER (-20..1000)''')
>>> TestInt
<TestInt (INTEGER type)>
>>> TestEnum = inline('''TestEnum ::= ENUMERATED {jambon, salami, coppa, speck}''')
>>> TestEnum
<TestEnum (ENUMERATED type)>
>>> TestSeq = inline('''TestSeq ::= SEQUENCE {
testInt TestInt,
testEnum TestEnum DEFAULT coppa
}''')
>>> TestSeq
<TestSeq (SEQUENCE type)>
>>> GLOBAL.TYPE
TestInt: <TestInt (INTEGER type)>
TestEnum: <TestEnum (ENUMERATED type)>
TestSeq: <TestSeq (SEQUENCE type)>
```


How ASN1 Python objects work
============================

The basics
----------

The largest part of ASN1 Python objects' behavior is available in the *ASN1.py*
file. All ASN.1 objects (subtypes, classes, values and sets) are all compiled as
a specific instance of the **ASN1Obj** class. Each ASN1Obj instance has the 
following attributes:
* name: name of the ASN.1 object
* type: basic ASN.1 type of the ASN.1 object
* mode: 0 if a sub-type or a class, 1 if a value, 2 if a set of values
* tag: tag of the ASN.1 object
* param: formal parameters, for any parameterized ASN.1 object
* typeref: referenced ASN.1 object, when a user-defined object is a subtype or
   a reference to another user-defined ASN.1 object
* cont: content of the ASN.1 object
* const: constraint on the ASN.1 object
* val: value of the ASN.1 object (only for value and set of values)

All those attributes can be called like any Python instance's attribute, after
adding an underscore prefix, or like any Python dictionnary's key. Some more 
attributes are used internally but are not that important, here. A more complete 
description of the innerworking of the ASN1Obj instance is made in its docstring.


```python
>>> TestSeq._name
'TestSeq'
>>> TestSeq._type
'SEQUENCE'
>>> TestSeq._cont
testInt: <testInt ([TestInt] INTEGER type)>
testEnum: <testEnum ([TestEnum] ENUMERATED type)>
>>> TestSeq['name']
'TestSeq'
>>> TestSeq['type']
'SEQUENCE'
>>> TestSeq['cont']
testInt: <testInt ([TestInt] INTEGER type)>
testEnum: <testEnum ([TestEnum] ENUMERATED type)>
>>> help(TestSeq)
Help on ASN1Obj in module libmich.asn1.ASN1 object:

class ASN1Obj(__builtin__.object)
[...]
```

How to set / get a specific value to / from an ASN.1 object
-----------------------------------------------------------

Every ASN1Obj instance has a method *set_val(val)* to set a given value to it.
The value *val* must have a type according to the *type* attribute of the 
ASN1Obj instance. See the ASN1Obj docstring for more information on this.
Any ASN1Obj instance which has been attributed a value, will return it when
called. The value also (partially) appear when representing the ASN1Obj.

Here are few examples:

```python
>>> # lets define some more use-cases
>>> TestBool = inline('''TestBool ::= BOOLEAN''')
>>> TestBitStr = inline('''TestBitStr ::= BIT STRING (SIZE(4..60))''')
>>> TestOctStr = inline('''TestOctStr ::= OCTET STRING (SIZE(1..16))''')
>>> TestCho = inline('''TestCho ::= CHOICE {
testBool TestBool,
testInt TestInt
}''')
>>> 
>>> 
>>> # lets attribute some values to a BOOLEAN
>>> TestBool.set_val(True)
>>> TestBool
<TestBool (BOOLEAN type): True>
>>> TestBool()
True
>>> TestBool.set_val(False)
>>> TestBool()
False
>>> 
>>> 
>>> # lets attribute some values to an INTEGER
>>> TestInt.set_val(10)
>>> TestInt
<TestInt (INTEGER type): 10>
>>> TestInt()
10
>>> TestInt.set_val(20000000)

Traceback (most recent call last):
  File "<pyshell#67>", line 1, in <module>
    TestInt.set_val(20000000)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 592, in set_val
    self._set_val_basic(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 415, in _set_val_basic
    self._val_basic_in_const(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 373, in _val_basic_in_const
    % (self.get_fullname(), ub, val)))
ASN1_OBJ: TestInt: INTEGER value overflow (MAX: 1000): 20000000
>>> # This is because of the constraint (-20..1000) on TestInt
>>> TestInt._const
[{'lb': -20, 'keys': ('lb', 'ub', 'ext'), 'text': '-20..1000', 'ext': False, 'type': 'CONST_VAL_RANGE', 'ub': 1000}]
>>> 
>>> 
>>> # lets attribute some values to an ENUMERATED
>>> TestEnum.set_val('jambon')
>>> TestEnum
<TestEnum (ENUMERATED type): 'jambon'>
>>> TestEnum()
'jambon'
>>> TestEnum.set_val('bacon')

Traceback (most recent call last):
  File "<pyshell#73>", line 1, in <module>
    TestEnum.set_val('bacon')
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 592, in set_val
    self._set_val_basic(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 414, in _set_val_basic
    % (self.get_fullname(), self._type, val)))
ASN1_OBJ: TestEnum: invalid ENUMERATED value: bacon
>>> # this is because TestEnum is not extensible and bacon is not part of the root content of the object
>>> TestEnum._cont
jambon: 0
salami: 1
coppa: 2
speck: 3
>>> TestEnum._ext is None
True
>>> 
>>> 
>>> # lets attribute some values to a BIT STRING
>>> # warning: internal representation of BIT STRING values is done with an integral value and a size in bits
>>> TestBitStr.set_val( (255, 16) )
>>> TestBitStr
<TestBitStr (BIT STRING type): (255, 16)>
>>> TestBitStr()
(255, 16)
>>> TestBitStr.set_val( (255, 72) )

Traceback (most recent call last):
  File "<pyshell#82>", line 1, in <module>
    TestBitStr.set_val( (255, 72) )
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 592, in set_val
    self._set_val_basic(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 415, in _set_val_basic
    self._val_basic_in_const(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 382, in _val_basic_in_const
    % (self.get_fullname(), ub, val[1])))
ASN1_OBJ: TestBitStr: BIT STRING size overflow (MAX: 60): 72
>>> # if you want to provide a string of 0 and 1, or hex characters, like within the ASN.1 language, you can use the .parse_value() method
>>> TestBitStr.parse_value(''' '10010011110001'B ''')
''
>>> TestBitStr
<TestBitStr (BIT STRING type): (9457, 14)>
>>> TestBitStr.parse_value(''' '12ABCD'H ''')
''
>>> TestBitStr
<TestBitStr (BIT STRING type): (1223629, 24)>
>>> 
>>> 
>>> # lets attribute some values to an OCTET STRING
>>> TestOctStr.set_val('tralalalalere')
>>> TestOctStr
<TestOctStr (OCTET STRING type): 'tralalalalere'>
>>> TestOctStr()
'tralalalalere'
>>> TestOctStr.set_val('tralalalalere'*5)

Traceback (most recent call last):
  File "<pyshell#91>", line 1, in <module>
    TestOctStr.set_val('tralalalalere'*5)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 592, in set_val
    self._set_val_basic(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 415, in _set_val_basic
    self._val_basic_in_const(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 393, in _val_basic_in_const
    % (self.get_fullname(), self._type, ub, len(val))))
ASN1_OBJ: TestOctStr: OCTET STRING size overflow (MAX: 16): 65
>>> # you can use parse_value() just like with BIT STRING
>>> TestOctStr.parse_value(''' '0101101001011010'B ''')
''
>>> TestOctStr
<TestOctStr (OCTET STRING type): 'ZZ'>
>>> TestOctStr.parse_value(''' 'ABCDEF'H ''')
''
>>> TestOctStr
<TestOctStr (OCTET STRING type): '\xab\xcd\xef'>
>>> 
>>> 
>>> # lets attribute some values to a CHOICE
>>> # the name of the component chosen to be set needs to be passed as a 1st part of a 2-tuple
>>> # the 2nd part of the 2-tuple must contain the associated value
>>> TestCho.set_val( ('testBool', False) )
>>> TestCho
<TestCho (CHOICE type): ('testBool', False)>
>>> TestCho()
('testBool', False)
>>> TestCho.set_val( ('testInt', 500) )
>>> TestCho
<TestCho (CHOICE type): ('testInt', 500)>
>>> TestCho()
('testInt', 500)
>>> 
>>> 
>>> # lets attribute some values to a SEQUENCE
>>> TestSeq.set_val( {'testInt':-5, 'testEnum':'salami'} )
>>> TestSeq
<TestSeq (SEQUENCE type): {'testInt': -5, 'testEnum': 'salami'}>
>>> TestSeq()
{'testInt': -5, 'testEnum': 'salami'}
>>> TestSeq.set_val( {'testInt':-5} )
>>> TestSeq()
{'testInt': -5, 'testEnum': 'coppa'}
>>> # DEFAULT value does not need to be assigned if not changed
>>> TestSeq.set_val( {'testEnum':'salami'} )

Traceback (most recent call last):
  File "<pyshell#114>", line 1, in <module>
    TestSeq.set_val( {'testEnum':'salami'} )
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 588, in set_val
    self._set_val_seq(val)
  File "C:\Users\benoit\Python\libmich\asn1\ASN1.py", line 494, in _set_val_seq
    % (self.get_fullname(), name)))
ASN1_OBJ: TestSeq: missing mandatory component: testInt
>>> # mandatory components need to get a value
```


How to encode / decode ASN.1 objects
====================================

This is the most interesting part of the project. It makes possible to parse
and build complete messages according to the ASN.1 specification, retrieve 
values passed to any encoded ASN.1 object, visualize the internal construction 
of any encoded messages thanks to the *show* function...

Currently, two encoders / decoders are supported:
* BER: Basic Encoding Rules (used in the MAP protocol), which makes use of 
   heavily nested Tag-Length-Value structures, in a byte-aligned way.
* PER: Packed Encoding Rules (used in all 3GPP radio access protocols), which 
   has two variants *aligned* and *unaligned*, which is more compressed and 
   sequential than BER, but not byte-aligned in most of the cases.

Encoders / decoders are making use of the libmich/core/ part to build and parse
message structures to be transferred. Those structures are set into the *_msg*
attribute of the ASN1Obj instance. It is a libmich *Layer* instance which has
all the properties of any Layer from libmich/core/element.py. The *show* 
function leverages actually the *show* method of the *_msg* attribute.

In case the required ASN.1 Python functions and objects are not yet imported:
```python
>>> from libmich.asn1.processor import *
```

In case you already crippled the **GLOBAL** object with lots of dummy ASN.1
definitions, you shoud clear it:
```python
>>> GLOBAL.clear()
```

In order to configure BER as the default encoder / decoder:
```python
>>> ASN1.ASN1Obj.CODEC = BER
```

In order to configure PER aligned as the default encoder / decoder:
```python
>>> ASN1.ASN1Obj.CODEC = PER
>>> PER.VARIANT = 'A'
```

In order to configure PER unaligned as the default encoder / decoder:
```python
>>> ASN1.ASN1Obj.CODEC = PER
>>> PER.VARIANT = 'U'
```

Then, you can use the methods *encode* after having set a value thanks to the 
*set_val(val)* method (see below), and *decode(buf)* in order to decode a buffer
according to the ASN1Obj instance definition.

Let's see an example with S1AP which uses PER aligned. A buffer corresponding
to an S1SetupResponse gets decoded, the structure of the transferred message is
showed, the value gets then modified and re-encoded:

```python
>>> load_module('S1AP')
S1AP: 894 objects loaded into GLOBAL
>>> ASN1.ASN1Obj.CODEC = PER
>>> PER.VARIANT = 'A'
>>> pdu = GLOBAL.TYPE['S1AP-PDU']
>>> pdu
<S1AP-PDU (CHOICE type)>
>>> buf = '201100170000020069000b000063f3100000800100010057400132'.decode('hex')
>>> pdu.decode(buf)
>>> pdu()
('successfulOutcome', {'procedureCode': 17, 'value': ('S1SetupResponse', {'protocolIEs': [{'value': ('ServedGUMMEIs', [{'servedGroupIDs': ['\x80\x01'], 'servedPLMNs': ['c\xf3\x10'], 'servedMMECs': ['\x01']}]), 'id': 105, 'criticality': 'reject'}, {'value': ('RelativeMMECapacity', 50), 'id': 87, 'criticality': 'ignore'}]}), 'criticality': 'reject'})
>>> show(pdu)
### [S1AP-PDU] ###
 <[E] : 0b0>
 ### [I] ###
  <[C] : '1 : successfulOutcome'>
 ### [successfulOutcome] ###
  ### [procedureCode] ###
   <[P] : 0b00000>
   <[C] : 17>
  ### [criticality] ###
   <[C] : '0 : reject'>
  <[P] : 0b000000>
  ### [value] ###
   ### [L] ###
    <[Form] : 0b0>
    <[Count] : 0b0010111>
   ### [S1SetupResponse] ###
    <[E] : 0b0>
    ### [protocolIEs] ###
     ### [L] ###
      <[P] : 0b0000000>
      <[C] : 2>
     ### [_item_ProtocolIE-Field] ###
      ### [id] ###
       <[C] : 105>
      ### [criticality] ###
       <[C] : '0 : reject'>
      <[P] : 0b000000>
      ### [value] ###
       ### [L] ###
        <[Form] : 0b0>
        <[Count] : 0b0001011>
       ### [ServedGUMMEIs] ###
        ### [L] ###
         <[C] : 0>
        ### [_item_ServedGUMMEIsItem] ###
         <[E] : 0b0>
         <[B] : 0b0>
         ### [servedPLMNs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_PLMNidentity] ###
           <[P] : 0b000000>
           <[C] : 0x63f310>
         ### [servedGroupIDs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_MME-Group-ID] ###
           <[C] : 0x8001>
         ### [servedMMECs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_MME-Code] ###
           <[C] : 0x01>
     ### [_item_ProtocolIE-Field] ###
      ### [id] ###
       <[C] : 87>
      ### [criticality] ###
       <[C] : '1 : ignore'>
      <[P] : 0b000000>
      ### [value] ###
       ### [L] ###
        <[Form] : 0b0>
        <[Count] : 0b0000001>
       ### [RelativeMMECapacity] ###
        <[C] : 50>
>>> val = pdu()
>>> val[1]['value'][1]['protocolIEs'][1]
{'value': ('RelativeMMECapacity', 50), 'id': 87, 'criticality': 'ignore'}
>>> val[1]['value'][1]['protocolIEs'][1]['value'] = ('RelativeMMECapacity', 255)
>>> pdu.set_val(val)
>>> pdu()
('successfulOutcome', {'procedureCode': 17, 'value': ('S1SetupResponse', {'protocolIEs': [{'value': ('ServedGUMMEIs', [{'servedGroupIDs': ['\x80\x01'], 'servedPLMNs': ['c\xf3\x10'], 'servedMMECs': ['\x01']}]), 'id': 105, 'criticality': 'reject'}, {'value': ('RelativeMMECapacity', 255), 'id': 87, 'criticality': 'ignore'}]}), 'criticality': 'reject'})
>>> pdu.encode()
>>> show(pdu)
### [S1AP-PDU] ###
 <[E] : 0b0>
 ### [I] ###
  <[C] : '1 : successfulOutcome'>
 ### [successfulOutcome] ###
  ### [procedureCode] ###
   <[P] : 0b00000>
   <[C] : 17>
  ### [criticality] ###
   <[C] : '0 : reject'>
  <[P] : 0b000000>
  ### [value] ###
   ### [L] ###
    <[Form] : 0b0>
    <[Count] : 0b0010111>
   ### [S1SetupResponse] ###
    <[E] : 0b0>
    ### [protocolIEs] ###
     ### [L] ###
      <[P] : 0b0000000>
      <[C] : 2>
     ### [_item_ProtocolIE-Field] ###
      ### [id] ###
       <[C] : 105>
      ### [criticality] ###
       <[C] : '0 : reject'>
      <[P] : 0b000000>
      ### [value] ###
       ### [L] ###
        <[Form] : 0b0>
        <[Count] : 0b0001011>
       ### [ServedGUMMEIs] ###
        ### [L] ###
         <[C] : 0>
        ### [_item_ServedGUMMEIsItem] ###
         <[E] : 0b0>
         <[B] : 0b0>
         ### [servedPLMNs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_PLMNidentity] ###
           <[P] : 0b000000>
           <[C] : 0x63f310>
         ### [servedGroupIDs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_MME-Group-ID] ###
           <[C] : 0x8001>
         ### [servedMMECs] ###
          ### [L] ###
           <[C] : 0>
          ### [_item_MME-Code] ###
           <[C] : 0x01>
     ### [_item_ProtocolIE-Field] ###
      ### [id] ###
       <[C] : 87>
      ### [criticality] ###
       <[C] : '1 : ignore'>
      <[P] : 0b000000>
      ### [value] ###
       ### [L] ###
        <[Form] : 0b0>
        <[Count] : 0b0000001>
       ### [RelativeMMECapacity] ###
        <[C] : 255>
>>> str(pdu)
' \x11\x00\x17\x00\x00\x02\x00i\x00\x0b\x00\x00c\xf3\x10\x00\x00\x80\x01\x00\x01\x00W@\x01\xff'
>>> buf
' \x11\x00\x17\x00\x00\x02\x00i\x00\x0b\x00\x00c\xf3\x10\x00\x00\x80\x01\x00\x01\x00W@\x012'
>>> GLOBAL.clear()
```

Here is another example with the RRC3G module, which uses PER unaligned. A 
Paging Control CHannel message (PCCH) gets decoded first and the corresponding
value retrieved. Then, the value corresponding to the first P-TMSI paged gets 
modified to a CS domain TMSI, and re-encoded:

```python
>>> load_module('RRC3G')
RRC3G: 4197 objects loaded into GLOBAL
>>> ASN1.ASN1Obj.CODEC = PER
>>> PER.VARIANT = 'U'
>>> pcch = GLOBAL.TYPE['PCCH-Message']
>>> pcch
<PCCH-Message (SEQUENCE type)>
>>> buf = '4455c803999055c601b95855aa06b09e'.decode('hex')
>>> pcch.decode(buf)
>>> pcch()
{'message': ('pagingType1', {'pagingRecordList': [('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3825323208L, 32))}), ('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3808484524L, 32))}), ('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3573766223L, 32))})]})}
>>> show(pcch)
### [PCCH-Message] ###
 ### [message] ###
  ### [I] ###
   <[C] : '0 : pagingType1'>
  ### [pagingType1] ###
   <[B] : 0b100>
   ### [pagingRecordList] ###
    ### [L] ###
     <[C] : 2>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '1 : ps-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '2 : p-TMSI-GSM-MAP'>
       ### [p-TMSI-GSM-MAP] ###
        <[C] : 0xe401ccc8>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '1 : ps-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '2 : p-TMSI-GSM-MAP'>
       ### [p-TMSI-GSM-MAP] ###
        <[C] : 0xe300dcac>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '1 : ps-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '2 : p-TMSI-GSM-MAP'>
       ### [p-TMSI-GSM-MAP] ###
        <[C] : 0xd503584f>
>>> val = pcch()
>>> val['message'][1]['pagingRecordList'][0]
('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3825323208L, 32))})
>>> val['message'][1]['pagingRecordList'][1]
('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3808484524L, 32))})
>>> val['message'][1]['pagingRecordList'][2]
('cn-Identity', {'cn-DomainIdentity': 'ps-domain', 'pagingCause': 'terminatingInteractiveCall', 'cn-pagedUE-Identity': ('p-TMSI-GSM-MAP', (3573766223L, 32))})
>>> val['message'][1]['pagingRecordList'][0][1]['cn-DomainIdentity'] = 'cs-domain'
>>> val['message'][1]['pagingRecordList'][0][1]['cn-pagedUE-Identity'] = ('tmsi-GSM-MAP', (10, 32))
>>> pcch.set_val(val)
>>> pcch.encode()
>>> show(pcch)
### [PCCH-Message] ###
 ### [message] ###
  ### [I] ###
   <[C] : '0 : pagingType1'>
  ### [pagingType1] ###
   <[B] : 0b100>
   ### [pagingRecordList] ###
    ### [L] ###
     <[C] : 2>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '0 : cs-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '1 : tmsi-GSM-MAP'>
       ### [tmsi-GSM-MAP] ###
        <[C] : 0x0000000a>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '1 : ps-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '2 : p-TMSI-GSM-MAP'>
       ### [p-TMSI-GSM-MAP] ###
        <[C] : 0xe300dcac>
    ### [_item_PagingRecord] ###
     ### [I] ###
      <[C] : '0 : cn-Identity'>
     ### [cn-Identity] ###
      ### [pagingCause] ###
       <[C] : '2 : terminatingInteractiveCall'>
      ### [cn-DomainIdentity] ###
       <[C] : '1 : ps-domain'>
      ### [cn-pagedUE-Identity] ###
       ### [I] ###
        <[C] : '2 : p-TMSI-GSM-MAP'>
       ### [p-TMSI-GSM-MAP] ###
        <[C] : 0xd503584f>
>>> str(pcch)
'DB\x00\x00\x00\x14U\xc6\x01\xb9XU\xaa\x06\xb0\x9e'
>>> buf
'DU\xc8\x03\x99\x90U\xc6\x01\xb9XU\xaa\x06\xb0\x9e'
```

How to extend the code
======================

Structure of the ASN.1 code
---------------------------

The following Python files are provided:
* *utils.py*: it provides global variables, functions and short routines for
   processing the ASN.1 language.
* *parsers.py*: it provides all required textual processing to parse the ASN.1
   syntax and convert it to Python dictionnaries.
* *ASN1.py*: it provides the class ASN1Obj and all methods required for handling
   all ASN.1 types as Python objects. Furthermore, it provides an empty 
   ASN1Codec class.
* *processor.py*: it provides the main functions to compile, build Python modules
   and process inlined ASN.1 definitions. This is also the main file to import
   if we want to import everything needed to work with ASN.1.
* *PER.py*: it provides the PER aligned and unaligned encoder / decoder.
* *BER.py*: it provides the BER encoder / decoder.
* *test.py*: it provides a serie of tests, in order to confirm the correct 
   implementation and working of the ASN.1 processor and PER encoder / decoder.

Supporting a new ASN.1 type
---------------------------

It is possible to support new ASN.1 types, such as RELATIVE-OID, EMBEDDED-PDV,
XYZString, ...

For this, the global variables required need to be created in the *utils.py* 
file, specific processing and methods need to be created in the ASN1Obj class 
in the *ASN1.py* file, and specific syntax parsing routines need to be created 
in the *parsers.py* file. When doing so, it is required not to break any of the 
testing functions provided in the *test.py* file.

Supporting a new ASN.1 codec
----------------------------

It is possible to introduce a new ASN.1 encoder / decoder. A new file containing
a new ASN1Codec class, with *encode(obj)* and *decode(obj, buf)* methods, needs 
to be created similarly to what is done in *PER.py* and *BER.py*.


Contact
=======

As part of the libmich library, the license and contact does not change:
see [libmich](https://github.com/mitshell/libmich/).

