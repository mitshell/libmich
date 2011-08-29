###########
# libmich #
###########
# READ ME #
###########

This library is being developped since 2009, when I started to work with some 
telecoms and mobile protocols. France Telecom SA, my employer, has kindly accepted 
me to publish it over GPLv2.

1) How to install?
Actually, nothing specific is required in addition to python-2 (at least version 2.6). 
See http://www.python.org/. 
For formats making use of ciphering (i.e. IKEv2, EAPAKA), the python 
cryptography library pycrypto is used. See https://www.dlitz.net/software/pycrypto/

Then, you only need to place the 'libmich' directory with its files in your
PYTHONPATH. You can for example place it in the python's 'sitepackage' directoy,
or anywhere else your python engine is configured to look and load external modules.

2) Why python?
because...

3) Why not python 3?
because...
Be careful, the code is currently not compatible with python-3 (I will have to
manage it... in the future)

4) What does it do?
this library can be seen as a poor and rachitic clone of scapy, in the sense that
it is made to build easily any types of digital format (by defining data structures,
similarly than in C). Once a format is properly defined, it becomes very easy
to build messages based on it, and to parse binary streams to fit into it.

Automating fields is very easy (primarily thanks to python). For example, defining
a Tag-Length-Value format is straightforward; the 'Tag' field can reference a 
dictionnary to print human-readable information instead of integer value; the 'Length'
field computation, when creating a message, is defined very easily by referencing
the 'Value' field into one of its specific attribute.

5) Why not introducing all these formats directly into scapy?
Actually, scapy is network oriented. Formats are stacked: what comes first is 
considered header of what comes after, that is considered as payload. I got so much
headaches when I initially worked on the IKEv2 format, that I decided to make a 
proper little library to manage it. I introduced a notion of hierarchy between the 
different layers that are used into the IKEv2 format. With the time, I introduced
new tips to make it even more convinient (see how L3Mobile* modules are made).

I also found that automatic field computation in scapy is done when packets are 
going through its socket interface (when read / write): this is made by calling 
'pre' and 'post' procedures. On my side, I wanted format's instances to be fully 
independent of what is going to be done on them. So when a format is instantiated, 
every fields that require automation are evaluated at each call.

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
If people are interested and I have time for it, I'll do some little tutorials.

8) What are the worse formats?
Clearly: IKEv2 (with ciphering and MAC computation aspects)
But also: SCTP, IPv4 (yes... IPv4), and L3Mobile (Layer 3 of mobile signalling)
 
9) Where can I get some support?
You can drop me an email at: michau (dot) benoit (at) gmail (dot) com
However, I cannot promise I will be able to response in short delay.

Have fun!

