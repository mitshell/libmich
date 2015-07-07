# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.3
# *
# * Copyright © 2014. Benoit Michau. ANSSI.
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
# * File Name : asn1/test.py
# * Created : 2014-08-06
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

from time import time

from libmich.utils.repr import *

import ASN1
from PER import PER
from utils import *
from processor import inline, compile, export, load_module, GLOBAL

def test_def(print_info=True):
    
    ASN1.ASN1Obj._SAFE = True
    ASN1.ASN1Obj._RET_STRUCT = True
    
    MODULE_OPT.TAG = TAG_AUTO
    
    if print_info: print('testing NULL definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_NULL)
    A.set_val(None)
    
    if print_info: print('testing BOOLEAN definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_BOOL)
    A.set_val(False)
    A.set_val(True)
    
    if print_info: print('testing INTEGER definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_INTEGER)
    A.set_val(0)
    A.set_val(-999999999999999999999999999)
    A.set_val(111999999999999999999999999999111)
    
    if print_info: print('testing ENUMERATED definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_ENUM)
    A._cont = OD([('un', 1), ('deux', 2), ('trois', 3)])
    A.set_val('un') # parce qu'un tien vaut mieux que deux tu l'auras 
    
    if print_info: print('testing BIT STRING definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_BIT_STR)
    A.set_val((0b11001100111000, 16))
    A.parse_value("'0011001100111000'B")
    A.parse_value("'3338'H")
    
    if print_info: print('testing OCTET STRING definition')
    A = ASN1.ASN1Obj(name='A', type=TYPE_OCTET_STR)
    A.set_val('la grande truite')
    A.parse_value("'11001100111000'B")
    A.parse_value("'3338'H")
    
    if print_info: print('testing CHOICE definition')
    A = inline('''
        A ::= CHOICE {
            a1 BOOLEAN,
            a2 INTEGER (0..20),
            a3 NULL,
            a4 INTEGER(MIN..100, ...),
            ...,
            a5 BIT STRING (SIZE(0..80))
            }''')
    A.set_val( ('a1', True) )
    A.set_val( ('a2', 12) )
    A.set_val( ('a3', None) )
    A.set_val( ('a4', -50000000) )
    A.set_val( ('a5', (1000000000000000000001, 70)) )
    
    A = inline('''
        A ::= CHOICE {
            c1  INTEGER {first(1), second(2)} (1..50, ...),
            c2  ENUMERATED {first, second, third, ..., fourth},
            c3  BIT STRING {first-bit(1), second-bit(2)} (SIZE(8..16, ...)),
            c4  OCTET STRING (SIZE(10..20)),
            c5  CHOICE { c51  INTEGER (-20..50),
                         c52  BOOLEAN,
                         c53  NULL,
                         c54  BOOLEAN },
            ...,
            c6  OBJECT IDENTIFIER,
            c7  BOOLEAN
            }
    ''')
    A.set_val( ('c1', 500) )
    A.set_val( ('c2', 'fourth') )
    A.set_val( ('c3', (0b10100000, 12)) )
    A.set_val( ('c4', 'abcdefghijklmn') )
    A.set_val( ('c5', ('c54', True)) )
    A.set_val( ('c6', (1, 2, 3)) )
    A.set_val( ('c7', False) )
    
    if print_info: print('testing SEQUENCE definition')
    A = inline('''
        A ::= SEQUENCE {
            s1  INTEGER {first(1), second(2)} (1..50, ...),
            s2  ENUMERATED {first, second, third},
            s3  SEQUENCE { s31  BOOLEAN,
                           s32  NULL,
                           s33  BIT STRING (SIZE(56..64)),
                           s34  BOOLEAN DEFAULT FALSE},
            ...,
            s4  NULL OPTIONAL,
            s5  CHOICE { s51  INTEGER (-20..50),
                         s52  BOOLEAN,
                         s53  NULL,
                         s54  BOOLEAN }
            }
    ''')
    A.set_val({'s1':50,
               's2':'third',
               's3':{'s31':True, 's32':None, 's33':(1, 64)}
               })
    A.set_val({'s1':-5000,
               's2':'third',
               's3':{'s31':True, 's32':None, 's33':(1, 64), 's34':False},
               's4':None,
               's5':('s52', True)
               })
    
    if print_info: print('testing SEQUENCE OF definition')
    A = inline('''
        A ::= SEQUENCE (SIZE(1..5, ...)) OF INTEGER (0..MAX)
        ''')
    A.set_val([1, 2, 5, 41, 566321564])
    A = inline('''
        A ::= SEQUENCE (SIZE(1..3, ...)) OF OCTET STRING (SIZE(0..10, ...))
        ''')
    A.set_val(['a', 'abcdef', 'abcdef'*50])
    
    if print_info: print('testing CLASS definition')
    C3 = inline('''
        C3 ::= INTEGER
        ''')
    C3.set_val(230000)
    A = inline('''
        A ::= CLASS {
            &c1 INTEGER UNIQUE,
            &c2 ENUMERATED {first},
            &C3,
            &c4 INTEGER } WITH SYNTAX {
            IDENT &c1 PLACE &c2 TYPE &C3 VALUE &c4 }
        ''')
    A.set_val({'c1':10,
               'c2':'first',
               'C3':('C3', 23000),
               'c4':1
               })

def test_per_integer(print_info=True):
    
    ASN1.ASN1Obj._SAFE = True
    ASN1.ASN1Obj._RET_STRUCT = True
    ASN1.ASN1Obj.CODEC = PER
    #
    PER._REPR_INT = 'bin'
    PER._REPR_ENUM = 'bin'
    #
    PER.VARIANT = 'A'
    
    if print_info: print('testing unconstrained INTEGER encoding / decoding (PER)')
    i1 = inline('I1 ::= INTEGER')
    i1.encode(4096)
    #print('i1:\n%s' % i1._msg.show())
    assert(str(i1) == '\x02\x10\x00')
    i1d = inline('I1D ::= INTEGER')
    buf = i1d.decode(str(i1))
    assert(str(i1d) == str(i1) and i1d() == i1())
    
    i2 = inline('I2 ::= INTEGER (MIN..65535)')
    i2.encode(127)
    #print('i2:\n%s' % i2._msg.show())
    assert(str(i2) == '\x01\x7f')
    i2d = inline('I2D ::= INTEGER (MIN..65535)')
    buf = i2d.decode(str(i2))
    assert(str(i2d) == str(i2) and i2d() == i2())
    
    i3 = inline('I3 ::= INTEGER (MIN..65535)')
    i3.encode(-128)
    #print('i3:\n%s' % i3._msg.show())
    assert(str(i3) == '\x01\x80')
    i3d = inline('I3D ::= INTEGER (MIN..65535)')
    buf = i3d.decode(str(i3))
    assert(str(i3d) == str(i3) and i3d() == i3())
    
    i4 = inline('I4 ::= INTEGER (MIN..65535)')
    i4.encode(128)
    #print('i4:\n%s' % i4._msg.show())
    assert(str(i4) == '\x02\x00\x80')
    i4d = inline('I4D ::= INTEGER (MIN..65535)')
    buf =  i4d.decode(str(i4))
    assert(str(i4d) == str(i4) and i4d() == i4())
    #return i1, i2, i3, i4
    
    if print_info: print('testing semi-constrained INTEGER encoding / decoding (PER)')
    i5 = inline('I5 ::= INTEGER (-1..MAX)')
    i5.encode(4096)
    #print('i5: %s' % i5._msg.show())
    assert(str(i5) == '\x02\x10\x01')
    i5d = inline('I5D ::= INTEGER (-1..MAX)')
    buf = i5d.decode(str(i5))
    assert(str(i5d) == str(i5) and i5d() == i5())
    
    i6 = inline('I6 ::= INTEGER (1..MAX)')
    i6.encode(127)
    #print('i6: %s' % i6._msg.show())
    assert(str(i6) == '\x01~')
    i6d = inline('I6D ::= INTEGER (1..MAX)')
    buf = i6d.decode(str(i6))
    assert(str(i6d) == str(i6) and i6d() == i6())
    
    i7 = inline('I7 ::= INTEGER (0..MAX)')
    i7.encode(128)
    #print('i7: %s' % i7._msg.show())
    assert(str(i7) == '\x01\x80')
    i7d = inline('I7D ::= INTEGER (0..MAX)')
    buf = i7d.decode(str(i7))
    assert(str(i7d) == str(i7) and i7d() == i7())
    #return i1, i2, i3, i4, i5, i6, i7
    
    if print_info: print('testing constrained INTEGER encoding / decoding (PER aligned / unaligned)')
    i8 = inline('I8 ::= INTEGER(3..6)')
    i8.encode(3)
    assert(i8._msg.__bin__() == '00')
    i8d = inline('I8D ::= INTEGER(3..6)')
    buf = i8d.decode(str(i8))
    assert(str(i8d) == str(i8) and i8d() == i8())
    i8.encode(4)
    assert(i8._msg.__bin__() == '01')
    buf = i8d.decode(str(i8))
    assert(str(i8d) == str(i8) and i8d() == i8())
    i8.encode(5)
    assert(i8._msg.__bin__() == '10')
    buf = i8d.decode(str(i8))
    assert(str(i8d) == str(i8) and i8d() == i8())
    i8.encode(6)
    assert(i8._msg.__bin__() == '11')
    buf = i8d.decode(str(i8))
    assert(str(i8d) == str(i8) and i8d() == i8())
    #print('i8 (6): %s' % i8._msg.show())
    
    i9 = inline('I9 ::= INTEGER (4000..4254)')
    i9.encode(4002)
    assert(str(i9) == '\x02')
    i9d = inline('I9D ::= INTEGER (4000..4254)')
    buf = i9d.decode(str(i9))
    assert(str(i9d) == str(i9) and i9d() == i9())
    i9.encode(4006)
    assert(str(i9) == '\x06')
    buf = i9d.decode(str(i9))
    assert(str(i9d) == str(i9) and i9d() == i9())
    #print('i9 (4006): %s' % i9._msg.show())
    
    i10 = inline('I10 ::= INTEGER (4000..4255)')
    i10.encode(4002)
    assert(str(i10) == '\x02')
    i10d = inline('I10D ::= INTEGER (4000..4255)')
    buf = i10d.decode(str(i10))
    assert(str(i10d) == str(i10) and i10d() == i10())
    i10.encode(4006)
    assert(str(i10) == '\x06')
    buf = i10d.decode(str(i10))
    assert(str(i10d) == str(i10) and i10d() == i10())
    #print('i10 (4006): %s' % i10._msg.show())
    
    i11 = inline('I11 ::= INTEGER (0..32000)')
    i11.encode(0)
    assert(str(i11) == '\0\0')
    i11d = inline('I11D ::= INTEGER (0..32000)')
    buf = i11d.decode(str(i11))
    assert(str(i11d) == str(i11) and i11d() == i11())
    i11.encode(31000)
    assert(str(i11) == '\x79\x18')
    buf = i11d.decode(str(i11))
    assert(str(i11d) == str(i11) and i11d() == i11())
    #print('i11 (31000): %s' % i11._msg.show())
    
    i12 = inline('I12 ::= INTEGER (1..65538)')
    i12.encode(1)
    assert(str(i12) == '\0\0')
    i12d = inline('I12D ::= INTEGER (1..65538)')
    buf = i12d.decode(str(i12))
    assert(str(i12d) == str(i12) and i12d() == i12())
    i12.encode(257)
    assert(str(i12) == '@\x01\x00')
    buf = i12d.decode(str(i12))
    assert(str(i12d) == str(i12) and i12d() == i12())
    i12.encode(65538)
    assert(str(i12) == '\x80\x01\x00\x01')
    buf = i12d.decode(str(i12))
    assert(str(i12d) == str(i12) and i12d() == i12())
    #print('i12 (65538 - aligned): %s' % i12._msg.show())
    
    PER.VARIANT = 'U'
    i12.encode(1)
    assert(i12._msg.__bin__() == '00000000000000000')
    buf = i12d.decode(str(i12))
    assert(i12d() == i12())
    i12.encode(257)
    assert(i12._msg.__bin__() == '00000000100000000')
    buf = i12d.decode(str(i12))
    assert(i12d() == i12())
    i12.encode(65538)
    assert(i12._msg.__bin__() == '10000000000000001')
    buf = i12d.decode(str(i12))
    assert(i12d() == i12())
    #print('i12 (65538 - unaligned): %s' % i12._msg.show())
    #return i8, i9, i10, i11, i12
    
    PER.VARIANT = 'A'
    if print_info: print('testing extended INTEGER encoding / decoding (PER aligned / unaligned)')
    i13 = inline('I13 ::= INTEGER(MIN..65535, ...)')
    i13.encode(127)
    assert(str(i13) == '\x00\x01\x7f')
    i13d = inline('I13D ::= INTEGER(MIN..65535, ...)')
    buf = i13d.decode(str(i13))
    assert(str(i13d) == str(i13) and i13d() == i13())
    i13.encode(65536)
    assert(str(i13) == '\x80\x03\x01\x00\x00')
    buf = i13d.decode(str(i13))
    assert(str(i13d) == str(i13) and i13d() == i13())
    #print('i13 (65536): %s' % i13._msg.show())
    
    i14 = inline('I14 ::= INTEGER (-1..MAX, ...)')
    i14.encode(4096)
    assert(str(i14) == '\x00\x02\x10\x01')
    i14d = inline('I14D ::= INTEGER (-1..MAX, ...)')
    buf = i14d.decode(str(i14))
    assert(str(i14d) == str(i14) and i14d() == i14())
    i14.encode(-8)
    assert(str(i14) == '\x80\x01\xf8')
    buf = i14d.decode(str(i14))
    assert(str(i14d) == str(i14) and i14d() == i14())
    #print('i14 (-8): %s' % i14._msg.show())
    
    i15 = inline('I15 ::= INTEGER (3..6, ...)')
    i15.encode(4)
    assert(i15._msg.__bin__() == '001')
    i15d = inline('I15D ::= INTEGER (3..6, ...)')
    buf = i15d.decode(str(i15))
    assert(str(i15d) == str(i15) and i15d() == i15())
    i15.encode(8)
    assert(str(i15) == '\x80\x01\x08')
    buf = i15d.decode(str(i15))
    assert(str(i15d) == str(i15) and i15d() == i15())
    #print('i15 (8): %s' % i15._msg.show())
    
    i16 = inline('I16 ::= INTEGER (1..65538, ...)')
    i16.encode(257)
    assert(str(i16) == ' \x01\x00')
    i16d = inline('I16D ::= INTEGER (1..65538, ...)')
    buf = i16d.decode(str(i16))
    assert(str(i16d) == str(i16) and i16d() == i16())
    i16.encode(65539)
    assert(str(i16) == '\x80\x03\x01\x00\x03')
    buf = i16d.decode(str(i16))
    assert(str(i16d) == str(i16) and i16d() == i16())
    #print('i16 (65539 - aligned): %s' % i16._msg.show())
    #
    PER.VARIANT = 'U'
    i16.encode(257)
    assert(i16._msg.__bin__() == '000000000100000000')
    buf = i16d.decode(str(i16))
    assert(i16d() == i16())
    i16.encode(65539)
    assert(i16._msg.__bin__() == '100000011000000010000000000000011')
    buf = i16d.decode(str(i16))
    assert(i16d() == i16())
    #print('i16 (65539 - unaligned): %s' % i16._msg.show())
    #return i13, i14, i15, i16
    
    PER.VARIANT = 'A'

def test_per_choice(print_info=True):
    
    ASN1.ASN1Obj._SAFE = True
    ASN1.ASN1Obj._RET_STRUCT = True
    ASN1.ASN1Obj.CODEC = PER
    #
    PER._REPR_INT = 'bin'
    PER._REPR_ENUM = 'bin'
    #
    PER.VARIANT = 'A'
    
    if print_info: print('testing BIT STRING and CHOICE encoding /decoding (PER aligned)')
    PER.VARIANT = 'A'
    a = inline('''
        A ::= CHOICE {
            a1 BIT STRING (SIZE(4..8)),
            a2 BIT STRING (SIZE(5..10, ...)),
            ...,
            a3 BIT STRING,
            a4 BIT STRING (SIZE(4..8, ...))
            }
        ''')
    b = a.clone()
    #
    a.encode(('a1', (0b111000, 6)))
    #print('a1 (0b111000): %s' % a._msg.show())
    assert(a._msg.__hex__() == '10e0')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a2', (0b10101, 5)))
    #print('a2 (0b10101): %s' % a._msg.show())
    assert(a._msg.__hex__() == '40a8')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a2', (0b111111111111111111111, 21)))
    #print('a2 (0x1fffff): %s' % a._msg.show())
    assert(a._msg.__hex__() == '6015fffff8')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a3', (1, 1)))
    #print('a3 (0b1): %s' % a._msg.show())
    assert(a._msg.__hex__() == '80020180')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a3', (0x617a6572747975696f70617a6572747975696f70, 160)))
    #print('a3 (azertyuiopazertyuiop): %s' % a._msg.show())
    assert(a._msg.__hex__() == '801680a0617a6572747975696f70617a6572747975696f70')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a4', (0, 0)))
    #print('a4 (0): %s' % a._msg.show())
    assert(a._msg.__hex__() == '81028000')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a4', (0x4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141, 4000)))
    #print('a5 (500*"A"): %s' % a._msg.show())
    assert(str(a) == '\x81\x81\xf7\x80\x8f\xa0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    
    if print_info: print('testing BIT STRING and CHOICE encoding / decoding (PER unaligned)')
    PER.VARIANT = 'U'
    #
    a.encode(('a1', (0b111000, 6)))
    #print('a1 (0b111000): %s' % a._msg.show())
    assert(a._msg.__bin__() == '00010111000')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a2', (0b10101, 5)))
    #print('a2 (0b10101): %s' % a._msg.show())
    assert(a._msg.__bin__() == '01000010101')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a2', (0b111111111111111111111, 21)))
    #print('a2 (0x1fffff): %s' % a._msg.show())
    assert(a._msg.__bin__() == '01100010101111111111111111111111')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a3', (1, 1)))
    #print('a3 (0b1): %s' % a._msg.show())
    assert(a._msg.__bin__() == '10000000000000100000000110000000')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a3', (0x617a6572747975696f70617a6572747975696f70, 160)))
    #print('a3 (azertyuiopazertyuiop): %s' % a._msg.show())
    assert(a._msg.__hex__() == '801680a0617a6572747975696f70617a6572747975696f70')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a4', (0, 0)))
    #print('a4 (0): %s' % a._msg.show())
    assert(a.__bin__() == '10000001000000101000000000000000')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode(('a4', (0x4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141, 4000)))
    #print('a5 (500*"A"): %s' % a._msg.show())
    assert(a.__hex__() == '8181f7c7d020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a080')
    b.decode( str(a) )
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())

def test_per_sequence(print_info=True):
    
    ASN1.ASN1Obj._SAFE = True
    ASN1.ASN1Obj._RET_STRUCT = True
    ASN1.ASN1Obj.CODEC = PER
    #
    PER._REPR_INT = 'bin'
    PER._REPR_ENUM = 'bin'
    #
    PER.VARIANT = 'A'
    
    if print_info: print('testing OCTET STRING and SEQUENCE encoding / decoding (PER aligned)')
    PER.VARIANT = 'A'
    a = inline('''
        A ::= SEQUENCE {
            s1  INTEGER (1..50, ...),
            s2  ENUMERATED {first, second, third},
            s3  BOOLEAN OPTIONAL,
            s4  INTEGER (-10..20) DEFAULT 5,
            s5  OCTET STRING (SIZE(2..10, ...)),
            ...,
            s8  INTEGER,
            s9  BOOLEAN
            }
        ''')
    b = a.clone()
    
    a.encode({'s1':2, 's2':'second', 's3':True, 's4':2, 's5':'abcdef'})
    #print('a (2, second, True, 2, abcdef): %s' % a._msg.show())
    assert(a._msg.__hex__() == '605b08616263646566')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':2, 's2':'second', 's5':'abcdef'})
    #print('a (2, second, abcdef): %s' % a._msg.show())
    assert(a._msg.__hex__() == '005200616263646566')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':2, 's2':'second', 's5':'a', 's8':500000})
    #print('a (2, second, a, 500000): %s' % a._msg.show())
    assert(a._msg.__hex__() == '805801610300040307a120')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':200, 's2':'third', 's3':False, 's5':'', 's8':5000000, 's9':True})
    #print('a (200, third, False, , 5000000, True): %s' % a._msg.show())
    assert(a._msg.__hex__() == 'd00200c89000038004034c4b400180')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':200, 's2':'third', 's3':False, 's5':300*'A', 's8':-10, 's9':True})
    #print('a (200, third, False, , 300*A, -10, True): %s' % a.show())
    assert(a._msg.__hex__() == 'd00200c890812c41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414103800201f60180')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    
    if print_info: print('testing OCTET STRING and SEQUENCE encoding (PER unaligned)')
    PER.VARIANT = 'U'
    a.encode({'s1':2, 's2':'second', 's3':True, 's4':2, 's5':'abcdef'})
    #print('a (2, second, True, 2, abcdef): %s' % a._msg.show())
    assert(a._msg.__bin__() == '01100000010110110000100011000010110001001100011011001000110010101100110')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':2, 's2':'second', 's5':'abcdef'})
    #print('a (2, second, abcdef): %s' % a._msg.show())
    assert(a._msg.__bin__() == '00000000010100100011000010110001001100011011001000110010101100110')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':2, 's2':'second', 's5':'a', 's8':500000})
    #print('a (2, second, a, 500000): %s' % a._msg.show())
    assert(a._msg.__bin__() == '100000000101100000001011000010000001100000010000000011000001111010000100100000')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':200, 's2':'third', 's3':False, 's5':'', 's8':5000000, 's9':True})
    #print('a (200, third, False, , 5000000, True): %s' % a._msg.show())
    assert(a._msg.__bin__() == '110100000010000000001100100010010000000000000011100000100000000110100110001001011010000000000000110000000')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode({'s1':200, 's2':'third', 's3':False, 's5':300*'A', 's8':-10, 's9':True})
    #print('a (200, third, False, , 300*A, -10, True): %s' % a._msg.show())
    assert(a._msg.__hex__() == 'd0200c89812c414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141038100fb00c00')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    
    PER.VARIANT = 'A'
    a = inline('''
        A ::= SEQUENCE {
            s1  INTEGER {first(1), second(2)} (1..50, ...),
            s2  ENUMERATED {first, second, third},
            s3  SEQUENCE { s31  BOOLEAN,
                           s32  NULL,
                           s33  BIT STRING (SIZE(56..64)),
                           s34  BOOLEAN DEFAULT FALSE},
            ...,
            s4  NULL OPTIONAL,
            s5  CHOICE { s51  INTEGER (-20..50),
                         s52  BOOLEAN,
                         s53  NULL,
                         s54  BOOLEAN }
            }
    ''')
    b = a.clone()
    
    a.encode({'s1':-5000,
              's2':'third',
              's3':{'s31':True, 's32':None, 's33':(1, 64), 's34':False},
              's4':None,
              's5':('s52', True)
              })
    #print('a (-5000, third, {True, None, (1, 64), False}, None, (s52, True)): %s' % a._msg.show())
    assert(a._msg.__hex__() == 'c002ec78980000000000000001038001000160')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    
    PER.VARIANT = 'U'
    a.encode({'s1':-5000,
              's2':'third',
              's3':{'s31':True, 's32':None, 's33':(1, 64), 's34':False},
              's4':None,
              's5':('s52', True)
              })
    #print('a (-5000, third, {True, None, (1, 64), False}, None, (s52, True)): %s' % a._msg.show())
    assert(a._msg.__hex__() == 'c0bb1e26000000000000000040e020002c0' and a._msg.bit_len() == 139)
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    
    if print_info: print('testing SEQUENCE OF encoding / decoding (PER aligned)')
    PER.VARIANT = 'A'
    a = inline('''
        A ::= SEQUENCE (SIZE(2..10, ...)) OF OCTET STRING (SIZE(0..10, ...))
        ''')
    b = a.clone()
    
    a.encode(['abc', '', 5*'a', 11*'A', 25*'B'])    
    #print('a (abc, , 5*a, 11*A, 25*B): %s' % a._msg.show())
    assert(a._msg.__hex__() == '18c061626301406161616161800b4141414141414141414141801942424242424242424242424242424242424242424242424242')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    a.encode([13*'XY'])
    #print('a (13*XY): %s' % a._msg.show())
    assert(a._msg.__hex__() == '8001801a5859585958595859585958595859585958595859585958595859')
    b.decode(str(a))
    assert(a._msg.__hex__() == b._msg.__hex__() and a() == b())
    #
    a = inline('''
        A ::= SEQUENCE SIZE(2..10, ...) OF INTEGER (0..300)
        ''')
    b = a.clone()
    a.encode(range(300))
    assert(a.__hex__() == '80812c0000000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019001a001b001c001d001e001f0020002100220023002400250026002700280029002a002b002c002d002e002f0030003100320033003400350036003700380039003a003b003c003d003e003f0040004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005b005c005d005e005f0060006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400750076007700780079007a007b007c007d007e007f0080008100820083008400850086008700880089008a008b008c008d008e008f0090009100920093009400950096009700980099009a009b009c009d009e009f00a000a100a200a300a400a500a600a700a800a900aa00ab00ac00ad00ae00af00b000b100b200b300b400b500b600b700b800b900ba00bb00bc00bd00be00bf00c000c100c200c300c400c500c600c700c800c900ca00cb00cc00cd00ce00cf00d000d100d200d300d400d500d600d700d800d900da00db00dc00dd00de00df00e000e100e200e300e400e500e600e700e800e900ea00eb00ec00ed00ee00ef00f000f100f200f300f400f500f600f700f800f900fa00fb00fc00fd00fe00ff0100010101020103010401050106010701080109010a010b010c010d010e010f0110011101120113011401150116011701180119011a011b011c011d011e011f0120012101220123012401250126012701280129012a012b')
    b.decode(str(a))
    assert(a() == b())
    
    if print_info: print('testing SEQUENCE OF encoding / decoding (PER unaligned)')
    PER.VARIANT = 'U'
    a = inline('''
        A ::= SEQUENCE (SIZE(2..10, ...)) OF OCTET STRING (SIZE(0..10, ...))
        ''')
    b = a.clone()
    
    a.encode(['abc', '', 5*'a', 11*'A', 25*'B'])    
    #print('a (abc, , 5*a, 11*A, 25*B): %s' % a._msg.show())
    assert(a._msg.__hex__() == '18d85898c05616161616185a0a0a0a0a0a0a0a0a0a0a0c6509090909090909090909090909090909090909090909090908' and a._msg.bit_len() == 390)
    b.decode(str(a))
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    a.encode([13*'XY'])
    #print('a (13*XY): %s' % a._msg.show())
    assert(a._msg.__hex__() == '80c696165616561656165616561656165616561656165616561656164' and a._msg.bit_len() == 226)
    b.decode(str(a))
    assert(a._msg.__bin__() == b._msg.__bin__() and a() == b())
    
    a = inline('''
        A ::= SEQUENCE SIZE(2..10, ...) OF INTEGER (0..300)
        ''')
    b = a.clone()
    a.encode(range(300))
    assert(a.__hex__() == 'c0960000202018100a0603820120a058301a0e078402212098502a160b860321a0d8703a1e0f8804222118904a26138a0522a158b05a2e178c06232198d06a361b8e0723a1d8f07a3e1f9008242219108a4623920924a259309a4e27940a25229950aa562b960b25a2d970ba5e2f980c26231990ca66339a0d26a359b0da6e379c0e272399d0ea763b9e0f27a3d9f0fa7e3fa01028241a110a8643a21128a45a311a8e47a41229249a512a964ba61329a4da713a9e4fa8142a251a914aa653aa152aa55ab15aae57ac162b259ad16ab65bae172ba5daf17abe5fb0182c261b118ac663b2192ca65b319ace67b41a2d269b51aad66bb61b2da6db71bade6fb81c2e271b91cae673ba1d2ea75bb1daee77bc1e2f279bd1eaf67bbe1f2fa7dbf1fafe7fc02030281c120b0683c22130a85c321b0e87c42231289c522b168bc62331a8dc723b1e8fc82432291c924b2693ca2532a958' and a._msg.bit_len() == 2717)
    b.decode(str(a))
    assert(a() == b())

def _test_s1ap_prep():
    GLOBAL.clear()
    try:
        load_module('S1AP')
    except:
        log('Module "S1AP" unavailable')
        return None
    ASN1.ASN1Obj._RAISE_SILENTLY = False
    ASN1.ASN1Obj.CODEC = PER
    PER.VARIANT = 'A'
    unh = lambda x: x.decode('hex')
    #
    # logs taken from an Amarisoft LTE100 network
    # http://www.amarisoft.com
    #
    pkts = map(unh, [\
    '0011002d000004003b00080063f310001a2d00003c400a0380656e623161326430004000070000004063f3100089400140',
    '201100170000020069000b000063f3100000800100010057400132',
    '000c408083000005000800020001001a005b5a17e24564d9040741020bf663f3108001010000000104e060c04000210208d011d1271a8080211001000010810600000000830600000000000d00000a005263f31000015c0a003103e5e0341363f310000111035758a65d0100e0004300060063f3100001006440080063f3101a2d00100086400130',
    '000b4038000003000000020064000800020001001a002524075200c38bb94032cc40b533057327b25e335510a4f43c006d9c90017ed284accdaf768c',
    '000d403b000005000000020064000800020001001a001211171f524dde06075308b7ae79df8ece4200006440080063f3101a2d0010004340060063f3100001',
    '00090080b30000060000000200640008000200010042000a1805f5e1006002faf0800018006500003400604500093c0f807f00016403b9d2465127e0c3b4e302074202e0060063f310000100245208c101090807746573743132330501c0a80302270e8080210a0300000a8106c0a8fd01500bf663f310800101000000011363f310000123050400000001006b000518000c000000490020c9b9530a37fc57d7a7a66a476677cac689cf9cb4c713ba88da20b4fb8bb2bdd9',
    '00164050000003000000020064000800020001004a403d3c01d001037c5980060008208183930d1bf8fff1bf8fff1bf8fff1bf8fff1bf8fff1bf8fff1bf8ffeff9ffd75103004870ca74a92246058c0000000000',
    '200900220000030000400200640008400200010033400f000032400a0a1f7f0001014ca724db',
    '00124015000003000000020064000800020001000240020280',
    '001700110000020063000400640001000240020280',
    '2017000f000002000040020064000840020001'
    ])
    return pkts

def _test_s1ap(pkts):
    T0 = time()
    i = 1
    #
    pdu = GLOBAL.TYPE['S1AP-PDU']
    for msg in pkts:
        pdu.decode(msg)
        assert( str(pdu) == msg )
        val = pdu()
        buf = pdu.encode()
        assert( str(pdu) == msg )
        assert( pdu() == val )
        i += 1
    #
    return time() - T0

def test_s1ap():
    pkts = _test_s1ap_prep()
    if pkts is not None:
        void = _test_s1ap(pkts)

def _test_x2ap_prep():
    GLOBAL.clear()
    try:
        load_module('X2AP')
    except:
        log('Module "X2AP" unavailable')
        return None
    ASN1.ASN1Obj._RAISE_SILENTLY = False
    ASN1.ASN1Obj.CODEC = PER
    PER.VARIANT = 'A'
    unh = lambda x: x.decode('hex')
    #
    # logs nicely submitted by Alexandre De Oliveira (P1)
    # (2nd from http://www.pcapr.net/view/nos/2014/8/0/10/x2ap.pcap.html)
    #
    pkts = map(unh, [\
'000600808a000004001500080011f1110001013000140051020000330011f11101011010029011f111004c2c05dc330000340011f1110101102000a011f111004c2c05dc444000350011f1110101103000a011f111005eec189c3300010011f1110a0ab010002705dc001800060011f1118000a8dd4018000002100040030001031001400a0001c006001008020100',
'0000007b000006000a00020001000540020000000b000800522018000000200017000700522018000102000e004100010000000000303132333435363738393031323334353637383930313233343536373839303120000000000004400e0000010a03e01401a8c000000002020000000f400c000052201800000021800003',
       ])
    return pkts

def _test_x2ap(pkts):
    T0 = time()
    i = 1
    #
    pdu = GLOBAL.TYPE['X2AP-PDU']
    for msg in pkts:
        pdu.decode(msg)
        assert( str(pdu) == msg )
        val = pdu()
        buf = pdu.encode()
        assert( str(pdu) == msg )
        assert( pdu() == val )
        i += 1
    #
    return time() - T0

def test_x2ap():
    pkts = _test_x2ap_prep()
    if pkts is not None:
        void = _test_x2ap(pkts)

def _test_rrc3g_prep():
    GLOBAL.clear()
    try:
        load_module('RRC3G')
    except:
        log('Module "RRC3G" unavailable')
        return None, None
    ASN1.ASN1Obj._RAISE_SILENTLY = False
    ASN1.ASN1Obj.CODEC = PER
    PER.VARIANT = 'U'
    unh = lambda x: x.decode('hex')
    #
    # logs taken with a Samsung Galaxy S2 and xgoldmon from
    # https://github.com/2b-as/xgoldmon
    #
    pkts = map(unh, [\
    # PagingType1 (PCCH)
    '4455c803999055c601b95855aa06b09e',
    '4255ba00047855840454b2',
    '4055c8039990',
    # ActiveSetUpdate (DL-DCCH)
    'd2f17f0cb000304a00880a014aa0',
    'c70b4b01f800384a0cf80b4348087980',
    # DownlinkDirectTransfer (DL-DCCH)
    'ca0d7d191940002061e0',
    'b8bd242d114e02e101300bc05f020e9fe02300be9c607b15e540258640400000',
    # PhysicalChannelReconfiguration (DL-DCCH)
    'adb98ce3d28000c01147c400466ff0707a2515459fcc008cdfe0e0f44a2a8b06bec002337f8383d128aa2a9433e02d0d3a300880a034a943cc0550d3c6',
    # RRCConnectionRelease (DL-DCCH)
    'c94874130bc800',
    # RadioBearerReconfiguration (DL-DCCH)
    '9576583b9b00000000881cfeb41648c1386c82cfe741648c1386c83cfe741648c1386c009700',
    # RadioBearerSetup (DL-DCCH)
    'd5956df0938204aa41d00804c42388303a80e2b8830428103388304a8124100b0120a4b4989352b95f83788120111d9b1c442880027020a20476688100ce111d5824401e0445ce0c73d7a487088000204e0414408ecd4810100ce111db8090803c088bc002607e013600',
    # SecurityModeCommand (DL-DCCH)
    'b81ea4c39c0e8001800128c0000101310008c00380990c02',
    'e7848cd48c0e0001800128c0000100f10000c002fdfa0b8b0040',
    # SignallingConnectionRelease (DL-DCCH)
    'bc9728229440',
    # InitialDirectTransfer (UL-DCCH)
    '15001700603138081ab8c5802fa5002f55fe00020a50',
    '15860a018040408017c083a8000880cf981159ffacb316288001f2b335e400c97ce799384018c02fa7d4144b09881faf08019010000600004ac0',
    '15001700602920a01ab8c5802fa5002f55fe0001caf0',
    # UplinkDirectTransfer (UL-DCCH)
    '97e91641aec002c1968401704800',
    # SecurityModeComplete (UL-DCCH)
    'a452ec578d31111111800002016200218000',
    # RadioBearerSetupComplete (UL-DCCH)
    'efd728f42bcc000024d0',
    # RadioBearerReconfigurationComplete (UL-DCCH)
    '847d9dc832c000',
    # ActiveSetUpdateComplete (UL-DCCH)
    'e431772f2800',
    # PhysicalChannelReconfigurationComplete (UL-DCCH)
    'f3e0b9537a4000',
    ])
    
    # The following RRC frames are not encoded in a PER compliant / canonical 
    # way
    pkts_non_canon = map(unh, [\
    # MeasurementControl (DL-DCCH)
    # here, the RNC encodes CellInfo components with their DEFAULT values,
    # even for ASN.1 basic objects,...
    'a3549e989a008310c935be7be4ea51736ee514def25117afa51626fe516d20',
    'cdcc61022a010310c8ef8ce91bca2c55c4a2f65cca2485d4a2375dca2bf5e4a28d5eca298df4a2e15fca2f9c',
    '208803b8fc128a5d43288294528b154728825492883f4b28b3f4d288234f28b395128b435328a5b5528bcd5728bd959289215b288dd5d2888d5f28afd6128b316328a1d6528a356728a636928b856b28be76d289a16f2888371289357328b3d7528831772893f7928a3d7b28b637d288c97f289714c4585858b82180bb2b7510a0160293ecadd4ff9c20',
    # RadioBearerReleaseFailure (UL-DCCH)
    # here, the RNC encodes:
    # laterNonCriticalExtensions, 
    # which is however empty (it contains only OPTIONAL components, and none 
    # are encoded...) and this is handled differently in Paging frames, where 
    # the laterNonCriticalExtensions are not encoded at all: damned RNC !!!
    '39a0',
    # RRCConnectionSetupComplete (UL-DCCH)
    # here, the RNC encodes:
    # dl-PhysChCapabilityFDD-v380ext, rrcConnectionSetupComplete-v3a0ext,
    # rrcConnectionSetupComplete-v3g0ext, 
    # which are however empty (they contain only OPTIONAL components, and none 
    # are encoded...)
    '4b88000220000c64350aa0d4a8550d412808900030002b01981ab8c58218050908a2050a104035084a39f742cf4d76e509473ee859e9aedea128e7dd0b3d35db97010144109c38f5d0d0b3d35db400640740616378c24fd2845e1220d000',
    ])
    #
    return pkts, pkts_non_canon

def _test_rrc3g(pkts, pkts_non_canon):
    #
    T0 = time()
    i, j = 1, 1
    #
    pcch = GLOBAL.TYPE['PCCH-Message']
    for msg in pkts[0:3]:
        pcch.decode(msg)
        assert( str(pcch) == msg )
        val = pcch()
        buf = pcch.encode()
        assert( str(pcch) == msg )
        assert( pcch() == val )
        i += 1
    #
    dldcch = GLOBAL.TYPE['DL-DCCH-Message']
    for msg in pkts[3:14]:
        dldcch.decode(msg)
        assert( str(dldcch) == msg )
        val = dldcch()
        buf = dldcch.encode()
        assert( str(dldcch) == msg )
        assert( dldcch() == val )
        i += 1
    for msg in pkts_non_canon[:3]:
        dldcch.decode(msg)
        assert( str(dldcch) == msg )
        val = dldcch()
        buf = dldcch.encode()
        assert( dldcch() == val )
        j += 1
    #
    uldcch = GLOBAL.TYPE['UL-DCCH-Message']
    for msg in pkts[14:]:
        uldcch.decode(msg)
        assert( str(uldcch) == msg )
        val = uldcch()
        buf = uldcch.encode()
        assert( str(uldcch) == msg )
        assert( uldcch() == val )
        i += 1
    for msg in pkts_non_canon[3:]:
        uldcch.decode(msg)
        assert( str(uldcch) == msg )
        val = uldcch()
        buf = uldcch.encode()
        assert( uldcch() == val )
        i += 1
    #
    return time() - T0

def test_rrc3g():
    pkts, pkts_non_canon = _test_rrc3g_prep()
    if pkts is not None:
        void = _test_rrc3g(pkts, pkts_non_canon)
    
def test_all(print_info=False):
    test_def(print_info)
    test_per_integer(print_info)
    test_per_choice(print_info)
    test_per_sequence(print_info)
    test_s1ap()
    test_x2ap()
    test_rrc3g()
    GLOBAL.clear()
    
if __name__ == '__main__':
    test_all()
