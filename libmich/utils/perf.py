# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau.
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
# * File Name : utils/perf.py
# * Created : 2012-04-09
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import time
from libmich.core.element import Element, Str, Bit, Int, Layer, \
    testTLV
from libmich.core.element import test as test_tlv
from libmich.formats.BMP import BMP
from libmich.formats.BGP4 import BGP4, testbuf
from libmich.formats.L3Mobile import test_regr
from libmich.asn1.test import test_all as test_asn1
from libmich.asn1.test import _test_rrc3g_prep, _test_rrc3g, \
    _test_s1ap_prep, _test_s1ap

import libmich as _lm
bmp_fd = open(_lm.__path__[0] + '/utils/test.bmp', 'rb')
bmp_file = bmp_fd.read()
del _lm, bmp_fd

Element.safe = False
Element.dbg = 0
Layer.safe = False
Layer.dbg = 0

RND_T1 = 300000
RND_T2 = 20000
RND_T3 = 1000
RND_T4 = 1000
RND_T5 = 200
RND_T6 = 3
RND_T7 = 12
RND_T8 = 5
RND_T9 = 20

def texec(procedure):
    t0=time.time()
    procedure()
    return time.time()-t0

def t1():
    Int._endian = 'big'
    print('test 1: assigning Str() %i times' % RND_T1)
    for i in range(RND_T1):
        a=Str('test', Pt='azertyuiopqsdfghjjklmwxcvbn', Repr='bin')
        a < a()
        b = a
        a < None
        a, b
        del a, b

def t2():
    Int._endian = 'big'
    print('test 2: assigning testTLV() %i times' % RND_T2)
    for i in range(RND_T2):
        t = testTLV(V=(i%901)*'t')
        t.F1(), t.F2(), t.V(), t.L()
        t.F1, t.F2
        del t

def t3():
    Int._endian = 'big'
    print('test 3: building / parsing aligned and unaligned layers %i times'\
          % RND_T3)
    for i in range(RND_T3):
        test_tlv()

def t4(bmp=bmp_file):
    Int._endian = 'little'
    print('test 4: parsing BMP file of %.3f kB %i times'\
          % (len(bmp)/1024.0, RND_T4))
    for i in range(RND_T4):
        b=BMP()
        b.parse(bmp)
        del b

def t5(bgp=testbuf):
    Int._endian = 'big'
    print('test 5: parsing BGP4 packet of %i Bytes %i times'\
          % (len(bgp), RND_T5))
    for i in range(RND_T5):
        b=BGP4()
        b.parse(bgp)
        del b

def t6():
    Int._endian = 'big'
    print('test 6: building / parsing all L3 mobile packets defined in '\
          'formats/L3Mobile.py, %i times' % RND_T6)
    for i in range(RND_T6):
        void = test_regr(False)

def t7():
    Int._endian = 'big'
    print('test 7: compiling / assigning / encoding / decoding ASN.1 PER '\
          'structures %i times' % RND_T7)
    for i in range(RND_T7):
        test_asn1()

def t8():
    Int._endian = 'big'
    print('test 8: loading rrc3g module and encoding / decoding UMTS RRC ASN.1 '\
          'PER unaligned structures %i times' % RND_T8)
    pkts, pkts_nc = _test_rrc3g_prep()
    if pkts is None:
        print('unable to load rrc3g ASN.1 module')
    for i in range(RND_T8):
        _test_rrc3g(pkts, pkts_nc)

def t9():
    Int._endian = 'big'
    print('test 9: loading s1ap module and encoding / decoding LTE S1AP ASN.1 '\
          'PER aligned structures %i times' % RND_T9)
    pkts = _test_s1ap_prep()
    if pkts is None:
        print('unable to load s1ap ASN.1 module')
    for i in range(RND_T9):
        _test_s1ap(pkts)

TESTS = [t1, t2, t3, t4, t5, t6, t7, t8, t9]
#TESTS = [t3]

def main(tests=TESTS):
    T0 = time.time()
    for T in tests:
        print('duration: %.4f sec.' % texec(T))
    print('total duration: %.4f sec.' % (time.time()-T0))

if __name__ == '__main__':
    main()

