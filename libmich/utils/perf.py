#!/usr/bin/env python2

import time
from libmich.core.element import Element, Str, Bit, Int, Layer, \
    testTLV, show
from libmich.formats.BMP import BMP
from libmich.formats.BGP4 import BGP4, testbuf

Element.safe = False
Element.dbg = 0
Layer.safe = False
Layer.dbg = 0

RND_T1 = 1000000
RND_T2 = 80000
RND_T3 = 13
RND_T4 = 2000

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
    
def t3(path_to_bmp='./red2.bmp'):
    Int._endian = 'little'
    print('test 3: parsing BMP() %i times' % RND_T3)
    bin=open(path_to_bmp, 'rb', -1).read()
    print('test 3: BMP file is %i kB' % (len(bin)/1024))
    for i in range(RND_T3):
        b=BMP()
        b.parse(bin)
        del b

def t4():
    Int._endian = 'big'
    print('test 4: parsing BGP4 paket %i times' % RND_T4)
    bin = testbuf
    print('test 4: BGP4 packet is %i Bytes' % len(bin))
    for i in range(RND_T4):
        b=BGP4()
        b.parse(bin)
        del b

TESTS = [t1, t2, t3, t4]
#TESTS = [t1, t2, t4]

def main():
    for T in TESTS:
        print('duration: %i sec.' % texec(T))

if __name__ == '__main__':
    main()

