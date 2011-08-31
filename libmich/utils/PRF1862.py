# −*− coding: UTF−8 −*−
#!/usr/bin/env python

# implements the Pseudo-Random Function defined by NIST in PRF-186-2
# usable for EAP-SIM and EAP-AKA PRF: based on the NIST-186-2 

# derived from the pure python sha1 source code: sha1.py
# Copyrighted by Michael D. Leonhard, 2005
# http://tamale.net/

from struct import pack

class G_prf:
    def lrot( self, num, b ): return ((num<<b)&0xFFFFFFFF)|(num>>32 - b)
    def BE32( self, bytes ):
        assert( len(bytes) == 4 )
        return (ord(bytes[0]) << 24)|(ord(bytes[1]) << 16)|(ord(bytes[2]) << 8)|ord(bytes[3])
    def process( self, block ):
        assert( len(block) == 64 )
        # copy initial values
        a = self.A
        b = self.B
        c = self.C
        d = self.D
        e = self.E
        # expand message into W
        W = []
        for t in range(16): W.append( self.BE32( block[t*4:t*4+4] ) )
        for t in range(16,80): W.append( self.lrot( W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1) )
        # do rounds
        for t in range(80):
            if t < 20:
                K = 0x5a827999
                f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
            elif t < 40:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t < 60:
                K = 0x8f1bbcdc
                f = (b & c) | (b & d) | (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d
            TEMP = (self.lrot(a,5) + f + e + W[t] + K) & 0xFFFFFFFF
            e = d
            d = c
            c = self.lrot(b,30)
            b = a
            a = TEMP
        # add result
        self.A = (self.A + a) & 0xFFFFFFFF
        self.B = (self.B + b) & 0xFFFFFFFF
        self.C = (self.C + c) & 0xFFFFFFFF
        self.D = (self.D + d) & 0xFFFFFFFF
        self.E = (self.E + e) & 0xFFFFFFFF
    def xkey_add( self ):
        # set carry = 1 to manage the XKEY = (1 + XKEY + w_i)
        carry = 1
        pos = 20
        for i in [self.E, self.D, self.C, self.B, self.A]:
            res = ( self.BE32(self.xkey[pos-4:pos]) + i + carry)
            carry = res / 0x100000000
            self.xkey = self.xkey[:pos-4] + pack('>I', res & 0xFFFFFFFF) + self.xkey[pos:]
            pos -= 4
    def prf_186_2( self, rnd ):
        #prf 186 2 from NIST for EAP-SIM and EAP-AKA, section 7
        self.x = []
        for i in range(rnd):
            w=''
            for j in range(2):
                # no optional user input: xseed_j = 0, xval = xkey
                # process with SHA1 transform the xkey padded with 0 bits
                self.init()
                self.process( self.xkey + (64-len(self.xkey))*chr(0) )
                w += pack('>IIIII', self.A, self.B, self.C, self.D, self.E)
                self.xkey_add()
            self.x.append(w)
        return self.x
    def update( self, newBytes ):
        self.xkey=newBytes
    def init( self ):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        self.E = 0xc3d2e1f0
    def __init__( self ):
        self.init()

