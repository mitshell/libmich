# -*- coding: UTF-8 -*-
# Diffie-Hellman python script from the OpenID project:
# http://openidenabled.com/files/python-openid/docs/1.2.0/openid.dh-module.html
# test with:
#def test1():
#    dh1 = DiffieHellman.fromDefaults()
#    dh2 = DiffieHellman.fromDefaults()
#    secret1 = dh1.getSharedSecret(dh2.public)
#    secret2 = dh2.getSharedSecret(dh1.public)
#    assert secret1 == secret2
#    return secret1


import os
import random
import binascii

try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ImportError:
    import pickle
    try:
        # Check Python compatiblity by raising an exception on import
        # if the needed functionality is not present. Present in
        # Python >= 2.3
        pickle.encode_long
        pickle.decode_long
    except AttributeError:
        raise ImportError(
            'No functionality for serializing long integers found')

    # Present in Python >= 2.4
    try:
        reversed
    except NameError:
        def reversed(seq):
            return map(seq.__getitem__, xrange(len(seq) - 1, -1, -1))

    def longToBinary(l):
        if l == 0:
            return '\x00'

        return ''.join(reversed(pickle.encode_long(l)))

    def binaryToLong(s):
        return pickle.decode_long(''.join(reversed(s)))
else:
    # We have pycrypto

    def longToBinary(l):
        if l < 0:
            raise ValueError('This function only supports positive integers')

        bytes = long_to_bytes(l)
        if ord(bytes[0]) > 127:
            return '\x00' + bytes
        else:
            return bytes

    def binaryToLong(bytes):
        if not bytes:
            raise ValueError('Empty string passed to strToLong')

        if ord(bytes[0]) > 127:
            raise ValueError('This function only supports positive integers')

        return bytes_to_long(bytes)

# A cryptographically safe source of random bytes
try:
    getBytes = os.urandom
except AttributeError:
    try:
        from Crypto.Util.randpool import RandomPool
    except ImportError:
        # Fall back on /dev/urandom, if present. It would be nice to
        # have Windows equivalent here, but for now, require pycrypto
        # on Windows.
        try:
            _urandom = file('/dev/urandom', 'rb')
        except IOError:
            raise ImportError('No adequate source of randomness found!')
        else:
            def getBytes(n):
                bytes = []
                while n:
                    chunk = _urandom.read(n)
                    n -= len(chunk)
                    bytes.append(chunk)
                    assert n >= 0
                return ''.join(bytes)
    else:
        _pool = RandomPool()
        def getBytes(n, pool=_pool):
            if pool.entropy < n:
                pool.randomize()
            return pool.get_bytes(n)

# A randrange function that works for longs
try:
    randrange = random.SystemRandom().randrange
except AttributeError:
    # In Python 2.2's random.Random, randrange does not support
    # numbers larger than sys.maxint for randrange. For simplicity,
    # use this implementation for any Python that does not have
    # random.SystemRandom
    from math import log, ceil

    _duplicate_cache = {}
    def randrange(start, stop=None, step=1):
        if stop is None:
            stop = start
            start = 0

        r = (stop - start) // step
        try:
            (duplicate, nbytes) = _duplicate_cache[r]
        except KeyError:
            rbytes = longToBinary(r)
            if rbytes[0] == '\x00':
                nbytes = len(rbytes) - 1
            else:
                nbytes = len(rbytes)

            mxrand = (256 ** nbytes)

            # If we get a number less than this, then it is in the
            # duplicated range.
            duplicate = mxrand % r

            if len(_duplicate_cache) > 10:
                _duplicate_cache.clear()

            _duplicate_cache[r] = (duplicate, nbytes)

        while 1:
            bytes = '\x00' + getBytes(nbytes)
            n = binaryToLong(bytes)
            # Keep looping if this value is in the low duplicated range
            if n >= duplicate:
                break

        return start + (n % r) * step

def toBase64(s):
    """Represent string s as base64, omitting newlines"""
    return binascii.b2a_base64(s)[:-1]
	
def fromBase64(s):
    try:
        return binascii.a2b_base64(s)
    except binascii.Error, why:
        # Convert to a common exception type
        raise ValueError(why[0])
	
def longToBase64(l):
    return toBase64(longToBinary(l))

def base64ToLong(s):
    return binaryToLong(fromBase64(s))

def randomString(length, chrs=None):
    """Produce a string of length random bytes, chosen from chrs."""
    if chrs is None:
        return getBytes(length)
    else:
        n = len(chrs)
        return ''.join([chrs[randrange(n)] for _ in xrange(length)])
	
def strxor(x, y):
    if len(x) != len(y):
        raise ValueError('Inputs to strxor must have the same length')

    xor = lambda (a, b): chr(ord(a) ^ ord(b))
    return "".join(map(xor, zip(x, y)))

class DiffieHellman(object):
    DEFAULT_MOD = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443L
    DEFAULT_GEN = 2

    def fromDefaults(cls):
        return cls(cls.DEFAULT_MOD, cls.DEFAULT_GEN)

    fromDefaults = classmethod(fromDefaults)

    def __init__(self, modulus, generator):
        self.modulus = long(modulus)
        self.generator = long(generator)

        self._setPrivate(randrange(1, modulus - 1))

    def _setPrivate(self, private):
        """This is here to make testing easier"""
        self.private = private
        self.public = pow(self.generator, self.private, self.modulus)

    def usingDefaultValues(self):
        return (self.modulus == self.DEFAULT_MOD and
                self.generator == self.DEFAULT_GEN)

    def getSharedSecret(self, composite):
        return pow(composite, self.private, self.modulus)

    def xorSecret(self, composite, secret, hash_func):
        dh_shared = self.getSharedSecret(composite)
        hashed_dh_shared = hash_func(longToBinary(dh_shared))
        return strxor(secret, hashed_dh_shared)
