#!/usr/bin/env python2

from socket import inet_pton, inet_ntop, \
    AF_INET, AF_INET6
from binascii import hexlify, unhexlify

# conv_type can be
# 'ipv4'
# 'ipv6'
# 'ethermac'
# 

def aton(data='', conv_type='ipv4') :
    if conv_type == 'ipv4' :
        try : return inet_pton(AF_INET, data)
        except : pass
    elif conv_type == 'ipv6' :
        try : return inet_pton(AF_INET6, data)
        except : pass
    elif conv_type == 'ethermac' and len(data) == 17 :
        return unhexlify(data.replace(':', ''))[:6]
    return ''

def ntoa(data='', conv_type='ipv4') :
    if conv_type == 'ipv4' :
        try : return inet_ntop(AF_INET, data)
        except : pass
    elif conv_type == 'ipv6' :
        try : return inet_ntop(AF_INET6, data)
        except : pass
    elif conv_type == 'ethermac' and len(data) == 6 :
        s = hexlify(data)
        return ''.join([s[0:2], ':', b[2:4], ':', b[4:6], \
                  ':', b[6:8], ':', b[8:10], ':', b[10:12]])
    return ''

