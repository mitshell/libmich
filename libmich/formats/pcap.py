#!/usr/bin/env python

# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show, debug

###
# pcap headers format
# from http://wiki.wireshark.org/Development/LibpcapFileFormat
###
#
# Warning, these integer values are all little endian encoded
#

class Global(Layer):
    constructorList = [
        Int('magic', Pt=0, Type='uint32', Repr='hex'),
        Int('vers_maj', Pt=0, Type='uint16', Repr='hex'),
        Int('vers_min', Pt=0, Type='uint16', Repr='hex'),
        Int('zone_time', Pt=0, Type='int32', Repr='hum'),
        Int('ts_accuracy', Pt=0, Type='uint32', Repr='hum'),
        Int('snaplen', Pt=0, Type='uint32', Repr='hum'),
        Int('link_type', Pt=0, Type='uint32', Repr='hex')]

class Record(Layer):
    constructorList = [
        Int('ts_sec', Pt=0, Type='uint32', Repr='hum'),
        Int('ts_usec', Pt=0, Type='uint32', Repr='hum'),
        Int('incl_len', Pt=0, Type='uint32', Repr='hum'),
        Int('orig_len', Pt=0, Type='uint32', Repr='hum')]


