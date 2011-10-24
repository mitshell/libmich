# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.1 
# *
# * Copyright © 2011. Benoit Michau. France Telecom.
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
# * File Name : formats/MPEG2.py
# * Created : 2011-10-24 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

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


