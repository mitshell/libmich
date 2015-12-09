# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2011. Benoit Michau. France Telecom. ANSSI.
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
# * File Name : formats/pcap.py
# * Created : 2011-10-24 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show

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
        Int('link_type', Pt=0, Type='uint32', Repr='hex')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        for i in self:
            i._endian = 'l'
        
class Record(Layer):
    constructorList = [
        Int('ts_sec', Pt=0, Type='uint32', Repr='hum'),
        Int('ts_usec', Pt=0, Type='uint32', Repr='hum'),
        Int('incl_len', Pt=0, Type='uint32', Repr='hum'),
        Int('orig_len', Pt=0, Type='uint32', Repr='hum')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        for i in self:
            i._endian = 'l'


###
# gsmtap header format
# http://bb.osmocom.org/trac/wiki/GSMTAP
# or in libosmocore: include/osmocom/core/gsmtap.h
###
GSMTAPType_dict = {
    1 : 'GSM Um',
    2 : 'GSM Abis',
    3 : 'GSM Um burst',
    4 : 'SIM APDU',
    5 : 'TETRA I1',
    6 : 'TETRA I1 burst',
    7 : 'WiMAX burst',
    8 : 'GPRS LLC',
    9 : 'GPRS SNDCP',
    10 : 'GMR-1 L2 packets',
    }

class gsmtap(Layer):
    constructorList = [
        Int('version', Pt=2, Type='uint8'),
        Int('hdr_len', Pt=4, Type='uint8'),
        Int('type', Pt=1, Type='uint8', Dict=GSMTAPType_dict),
        Int('timeslot', Pt=0, Type='uint8'),
        Int('arfcn', Pt=0, Type='uint16'),
        Int('signal_dbm', Pt=0, Type='int8'),
        Int('snr_db', Pt=0, Type='int8'),
        Int('frame_number', Pt=0, Type='uint32'),
        Int('sub_type', Pt=0, Type='uint8'),
        Int('antenna_nr', Pt=0, Type='uint8'),
        Int('sub_slot', Pt=0, Type='uint8'),
        Int('res', Pt=0, Type='uint8')
        ]
