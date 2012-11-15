# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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
# * File Name : formats/SCTP.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show
from libmich.core.IANA_dict import IANA_dict
from libmich.utils.CRC32C import crc32c
from struct import unpack
import hmac, hashlib


chunk_dict = IANA_dict({
    0 : ('Payload Data', 'DATA'),
    1 : ('Initiation', 'INIT'),
    2 : ('Initiation Acknowledgement', 'INIT_ACK'),
    3 : ('Selective Acknowledgement', 'SACK'),
    4 : ('Heartbeat Request', 'HEARTBEAT'),
    5 : ('Heartbeat Acknowledgement', 'HEARTBEAT_ACK'),
    6 : ('Abort', 'ABORT'),
    7 : ('Shutdown', 'SHUTDOWN'),
    8 : ('Shutdown Acknowledgement', 'SHUTDOWN_ACK'),
    9 : ('Operation Error', 'ERROR'),
    10 : ('State Cookie', 'COOKIE_ECHO'),
    11 : ('Cookie Acknowledgement', 'COOKIE_ACK'),
    12 : ('Reserved for Explicit Congestion Notification Echo', 'ECNE'),
    13 : ('Reserved for Congestion Window Reduced', 'CWR'),
    14 : ('Shutdown Complete', 'SHUTDOWN_COMPLETE'),
    15 : ('Authentication Chunk', 'AUTH'),
    16 : 'available',
    63 : 'reserved',
    64 : 'available',
    127 : 'reserved',
    128 : ('Address Configuration Acknowledgment', 'ASCONF_ACK'),
    129 : 'available',
    132 : ('Padding Chunk', 'PAD'),
    133 : 'available',
    191 : 'reserved',
    192 : ('Forward TSN', 'FWD_TSN'),
    193 : ('Address Configuration Change Chunk', 'ASCONF'),
    194 : 'available',
    255 : 'reserved'})
    
param_dict = IANA_dict({
    0 : 'undefined',
    1 : ('Heartbeat Info', 'HB_INFO'),
    2 : 'undefined',
    5 : ('IPv4 Address', 'IPv4'),
    6 : ('IPv6 Address', 'IPv6'),
    7 : ('State Cookie', 'ST_COOK'),
    8 : 'Unrecognized Parameters',
    9 : ('Cookie Preservative', 'COOK_PRES'),
    10 : 'undefined',
    11 : ('Host Name Address', 'HOST'),
    12 : ('Supported Address Types', 'SUP_ADD'),
    13 : 'undefined',
    0x8000 : ('Reserved for ECN Capable', 'ECN'),
    0x8001 : 'undefined',
    0x8002 : ('Random', 'RAND'),
    0x8003 : ('Chunk List', 'LIST'),
    0x8004 : ('Requested HMAC Algorithm Parameter', 'HMAC_ALG'),
    0x8005 : ('Padding', 'PAD'),
    0x8006 : 'undefined',
    0x8008 : ('Supported Extensions', 'SUP_EXT'),
    0x8009 : 'undefined',
    0xC000 : ('Forward TSN supported', 'FWD_TSN'),
    0xC001 : ('Add IP Address', 'ADD_IP'),
    0xC002 : ('Delete IP Address', 'DEL_IP'),
    0xC003 : 'undefined',
    0xC004 : ('Set Primary Address', 'SET_PRIM'),
    0xC005 : 'undefined',
    0xC006 : ('Adaptation Layer Indication', 'AL_IND'),
    0xC007 : 'undefined',
    0xFFFF : 'undefined'})
    
error_dict = IANA_dict({
    1 : 'Invalid Stream Identifier',
    2 : 'Missing Mandatory Parameter',
    3 : 'Stale Cookie Error',
    4 : 'Out of Resource',
    5 : 'Unresolvable Address',
    6 : 'Unrecognized Chunk Type',
    7 : 'Invalid Mandatory Parameter',
    8 : 'Unrecognized Parameters',
    9 : 'No User Data',
    10 : 'Cookie Received While Shutting Down',
    11 : 'Restart of an Association with New Addresses',
    12 : 'User Initiated Abort',
    13 : 'Protocol Violation',
    14 : 'undefined',
    160 : 'Request to Delete Last Remaining IP Address',
    161 : 'Operation Refused Due to Resource Shortage',
    162 : 'Request to Delete Source IP Address',
    163 : 'Association Aborted due to illegal ASCONF-ACK',
    164 : 'Request refused - no authorization',
    165 : 'undefined',
    261 : 'Unsupported HMAC Identifier',
    262 : 'undefined'})
    
protocol_dict = IANA_dict({
    0 : 'Reserved',
    1 : 'IUA',
    2 : 'M2UA',
    3 : 'M3UA',
    4 : 'SUA',
    5 : 'M2PA',
    6 : 'V5UA',
    7 : 'H.248',
    8 : 'BICC/Q.2150.3',
    9 : 'TALI',
    10 : 'DUA',
    11 : 'ASAP',
    12 : 'ENRP',
    13 : 'H.323',
    14 : 'Q.IPC/Q.2150.3',
    15 : 'SIMCO',
    16 : 'DDP Segment Chunk',
    17 : 'DDP Stream Session Control',
    18 : 'S1AP',
    19 : 'RUA',
    20 : 'HNBAP',
    21 : 'ForCES-HP',
    22 : 'ForCES-MP',
    23 : 'ForCES-LP',
    24 : 'SBc-AP',
    25 : 'NBAP',
    26 : 'Unassigned',
    27 : 'X2AP',
    28 : 'IRCP',
    29 : 'LCS-AP',
    30 : 'MPICH2',
    31 : 'SABP',
    32 : 'FGP',
    33 : 'PingPongP',
    34 : 'CALCAPP',
    35 : 'SSP',
    36 : 'NPMP-CONTROL',
    37 : 'NPMP-DATA',
    38 : 'ECHO',
    39 : 'DISCARD',
    40 : 'DAYTIME',
    41 : 'CHARGEN',
    42 : 'RNA',
    43 : 'M2AP',
    44 : 'M3AP',
    45 : 'Unassigned',
    0xFFFFFFFF : 'Unassigned'})
    
hmac_dict = IANA_dict({
    0 : 'Reserved',
    1 : 'SHA-1',
    2 : 'Reserved',
    3 : 'SHA-256',
    4: "unassigned",
    })
    

class SCTP(Block):
    
    def __init__(self, src=0, dst=0, verif=4*'\x00'):
        Block.__init__(self, Name="SCTP")
        self.append( SCTP_hdr(src, dst, verif) )
    
    def pull_GapAckBlock(self, newLayer):
        if type(newLayer) is GapAckBlock:
            index = newLayer.get_index()
            while type(self[index-1]) is not SACK: 
                index -= 1
                if index == 0: return
            self[index-1].numgap.Pt +=1
    
    def pull_DuplicateTSN(self, newLayer):
        if type(newLayer) is DuplicateTSN:
            index = newLayer.get_index()
            while type(self[index-1]) is not SACK: 
                index -= 1
                if index == 0: return
            self[index-1].numdup.Pt +=1
    
    def append(self, newLayer):
        if issubclass( type(newLayer), Layer ):
            self.layerList.append(newLayer)
            newLayer.inBlock = True
            newLayer.Block = self
            self.pull_GapAckBlock(newLayer)
            self.pull_DuplicateTSN(newLayer)
    
    def __lt__(self, newLayer):
        # to use when appending a payload with hierarchy 1
        self.append(newLayer)
        self[-1].hierarchy = self[0].hierarchy + 1
        
    def parse(self, s):
        # 1st: map SCTP header
        self[0].map(s)
        s = s[ len(self[0]) : ]
        # Then iteratively, map each SCTP chunk
        while len(s) > 0:
            nc = unpack('!B', s[0])[0]
            
            # If chunk type is recognized:
            if nc in chunkCall.keys():
                self < chunkCall[nc]()
                self[-1].map( s )
                cklen = int( self[-1].len )
                ckhier = self[-1].hierarchy
                
                # for specific chunk, parse specific layers or error codes:
                if nc in (6, 9) : 
                    # for ABORT and ERROR chunks
                    # must parse error codes
                    error_s = s[ 4 : cklen ]
                    while len(error_s) > 0:
                        self.append( SCTP_error() )
                        self[-1].hierarchy = ckhier + 1
                        self[-1].map( error_s )
                        error_s = error_s[ int(self[-1].len) : ]
                        
                elif nc == 3:
                    # for SACK chunk
                    # must parse GapAckBlock and DuplicateTSN Layers
                    nums = s[ 16 : cklen ]
                    numgap = int(self[-1].numgap)
                    while numgap > 0:
                        self.append( GapAckBlock() )
                        self[-1].hierarchy = ckhier + 1
                        self[-1].map( nums )
                        nums = nums[ 4 : ]
                        numgap -= 1
                    while len(nums) > 0:
                        self.append( DuplicateTSN() )
                        self[-1].hierarchy = ckhier + 1
                        self[-1].map( nums )
                        nums = nums[ 4 : ]
                    
                elif nc == 0xC0:
                    # for Forward TSN chunk
                    ssq_s = s[ 8 : cklen ]
                    while len(ssq_s) > 0:
                        self.append( StreamSeq() )
                        self[-1].hierarchy = ckhier + 1
                        self[-1].map( ssq_s )
                        ssq_s = error_s[ 4 : ]
                    
                else:
                    # for other types of chunk
                    param_s = s[ len(self[-1]) : cklen ]
                    while len(param_s) > 0:
                        # if the chunk header has some remaining unmapped string: 
                        # parse with SCTP parameter 
                        self.append( SCTP_param() )
                        self[-1].hierarchy = ckhier + 1
                        self[-1].map( param_s )
                        param_s = param_s[ int(self[-1].len) : ]
                        
                # rest of the string to map for following chunks
                # TODO: need to take padding into account
                s = s[ cklen : ]
            
            # if chunk type is not recognized:
            else:
                self < SCTP_chunk()
                self[-1].map(s)
                self << RawLayer()
                self[-1].map( s[ 4 : len(self[-2]) ] )
                s = s[ len(self[-2]) : ]
                
        # after parsing the whole string,
        # in case of AUTH chunk, need to increment the hierarchy of all following layers
        if hasattr(self, 'auth'):
            for layer in range( self.auth.get_index(), self.num() ):
                layer.inc_hierarchy()
    

class SCTP_hdr(Layer):
    constructorList = [
        Int(CallName='src', ReprName='Source Port', Type='uint16'),
        Int(CallName='dst', ReprName='Destination Port', Type='uint16'),
        Str(CallName='verif', ReprName='Verification Tag', Len=4, Repr='hex'),
        Int(CallName='crc', ReprName='CRC32-C Checksum', Type='uint32', Repr='hex'),
        ]
    
    # then define the instantiation process when initializing
    def __init__(self, src=0, dst=0, verif=4*'\0'):
        Layer.__init__(self, CallName='hdr', ReprName='SCTP header')
        self.src.Pt = src
        self.dst.Pt = dst
        self.verif.Pt = verif
        self.crc.Pt = self.get_payload
        self.crc.PtFunc = lambda pay: crc32c( str(self.src)\
                                            + str(self.dst)\
                                            + str(self.verif)\
                                            + 4*'\0'\
                                            + str(pay()) )

# defines standard SCTP chunk header, with padding routine
class SCTP_chunk(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        ]
    padding_byte = '\0'
    
    def __init__(self, type=chunk_dict['DATA']):
        Layer.__init__(self, CallName='chk', ReprName='SCTP chunk')
        self.type.Pt = type
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len(pay())+4
    
    def _pad(self, s=''):
        extra = len(s)%4
        if extra == 0: return ''
        else: return (4-extra)*self.padding_byte
    
# defines any raw payload of an SCTP chunk header
class SCTP_raw(SCTP_chunk):
    constructorList = [
        Str(CallName='val', ReprName='Parameter Value'),
        Str(CallName='pad', ReprName='Padding', Repr='hex'),
        ]
    padding_byte = '\0'
        
    def __init__(self, val=''):
        Layer.__init__(self, CallName='raw', ReprName='SCTP raw data')
        self.val.Pt = val
        self.pad.Pt = self.val
        self.pad.PtFunc = lambda val: self._pad(s=val)
        self.pad.Len = self.val
        self.pad.LenFunc = lambda val: len(val)%4
    
# defines a standard SCTP parameter
class SCTP_param(SCTP_chunk):
    constructorList = [
        Int(CallName='type', ReprName='Parameter Type', Type='uint16', \
            Dict=param_dict),
        Int(CallName='len', ReprName='Parameter Length', Type='uint16'),
        Str(CallName='val', ReprName='Parameter Value'),
        Str(CallName='pad', ReprName='Padding', Repr='hex'),
        ]
    padding_byte = '\0'
    
    def __init__(self, type=param_dict['HB_INFO'], val=None):
        Layer.__init__(self, CallName='param', ReprName='SCTP parameter')
        self.type.Pt = type
        self.len.Pt = self.val
        self.len.PtFunc = lambda val: len(val)+4
        self.val.Pt = val
        self.val.Len = self.len
        self.val.LenFunc = lambda len: int(len)-4
        self.pad.Pt = self.val
        self.pad.PtFunc = lambda val: self._pad(s=val)
        self.pad.Len = self.val
        self.pad.LenFunc = lambda val: len(val)%4
    
#defines the SCTP error cause parameter
class SCTP_error(SCTP_chunk):
    constructorList = [
        Int(CallName='cause', ReprName='Error Cause Code', Type='uint16', \
            Dict=error_dict),
        Int(CallName='len', ReprName='Error Length', Type='uint16'),
        Str(CallName='val', ReprName='Error Value'),
        Str(CallName='pad', ReprName='Padding', Repr='hex'),
        ]
    padding_byte = '\0'
    
    def __init__(self, cause=error_dict['Protocol Violation'], val=None):
        Layer.__init__(self, CallName='error', ReprName='SCTP error')
        self.cause.Pt = cause
        self.len.Pt = self.val
        self.len.PtFunc = lambda val: len(val)+4
        self.val.Pt = val
        self.val.Len = self.len
        self.val.LenFunc = lambda len: int(len)-4
        self.pad.Pt = self.val
        self.pad.PtFunc = lambda val: self._pad(s=val)
        self.pad.Len = self.val
        self.pad.LenFunc = lambda val: len(val)%4

# Now defines all SCTP chunks:
#
class DATA(SCTP_chunk):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='tsn', ReprName='Transmission Sequence Number', Type='uint32'),
        Int(CallName='sid', ReprName='Stream Identifier', Type='uint16'),
        Int(CallName='sqn', ReprName='Stream Sequence Number', Type='uint16'),
        Int(CallName='ppid', ReprName='Payload Protocol Identifier', Type='uint32', \
            Dict=protocol_dict),
        Str(CallName='data', ReprName='User Data'),
        Str(CallName='pad', ReprName='Padding', Repr='hex'),
        ]
    padding_byte = '\x00'
    
    def __init__(self, tsn=0, sid=0, sqn=0, ppid=0, data=''):
        Layer.__init__(self, CallName='data', ReprName='SCTP DATA chunk')
        self.len.Pt = self.data
        self.len.PtFunc = lambda data: len( data ) + 16
        self.tsn.Pt = tsn
        self.sid.Pt = sid
        self.sqn.Pt = sqn
        self.ppid.Pt = ppid
        self.data.Pt = data
        self.pad.Pt = self.data
        self.pad.PtFunc = lambda val: self._pad(s=val)
        self.pad.Len = self.data
        self.pad.LenFunc = lambda val: len(val)%4

class INIT(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=1, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='init', ReprName='Initiate Tag', Type='uint32'),
        Int(CallName='a_rwnd', ReprName='Advertised Receiver Wundow Credit', \
            Type='uint32'),
        Int(CallName='outs', ReprName='Number of Outbound Streams', Type='uint16'),
        Int(CallName='ins', ReprName='Number of Inbound Streams', Type='uint16'),
        Int(CallName='itsn', ReprName='Initial Transmission Sequence Number', \
            Type='uint32'),
        ]
    
    def __init__(self, init=0x6D696368, a_rwnd=0x00100000, \
                 outs=10, ins=10, itsn=0x6D696368):
        Layer.__init__(self, CallName='init', ReprName='SCTP INIT chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 16
        self.init.Pt = init
        self.a_rwnd.Pt = a_rwnd
        self.outs.Pt = outs
        self.ins.Pt = ins
        self.itsn.Pt = itsn

class INIT_ACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=2, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='init', ReprName='Initiate Tag', Type='uint32'),
        Int(CallName='a_rwnd', ReprName='Advertised Receiver Wundow Credit', \
            Type='uint32'),
        Int(CallName='outs', ReprName='Number of Outbound Streams', Type='uint16'),
        Int(CallName='ins', ReprName='Number of Inbound Streams', Type='uint16'),
        Int(CallName='itsn', ReprName='Initial Transmission Sequence Number', \
            Type='uint32'),
        ]
    
    def __init__(self, init=0x6D696368, a_rwnd=0x00100000, \
                 outs=10, ins=10, itsn=0x6D696368):
        Layer.__init__(self, CallName='init-ack', ReprName='SCTP INIT ACK chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 16
        self.init.Pt = init
        self.a_rwnd.Pt = a_rwnd
        self.outs.Pt = outs
        self.ins.Pt = ins
        self.itsn.Pt = itsn
    # must have the STATE COOKIE as SCTP parameter in payload, 
    # may have other parameters as payload

class SACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=3, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='ctsn', ReprName='Cumulative TSN Ack', Type='uint32'),
        Int(CallName='a_rwnd', ReprName='Advertised Receiver Wundow Credit', \
            Type='uint32'),
        Int(CallName='numgap', ReprName='Number of Gap Ack Blocks', Type='uint16'),
        Int(CallName='numdup', ReprName='Number of Duplicate TSNs', Type='uint16'),
        ]
    
    def __init__(self, ctsn=0, a_rwnd=0x00100000):
        Layer.__init__(self, CallName='sack', ReprName='SCTP SACK chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 4
        self.ctsn.Pt = ctsn
        self.a_rwnd.Pt = a_rwnd
        self.numgap.Pt = 0
        self.numdup.Pt = 0
    # may have GapAckBlock and DuplicateTSN as payload
 
class GapAckBlock(Layer):
    constructorList = [
        Int(CallName='start', ReprName='Gap Ack Block Start', Type='uint16'),
        Int(CallName='end', ReprName='Gap Ack Block End', Type='uint16'),
        ]
    
    def __init__(self, start=0, end=0):
        Layer.__init__(self, CallName='gap', ReprName='Gap Ack Block')
        self.start.Pt = start
        self.end.Pt = end
        
class DuplicateTSN(Layer):
    constructorList = [
        Int(CallName='duptsn', ReprName='Duplicate TSN', Type='uint32'),
        ]
    
    def __init__(self, duptsn=0):
        Layer.__init__(self, CallName='dup', ReprName='Duplicate TSN')
        self.duptsn.Pt = duptsn

class HEARTBEAT(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=4, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='hb', ReprName='SCTP HEARTBEAT chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 4
    # can put some HB_INFO as payload

class HEARTBEAT_ACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=5, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='hb_ack', ReprName='SCTP HEARTBEAT_ACK chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 4
    # must returns the HB_INFO received as payload

class ABORT(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=6, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=7),
        Bit(CallName='T', ReprName='Transmit', BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        ]
    
    def __init__(self, T=0):
        Layer.__init__(self, CallName='abort', ReprName='SCTP ABORT chunk')
        self.T.Pt = T
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 4
    # put some ERROR CAUSE as payload
            
class SHUTDOWN(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=7, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=8, Type='uint16'),
        Int(CallName='ctsn', ReprName='Cumulative TSN Ack', Type='uint32'),
        ]
    
    def __init__(self, ctsn=0):
        Layer.__init__(self, CallName='shut', ReprName='SCTP SHUTDOWN chunk')
        self.ctsn.Pt = ctsn

class SHUTDOWN_ACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=8, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=4, Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='shut_ack', ReprName='SCTP SHUTDOWN_ACK chunk')

class ERROR(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=9, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='err', ReprName='SCTP ERROR chunk')
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 4
    # need some ERROR CAUSE as payload

class COOKIE_ECHO(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=10, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Str(CallName='cook', ReprName='Cookie'),
        ]
    
    def __init__(self, cookie=''):
        Layer.__init__(self, CallName='cook_echo', ReprName='SCTP COOKIE_ECHO chunk')
        self.cook.Pt = cookie
        self.len.Pt = self.cook
        self.len.PtFunc = lambda cook: len( cook ) + 4

class COOKIE_ACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=11, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=4, Type='uint16'),
        ]
    
    def __init__(self):
        Layer.__init__(self, CallName='cook_ack', ReprName='SCTP COOKIE_ACK chunk')

class ECNE(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=12, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=8, Type='uint16'),
        Int(CallName='ltsn', ReprName='Lowest TSN Number', Type='uint32'),
        ]
    
    def __init__(self, ltsn=0):
        Layer.__init__(self, CallName='ecne', ReprName='SCTP ECNE chunk')
        self.ltsn.Pt = ltsn

class CWR(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=13, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=8, Type='uint16'),
        Int(CallName='ltsn', ReprName='Lowest TSN Number', Type='uint32'),
        ]
    
    def __init__(self, ltsn=0):
        Layer.__init__(self, CallName='cwr', ReprName='SCTP CWR chunk')
        self.ltsn.Pt = ltsn

class SHUTDOWN_COMPLETE(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=14, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=7),
        Bit(CallName='T', ReprName='Transmit', BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Pt=4, Type='uint16'),
        ]
    
    def __init__(self, T=0):
        Layer.__init__(self, CallName='shut_comp', \
                       ReprName='SCTP SHUTDOWN_COMPLETE chunk')
        self.T.Pt = T

class ASCONF(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0xC1, \
            Type='uint8', Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='sqn', ReprName='Sequence Number', Type='uint32'),
        ]
    
    def __init__(self, sqn=0):
        Layer.__init__(self, CallName='asconf', ReprName='SCTP ASCONF chunk')
        self.sqn.Pt = sqn
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 8
    # need some TLV SCTP param, IP address param is mandatory

class ASCONF_ACK(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0x80, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='sqn', ReprName='Sequence Number', Type='uint32'),
        ]
    
    def __init__(self, sqn=0):
        Layer.__init__(self, CallName='asconf-ack', ReprName='SCTP ASCONF_ACK chunk')
        self.sqn.Pt = sqn
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 8
    # need some TLV SCTP param

class PAD(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0x84, \
            Type='uint8', Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Str(CallName='pad', ReprName='Padding Data', Repr='hex'),
        ]
    padding_bytes = '\0'
    
    def __init__(self, padlen=0):
        Layer.__init__(self, CallName='pad', ReprName='SCTP PAD chunk')
        self.pad.Pt = padlen * self.padding_bytes
        self.len.Pt = self.pad
        self.len.PtFunc = lambda pad: len(pad)+4

class AUTH(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0x0F, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='skid', ReprName='Shared Key Identifier', Type='uint16'),
        Int(CallName='hid', ReprName='HMAC Identifier', Type='uint16', \
            Dict=hmac_dict),
        Str(CallName='hmac', ReprName='HMAC Value', Repr='hex'),
        ]
    
    # hmac_dict -> 'Reserved', 'SHA-1', 'SHA-256'
    # SCTP chunks to authenticate must be placed as payload of the AUTH chunk...
    def __init__(self, skid=0, hid=1, K=20*'\x00'):
        Layer.__init__(self, CallName='auth', ReprName='SCTP AUTH chunk')
        self.skid.Pt = skid
        self.hid.Pt = hid
        self.hmac.Pt = self.get_payload
        self.hmac.PtFunc = lambda pay: self.computeHMAC(K, int(self.hid), str(pay()))
        self.hmac.Len = self.len
        self.hmac.LenFunc = lambda len: int( len ) - 8
        self.len.Pt = self.hmac
        self.len.PtFunc = lambda mac: len( mac ) + 8
    
    def computeHMAC(self, K=20*'\0', alg=1, payload=''):
        if alg == 1:
            self.hmac.Val = 20*'\x00'
            data = str(self) + payload
            mac = hmac.new(K, data, hashlib.sha1).digest()
        elif alg == 2:
            self.hmac.Val = 32*'\x00'
            data = str(self) + payload
            mac = hmac.new(K, data, hashlib.sha256).digest()
        else: mac=''
        self.hmac.Val = None
        return mac

class FORWARD_TSN(Layer):
    constructorList = [
        Int(CallName='type', ReprName='Chunk Type', Pt=0xC0, Type='uint8', \
            Dict=chunk_dict),
        Bit(CallName='res', ReprName='Reserved', Pt=0, BitLen=5),
        Bit(CallName='U', ReprName='Unordered', Pt=0, BitLen=1),
        Bit(CallName='B', ReprName='Beginning', Pt=0, BitLen=1),
        Bit(CallName='E', ReprName='Ending', Pt=0, BitLen=1),
        Int(CallName='len', ReprName='Chunk Length', Type='uint16'),
        Int(CallName='ctsn', ReprName='New Cumulative TSN', Type='uint32'),
        ]
    
    def __init__(self, ctsn=0):
        Layer.__init__(self, CallName='fwdtsn', ReprName='SCTP FORWARD_TSN chunk')
        self.ctsn.Pt = ctsn
        self.len.Pt = self.get_payload
        self.len.PtFunc = lambda pay: len( pay() ) + 8
    # must take some StreamSeq as payloads

class StreamSeq(Layer):
    constructorList = [
        Int(CallName='sid', ReprName='Stream Identifier', Type='uint16'),
        Int(CallName='ssq', ReprName='Stream Sequence', Type='uint16'),
        ]
    
    def __init__(self, sid=0, ssq=0):
        Layer.__init__(self, CallName='sseq', ReprName='Stream Sequence')
        self.sid.Pt = sid
        self.ssq.Pt = ssq


# define the dictionnary to call SCTP chunk Layer object from their identifier 
chunkCall = {
    0 : DATA,
    1 : INIT,
    2 : INIT_ACK,
    3 : SACK,
    4 : HEARTBEAT,
    5 : HEARTBEAT_ACK,
    6 : ABORT,
    7 : SHUTDOWN,
    8 : SHUTDOWN_ACK,
    9 : ERROR,
    10 : COOKIE_ECHO,
    11 : COOKIE_ACK,
    12 : ECNE,
    13 : CWR,
    14 : SHUTDOWN_COMPLETE,
    0x0F : AUTH,
    0x80 : ASCONF_ACK,
    0x84 : PAD,
    0xC0 : FORWARD_TSN,
    0xC1 : ASCONF,
    }


