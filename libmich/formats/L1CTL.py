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
# * File Name : formats/L1CTL.py
# * Created : 2012-03-25
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
##########
# L1CTL is the protocol implemented by 
# osmocom to communicate with low level (PHY frame)
# of the GSM air interface
#
# protocol structure is defined in 
# l1ctl_proto.h file of the project libosmocore
#
##########
#
#!/usr/bin/env python
#
from libmich.core.element import Element, Str, Int, Bit, Layer, \
    RawLayer, Block, show, log, ERR, WNG, DBG
from L2GSM import *
from L3Mobile import *
from L3Mobile_24007 import StrRR
from binascii import hexlify

#################
#
# shortcut for RR messages not implemented in L3GSM_RR
class RR_gene(Layer3):
    constructorList = [ie for ie in LengthRR()] + [ \
        Bit('SI', ReprName='Skip Indicator', Pt=0, BitLen=4),
        Bit('PD', ReprName='Protocol Discriminator', \
            BitLen=4, Dict=PD_dict, Repr='hum'),
        Int('Type', Type='uint8', Dict=GSM_RR_dict)
        ]
    def __init__(self):
        Layer3.__init__(self)
        self.extend([\
            Str('RawRR', Pt='', Repr='hex'),
            StrRR('IArest', ReprName='IA rest octets', Repr='hex')])
        self.RawRR.Len = self.len
        self.RawRR.LenFunc = lambda l: l()-2 # cause header() is 2 bytes
        self.len.Pt = self.RawRR
        self.len.PtFunc = lambda x: len(x)+2
        self.IArest.Len = self.len
        self.IArest.LenFunc = lambda l: 22-l()-len(l)

# SACCH L1 header (used like a slice of swiss cheese into a sandwich,
# to have glue between L1CTL header and LAPDm / L3 SACCH msg)
class SACCH_L1(Layer):
    constructorList = [
        Int('tx_power', ReprName='MS power level', Pt=1, Type='uint8'),
        Int('TA', ReprName='Actual timing advance', Pt=0, Type='uint8'),
        ]

################
#
# libmich elements configuration
Element.dbg = 1
Element.safe = True
Layer.dbg = 1
Layer.safe = True
Int._endian = 'big'

# L1CTL message types
L1CTL_NONE = 0
L1CTL_FBSB_REQ = 1  # tuning to a new ARFCN, request
L1CTL_FBSB_CONF = 2 # tuning to a new ARFCN, confirm
L1CTL_DATA_IND = 3  # receiving DATA
L1CTL_RACH_REQ = 4  # request access on RACH
L1CTL_DM_EST_REQ = 5    # dedicated mode establishment, request
L1CTL_DATA_REQ = 6
L1CTL_RESET_IND = 7 # confirm reset
L1CTL_PM_REQ = 8    # power measurement, request
L1CTL_PM_CONF = 9   # power measurement, confirm
L1CTL_ECHO_REQ = 10
L1CTL_ECHO_CONF = 11
L1CTL_RACH_CONF = 12    # confirm access on RACH
L1CTL_RESET_REQ = 13    # L1 firmware reset, request
L1CTL_RESET_CONF = 14   # L1 firmware reset, confirm
L1CTL_DATA_CONF = 15
L1CTL_CCCH_MODE_REQ = 16    # change mode on CCCH, request
L1CTL_CCCH_MODE_CONF = 17   # change mode on CCCH, confirm
L1CTL_DM_REL_REQ = 18   # dedicated mode release, request
L1CTL_PARAM_REQ = 19    # transmit new parameters to L1 for dedicated mode
L1CTL_DM_FREQ_REQ = 20  # request frequency in dedicated mode
L1CTL_CRYPTO_REQ = 21   # request the ciphering of the dedicated channel
L1CTL_SIM_REQ = 22
L1CTL_SIM_CONF = 23
L1CTL_TCH_MODE_REQ = 24     # change traffic channel parameters (eg TA, Tx_pwr)
L1CTL_TCH_MODE_CONF = 25    # change traffic channel parameters (eg TA, Tx_pwr)
L1CTL_NEIGH_PM_REQ = 26 # power measurement, request
L1CTL_NEIGH_PM_IND = 27 # power measurement, receiving results 
L1CTL_TRAFFIC_REQ = 28  # request a TCH
L1CTL_TRAFFIC_CONF = 29 # confirm TCH traffic is incoming
L1CTL_TRAFFIC_IND = 30  # receiving TCH traffic

L1type_dict = {
    0 : 'L1CTL_NONE',
    1 : 'L1CTL_FBSB_REQ',
    2 : 'L1CTL_FBSB_CONF',
    3 : 'L1CTL_DATA_IND',
    4 : 'L1CTL_RACH_REQ',
    5 : 'L1CTL_DM_EST_REQ',
    6 : 'L1CTL_DATA_REQ',
    7 : 'L1CTL_RESET_IND',
    8 : 'L1CTL_PM_REQ',
    9 : 'L1CTL_PM_CONF',
    10 : 'L1CTL_ECHO_REQ',
    11 : 'L1CTL_ECHO_CONF',
    12 : 'L1CTL_RACH_CONF',
    13 : 'L1CTL_RESET_REQ',
    14 : 'L1CTL_RESET_CONF',
    15 : 'L1CTL_DATA_CONF',
    16 : 'L1CTL_CCCH_MODE_REQ',
    17 : 'L1CTL_CCCH_MODE_CONF',
    18 : 'L1CTL_DM_REL_REQ',
    19 : 'L1CTL_PARAM_REQ',
    20 : 'L1CTL_DM_FREQ_REQ',
    21 : 'L1CTL_CRYPTO_REQ',
    22 : 'L1CTL_SIM_REQ',
    23 : 'L1CTL_SIM_CONF',
    24 : 'L1CTL_TCH_MODE_REQ',
    25 : 'L1CTL_TCH_MODE_CONF',
    26 : 'L1CTL_NEIGH_PM_REQ',
    27 : 'L1CTL_NEIGH_PM_IND',
    28 : 'L1CTL_TRAFFIC_REQ',
    29 : 'L1CTL_TRAFFIC_CONF',
    30 : 'L1CTL_TRAFFIC_IND',
    }

# L1CTL reset
L1CTL_RES_T_BOOT = 0
L1CTL_RES_T_FULL = 1
L1CTL_RES_T_SCHED = 2
Reset_dict = {
	0 : 'L1CTL_RES_T_BOOT',
	1 : 'L1CTL_RES_T_FULL',
	2 : 'L1CTL_RES_T_SCHED',
    }

# CCCH configuration
# warning, modes are not corresponding to what is sent by the net
# in SI_3.CChanDesc.CCCH_MODE
CCCH_MODE_NONE = 0
CCCH_MODE_NON_COMBINED = 1 # this is equivalent to CChanDesc.CCCH_MODE = 0
CCCH_MODE_COMBINED = 2 # this is equivalent to CChanDesc.CCCH_MODE in (1, 2, 4, 6)
CCCH_dict = {
	0 : 'CCCH_MODE_NONE',
	1 : 'CCCH_MODE_NON_COMBINED',
	2 : 'CCCH_MODE_COMBINED',
    }

# TCH configuration
TRAFFIC_DATA_LEN = 40
TCH_dict = {
    }

# Neighboring cell configuration
NEIGH_MODE_NONE = 0
NEIGH_MODE_PM = 1
NEIGH_MODE_SB = 2
Neigh_dict = {
    0 : 'NEIGH_MODE_NONE',
    1 : 'NEIGH_MODE_PM',
    2 : 'NEIGH_MODE_SB',
    }


class L1CTL(Block):
    
    def __init__(self, msg_type=L1CTL_RESET_IND):
        Block.__init__(self, Name="L1CTL")
        self.append( l1ctl_hdr() )
        self[0].msg_type > msg_type
    
    def _get_ccch(self, string=''):
        # this is to decode reliably GSM broadcast
        #
        if len(string) < 3:
            self << RawLayer()
            self[-1].map(string)
            return
        l = LengthRR()
        l.map(string[0:1])
        h = Header()
        h.map(string[1:3])
        # should check length (l) coherence here (including with M bit)
        # ...
        # check for non-RR protocol, or truncated string
        if h.PD() != 6 or len(string) < 23:
            self << l
            self | RawL3()
            self[-1].map(string[1:])
            return
        # if we have the complete RR decoder
        if h.Type() in L3Call[6].keys():
            rr = L3Call[6][h.Type()]()
        # otherwise, it's the generic RR decoder
        # what is not very smart... however !
        else:
            rr = RR_gene()
        # we can still have corrupted data
        try:
            rr.map(string)
            # if RR is correctly decoded
            self << rr
        except:
            if self.dbg >= DBG:
                log(DBG, '(L1CTL - L3GSM_RR) message parsing failed with:\n%s' \
                    % hexlify(string))
            self << RR_gene()
            self[-1].map(string)
    
    def _get_dch(self, string=''):
        # this is to decode reliably GSM dedicated channel
        if len(string) < 5:
            self << RawLayer()
            self[-1].map(string[:3])
            return
        self << LAPDm()
        self[-1].map(string)
        string = string[3:]
        # check what kind of signalling we have
        # RR 6, MM 5, CC 3
        l3_len = self[-1].len()
        # in case L3 is fragmented
        if self[-1].M():
            self << RawLayer(string[:l3_len])
        else:
            # this can lead to dummy L3 msg as there is no way
            # to distinguish between a self-contained LAPDm frame
            # and the last fragment of a fragmented LAPDm frame
            self << parse_L3(string[:l3_len])
        # in case we have GSM padding
        if l3_len < len(string):
            self | RestOctets()
            self[-1].map(string[l3_len:])
    
    def _get_data(self, string=''):
        # look for common / broadcast channel
        if self[1].ChanNr.Channel() in (16, 18):
            self._get_ccch(string)
        else:
            # dedicated channel
            # look for SACCH
            if self[1].LinkId.C2C1() == 1:
                if len(string) < 2:
                    self << RawLayer()
                    self[-1].map(string)
                    return
                self << SACCH_L1()
                self[-1].map(string[0:2])
                string = string[2:]
            # get LAPDm and signalling
            self._get_dch(string)
        
    def parse(self, s=''):
        self.__init__()
        self.map(s)
        s = s[4:]
        t = self[0].msg_type()
        
        # tune L1 on a new ARFCN
        if t == L1CTL_FBSB_REQ:
            self << l1ctl_fbsb_req()
            self[-1].map(s)
            s = s[8:]
        
        elif t == L1CTL_FBSB_CONF:
            self << l1ctl_info_dl()
            self[-1].map(s)
            s = s[12:]
            self | l1ctl_fbsb_conf()
            self[-1].map(s)
            s = s[4:]
        
        # CCCH data received
        # some burst are not fully decoded, 
        # and serial coms may partially fail too 
        # hence buffer length is taking care of
        elif t in (L1CTL_DATA_IND, L1CTL_DATA_CONF):
            self << l1ctl_info_dl()
            if len(s) >= 12:
                self[-1].map(s)
                s = s[12:]
                if s:
                    # select to common / dedicated processing
                    self._get_data(s)
        
        # CCCH mode request / confirmation
        elif t == L1CTL_CCCH_MODE_REQ:
            self << l1ctl_ccch_mode_req()
            self[-1].map(s)
            s = s[4:]
        elif t == L1CTL_CCCH_MODE_CONF:
            self << l1ctl_ccch_mode_conf()
            self[-1].map(s)
            s = s[4:]
        
        # echo toward baseband
        elif t == L1CTL_ECHO_REQ or t == L1CTL_ECHO_CONF:
            self << RawLayer()
            self[-1].map(s)
            s = ''
        
        # power measurement
        elif t == L1CTL_PM_REQ:
            self << l1ctl_pm_req()
            self[-1].map(s)
            s = s[8:]
        elif t == L1CTL_PM_CONF:
            while len(s) > 3:
                self.append( l1ctl_pm_conf() )
                self[-1].hierarchy = self[0].hierarchy + 1
                self[-1].map(s)
                s = s[4:]
        elif t == L1CTL_NEIGH_PM_REQ:
            self << l1ctl_neigh_pm_req()
            self[-1].map(s)
            s = s[194:]
        elif t == L1CTL_NEIGH_PM_IND:
            while len(s) > 3:
                self.append( l1ctl_neigh_pm_ind() )
                self[-1].hierarchy = self[0].hierarchy + 1
                self[-1].map(s)
                s = s[6:]
        
        # reset
        elif t == L1CTL_RESET_REQ or t == L1CTL_RESET_CONF:
            self << l1ctl_reset()
            self[-1].map(s)
            s = s[4:]
        
        # param request
        elif t == L1CTL_PARAM_REQ:
            self << l1ctl_info_ul()
            self[-1].map(s)
            s = s[4:]
            self | l1ctl_par_req()
            self[-1].map(s)
            s = s[4:]
        
        # RACH req / resp
        elif t == L1CTL_RACH_REQ:
            self << l1ctl_info_ul()
            self[-1].map(s)
            s = s[4:]
            self | l1ctl_rach_req()
            self[-1].map(s)
            s = s[4:]
        elif t == L1CTL_RACH_CONF:
            self << l1ctl_info_dl()
            self[-1].map(s)
            s = s[12:]
        
        # data req 
        elif t == L1CTL_DATA_REQ:
            self << l1ctl_info_ul()
            self[-1].map(s)
            s = s[4:]
            # we will have some L3 data here
            self._get_data(s)
            
        # dm establishment req
        elif t == L1CTL_DM_EST_REQ:
            self << l1ctl_info_ul()
            self[-1].map(s)
            s = s[4:]
            if len(s) == 6:
                self | l1ctl_dm_est_req_h0()
            else:
                self | l1ctl_dm_est_req_h1()
            self[-1].map(s)
            s = s[len(self[-1]):]
        
        # SIM access
        elif t == L1CTL_SIM_REQ or t == L1CTL_SIM_CONF:
            # this is actually smartcared raw APDU directly appended
            self << RawLayer()
            self[-1].map(s)
            s = ''
        
        # ...
        #

######
# L1CTL global header
class l1ctl_hdr(Layer):
    constructorList = [
        Int('msg_type', Pt=0, Type='uint8', Dict=L1type_dict),
        Int('flags', Pt=0, Type='uint8', Repr='hex'),
        Str('padding', Pt='\0\0', Len=2, Repr='hex'),
        ]

###
# from 48.058, section 9.3.1: channel number
ChanNr_dict = {
    1 : 'Bm + ACCH',
    2 : 'Lm + ACCH; subchannel 0',
    3 : 'Lm + ACCH; subchannel 1',
    4 : 'SDCCH/4 + ACCH; subchannel 0',
    5 : 'SDCCH/4 + ACCH; subchannel 1',
    6 : 'SDCCH/4 + ACCH; subchannel 2',
    7 : 'SDCCH/4 + ACCH; subchannel 3',
    8 : 'SDCCH/8 + ACCH; subchannel 0',
    9 : 'SDCCH/8 + ACCH; subchannel 1',
    10 : 'SDCCH/8 + ACCH; subchannel 2',
    11 : 'SDCCH/8 + ACCH; subchannel 3',
    12 : 'SDCCH/8 + ACCH; subchannel 4',
    13 : 'SDCCH/8 + ACCH; subchannel 5',
    14 : 'SDCCH/8 + ACCH; subchannel 6',
    15 : 'SDCCH/8 + ACCH; subchannel 7',
    16 : 'BCCH',
    17 : 'Uplink CCCH (RACH)',
    18 : 'Downlink CCCH (PCH + AGCH)',
    }
class ChanNr(Layer):
    constructorList = [
        Bit('Channel', ReprName='Channel / Subchannel', Pt=1, BitLen=5, \
            Repr='hum', Dict=ChanNr_dict),
        Bit('TN', ReprName='Timeslot Number', Pt=0, BitLen=3, Repr='hum')
        ]
# from 48.058, section 9.3.2: link identifier
C2C1_dict = {
    0 : 'main signalling channel (FACCH or SDCCH)',
    1 : 'SACCH'
    }
LinkPrio_dict = {
    0 : 'normal',
    1 : 'high',
    2 : 'low',
    }
class LinkId(Layer):
    constructorList = [
        Bit('C2C1', Pt=0, BitLen=2, Repr='hum', Dict=C2C1_dict),
        Bit('NA', ReprName='Non Applicable', Pt=0, BitLen=1, Repr='hum'),
        Bit('priority', Pt=0, BitLen=2, Repr='hum', Dict=LinkPrio_dict),
        Bit('SAPI', ReprName='Service Access Point Identifier', Pt=0, \
            BitLen=3, Repr='hum', Dict=SAPI_dict)
        ]
#
# downlink info: tgt -> host ?
class l1ctl_info_dl(Layer):
    constructorList = [
        ChanNr(),
        LinkId(),
        Int('band_arfcn', Pt=0, Type='uint16'),
        Int('frame_nr', Pt=0, Type='uint32'),
        Int('rx_level', Pt=0, Type='uint8'),
        Int('snr', Pt=0, Type='uint8'),
        Int('num_biterr', Pt=0, Type='uint8'),
        Int('fire_crc', Pt=0, Type='uint8', Repr='hex'),
        ]

#to confirm a new CCCH is found: tgt -> host
class l1ctl_fbsb_conf(Layer):
    constructorList = [
        Int('initial_freq_err', Pt=0, Type='int16'),
        Int('result', Pt=0, Type='uint8'),
        Int('bsic', Pt=0, Type='uint8'),
        ]

# to confirm a CCCH mode change: tgt -> host
class l1ctl_ccch_mode_conf(Layer):
    constructorList = [
        Int('ccch_mode', Pt=0, Type='uint8', Dict=CCCH_dict),
        Str('padding', Pt='\0\0\0', Len=3, Repr='hex'),
        ]

# to confirm a TCH mode change: tgt -> host
class l1ctl_tch_mode_conf(Layer):
    constructorList = [
        Int('tch_mode', Pt=0, Type='uint8'), #, Dict=TCH_dict),
        Int('audio_mode', Pt=0, Type='uint8'),
        Str('padding', Pt='\0\0', Len=2, Repr='hex'),
        ]

# data found in the CCCH: tgt -> host
class l1ctl_data_ind(Layer):
    constructorList = [
        Str('data', Len=23, Repr='hex'),
        ]

# traffic from the network (TCH): tgt -> host
class l1ctl_traffic_ind(Layer):
    constructorList = [
        Str('data', Len=TRAFFIC_DATA_LEN, Repr='hex'),
        ]

############################
# uplink info: host -> tgt ?
class l1ctl_info_ul(Layer):
    constructorList = [
        ChanNr(),
        LinkId(),
        Str('padding', Pt='\0\0', Len=2, Repr='hex'),
        ]

# request FBSB: Frequency and time Synchronization Burst
# in l1ctl_info_ul
class l1ctl_fbsb_req(Layer):
    constructorList = [
        Int('band_arfcn', Pt=0, Type='uint16'),
        Int('timeout', Pt=100, Type='uint16'),
        Int('freq_err_thresh1', Pt=10000, Type='uint16'),
        Int('freq_err_thresh2', Pt=800, Type='uint16'),
        Int('num_freqerr_avg', Pt=3, Type='uint8'),
        Bit('flags', Pt=0, BitLen=5),
        Bit('L1CTL_FBSB_F_SB', Pt=1, BitLen=1),
        Bit('L1CTL_FBSB_F_FB1', Pt=1, BitLen=1),
        Bit('L1CTL_FBSB_F_FB0', Pt=1, BitLen=1),
        Int('sync_info_idx', Pt=0, Type='uint8'),
        Int('ccch_mode', Pt=CCCH_MODE_NONE, Type='uint8', Dict=CCCH_dict),
        ]

# request CCCH mode
# in l1ctl_info_ul
class l1ctl_ccch_mode_req(Layer):
    constructorList = [
        Int('ccch_mode', Pt=0, Type='uint8', Dict=CCCH_dict),
        Str('padding', Pt='\0\0\0', Len=3, Repr='hex'),
        ]

# request TCH mode
# in l1ctl_info_ul
class l1ctl_tch_mode_req(Layer):
    constructorList = [
        Int('tch_mode', Pt=0, Type='uint8'),
        Bit('audio_mode', Pt=0, BitLen=4, Repr='hex'),
        Bit('AUDIO_RX_TRAFFIC_IND', Pt=0, BitLen=1),
        Bit('AUDIO_RX_SPEAKER', Pt=0, BitLen=1),
        Bit('AUDIO_TX_TRAFFIC_REQ', Pt=0, BitLen=1),
        Bit('AUDIO_TX_MICROPHONE', Pt=0, BitLen=1),
        #Int('audio_mode', Pt=0, Type='uint8'),
        Str('padding', Pt='\0\0', Len=2, Repr='hex'),
        ]
# audio modes:
#define AUDIO_TX_MICROPHONE	(1<<0)
#define AUDIO_TX_TRAFFIC_REQ	(1<<1)
#define AUDIO_RX_SPEAKER	(1<<2)
#define AUDIO_RX_TRAFFIC_IND	(1<<3)

# request RACH
# in l1ctl_info_ul
class l1ctl_rach_req(Layer):
    constructorList = [
        Int('ra', Pt=0, Type='uint8'),
        Int('combined', Pt=0, Type='uint8'),
        Int('offset', Pt=0, Type='uint16'),
        ]
# ra looks like "establishment cause + random ref"; eg:
# 0b101xxxxx = emergency call
# 0b000xxxxx = LocUpdate (without NECI)
# 0b111xxxxx = SDCCH (without NECI)
# 0b0000xxxx = LocUpdate (with NECI)
# 0b0001xxxx = SDCCH (with NECI)


# in l1ctl_info_ul
class l1ctl_par_req(Layer):
    constructorList = [
        Int('ta', Pt=0, Type='int8'),
        Int('tx_power', Pt=0, Type='uint8'),
        Str('padding', Pt='\0\0', Len=2, Repr='hex'),
        ]

###
# request dedicated mode establishment ?
class l1ctl_h0(Layer):
    constructorList = [
        Int('band_arfcn', Pt=0, Type='uint16'),
        ]

class l1ctl_h1(Layer):
    constructorList = [
        Int('hsn', Pt=0, Type='uint8'),
        Int('maio', Pt=0, Type='uint8'),
        Int('n', Pt=0, Type='uint8'),
        Str('padding', Pt='\0', Len=1, Repr='hex')] + \
        [Int('ma_%i' % i, Pt=0, Type='uint16') for i in range(64)]

class l1ctl_dm_est_req_h0(Layer):
    constructorList = [
        Int('tsc', Pt=0, Type='uint8'),
        Int('h', Pt=0, Type='uint8'),
        l1ctl_h0(),
        Int('tch_mode', Pt=0, Type='uint8'),
        Int('audio_mode', Pt=5, Type='uint8'),
        ]

class l1ctl_dm_est_req_h1(Layer):
    constructorList = [
        Int('tsc', Pt=0, Type='uint8'),
        Int('h', Pt=1, Type='uint8'),
        l1ctl_h1(),
        Int('tch_mode', Pt=0, Type='uint8'),
        Int('audio_mode', Pt=5, Type='uint8'),
        ]

###
# request ?
class l1ctl_dm_freq_req(Layer):
    constructorList = [
        Int('fn', Pt=0, Type='uint16'),
        Int('tsc', Pt=0, Type='uint8'),
        Int('h', Pt=0, Type='uint8'),
        l1ctl_h0(),
        l1ctl_h1(),
        ]

# request ciphering
class l1ctl_crypto_req(Layer):
    constructorList = [
        Int('algo', Pt=0, Type='uint8'),
        Str('key', Len=8, Repr='hex'), # ??? key[0]
        ]

# POWER MEASUREMENT
# Power measurement request: host -> tgt
class l1ctl_pm_req(Layer):
    constructorList = [
        Int('type', Pt=1, Type='uint8'),
        Str('padding', Pt='\0\0\0', Len=3, Repr='hex'),
        Int('band_arfcn_from', Pt=0, Type='uint16'),
        Int('band_arfcn_to', Pt=0, Type='uint16'),
        ]

# Power measurement request: tgt -> host
class l1ctl_pm_conf(Layer):
    constructorList = [
        Int('band_arfcn', Pt=0, Type='uint16'),
        Int('pm', Pt=0, Type='uint8'),
        Int('pm2', Pt=0, Type='uint8'),
        ]

# L1CTL RESET
# argument to L1CTL_RESET_REQ and L1CTL_RESET_IND
class l1ctl_reset(Layer):
    constructorList = [
        Int('type', Pt=0, Type='uint8', Dict=Reset_dict),
        Str('padding', Pt='\0\0\0', Len=3, Repr='hex'),
        ]

class l1ctl_neigh_pm_req(Layer):
    constructorList = [
        Int('n', Pt=0, Type='uint8'),
        Str('padding', Pt='\0', Len=1, Repr='hex'),
        #Str('band_arfcn', Len=128, Repr='hex'), # 64 * uint16
        #Str('tn', Len=64, Repr='hex'), # 64 * uint8
        ] + \
        [Int('band_arfcn_%s' % i, Pt=0, Type='uint16') for i in range(64)] + \
        [Int('tn_%s' % i, Pt=0, Type='uint8') for i in range(64)]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.n.Pt = None
        self.n.PtFunc = self.__num_bands
    
    def __num_bands(self, unused):
        n = 0
        for l in self[2:66]:
            if l() != 0: n += 1
        return n

class l1ctl_neigh_pm_ind(Layer):
    constructorList = [
        Int('band_arfcn', Pt=0, Type='uint16'),
        Int('pm', Pt=0, Type='uint8'),
        Int('pm2', Pt=0, Type='uint8'),
        Int('tn', Pt=0, Type='uint8'),
        Str('padding', Pt='\0', Len=1, Repr='hex'),
        ]

class l1ctl_traffic_req(Layer):
    constructorList = [
        Str('data', Len=TRAFFIC_DATA_LEN, Repr='hex'),
        ]
