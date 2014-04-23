# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau. ANSSI.
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
# * File Name : formats/L3GSM_IE.py
# * Created : 2012-04-03 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# exporting
__all__ = ['CellChan', 'BCCHFreq', 'ExtBCCHFreq', 'RACHCtrl', 'CChanDesc', \
           'CellOpt', 'CellSel', 'ChanDesc', 'MobAlloc', 'PChanDesc', 'ReqRef', \
           'MeasRes', 'CmEnq', 'ACS_SI3_dict', 'ACS_SI4_dict']

from binascii import hexlify
from libmich.core.element import Bit, Int, Str, Layer, \
    show, log, DBG, WNG, ERR
from libmich.core.IANA_dict import IANA_dict
from libmich.core.CSN1 import CSN1
from libmich.formats.MCCMNC import MCC_dict, MNC_dict

# TS 44.018 defines L3 Radio Ressource signalling for GSM mobile networks
# section 10: IE coding
#
# describes mobile L3 signalling information element
# each L3 message composed of Information Element (IE)
#
# Take care with naming convention here
# as it is used to pull automatically IEs into L3 messages when parsing them

######
# 44.018, section 10.5.2.1b: Cell Channel description
# IE layout: 2 MSB of 1st nibble, then 3 MSB of 2nd nibble
# depending of 1st nibble
#
#MSB(128)    LSB(121)
#b,b,s,s,b,b,b,s
CellChanFmtMSB_dict = {
    0 : 'bit map 0',
    2 : 'range or variable bit map'}
CellChanFmtM_dict = {
    0 : '1024 range'}
CellChanFmtLSB_dict = {
    4 : '512 range',
    5 : '256 range',
    6 : '128 range',
    7 : 'variable bit map'}
#
class CellChan(Layer):
    _fmts = ['map0', 'mapvar', 'r128', 'r256', 'r512', 'r1024']
    constructorList = [
        Bit('format', Pt=0, BitLen=2, Repr='hum', Dict=CellChanFmtMSB_dict),
        Bit('spare', Pt=0, BitLen=2, Repr='hex'),
        Bit('ARFCN_list', Pt=0, BitLen=124, Repr='hex')]
    
    def __init__(self, fmt='map0', **kwargs):
        Layer.__init__(self, **kwargs)
        self._rebuild(fmt)
    
    def map(self, string='\0'):
        # check bit 128, 127 for format: bit map 0, or range / variable
        # check bit 124 for format range 1024
        # check bit 123, 122 for little ranges and var bit map
        MSB = ord(string[0])
        # we have to select the right format from self._fmts
        if (MSB >> 6) == 0:
            self._rebuild('map0')
        elif (MSB >> 6) == 2:
            if ((MSB >> 3) & 0b1) == 0:
                self._rebuild('r1024')
            else:
                fmt_ext = (MSB >> 1) & 0b11
                if fmt_ext == 0:
                    self._rebuild('r512')
                elif fmt_ext == 1:
                    self._rebuild('r256')
                elif fmt_ext == 2:
                    self._rebuild('r128')
                elif fmt_ext == 3:
                    self._rebuild('mapvar')
        Layer.map(self, string)
    
    def _rebuild(self, fmt='map0'):
        if self.safe and fmt not in self._fmts:
            raise AttributeError('fmt must be a in %s' % self._fmts)
        if fmt in ['mapvar', 'r128', 'r256', 'r512', 'r1024']:
            # keep only 'format' and 'spare' field (WNG: with inheriting Layer)
            # and prepare the layer for the correct format
            # keep only fields before 'ARFCN_list'
            cnt = 0
            for f in self:
                if f.CallName == 'ARFCN_list': break
                else: cnt += 1
            self.elementList = self.elementList[0:cnt]
            #
            i = 1 # for index of W in range format
            if fmt == 'r1024':
                # 1 bit of format extension only, and the ARFCN mask
                self.append(Bit('format_ext', Pt=0, BitLen=1, Repr='hum', \
                                Dict=CellChanFmtM_dict))
                self.append(Bit('F0', Pt=0, BitLen=1, Repr='hum', \
                                Dict={0:'ARFCN 0 not included', \
                                      1:'ARFCN 0 included'}))
                layout = [10, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7]
                for bl in layout:
                    self.append(Bit('W_%i' % i, Pt=0, BitLen=bl, Repr='hum'))
                    i += 1
            else:
                # for other formats, we have 3 bits of format extension
                # the ORIG-ARFCN, and then mask or list of ARFCN
                self.append(Bit('format_ext', Pt=0, BitLen=3, Repr='hum', \
                                Dict=CellChanFmtLSB_dict))
                self.append(Bit('orig_arfcn', Pt=0, BitLen=10, Repr='hum'))
                if fmt == 'r512':
                    # W(i) bit length layout
                    layout = [9, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5]
                    for bl in layout:
                        self.append(Bit('W_%i' % i, Pt=0, BitLen=bl, Repr='hum'))
                        i += 1
                elif fmt == 'r256':
                    # W(i) bit length layout
                    layout = [8, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 4, \
                              4, 4, 4, 4, 4]
                    for bl in layout:
                        self.append(Bit('W_%i' % i, Pt=0, BitLen=bl, Repr='hum'))
                        i += 1
                    self.append(Bit('spare_e', Pt=0, BitLen=1, Repr='hex'))
                elif fmt == 'r128':
                    # W(i) bit length layout
                    layout = [7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, \
                              3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]
                    for bl in layout:
                        self.append(Bit('W_%i' % i, Pt=0, BitLen=bl, Repr='hum'))
                        i += 1
                    self.append(Bit('spare_e', Pt=0, BitLen=1, Repr='hex'))
                elif fmt == 'mapvar':
                    # variable bit map
                    self.append(Bit('RRFCN_list', Pt=0, BitLen=111, Repr='hex'))
    
    # this is to return the list of ARFCNs
    # different coding scheme are used
    def ARFCN(self):
        if self.format() == 0:
            try:
                return self._decode_bitmap0()
            except:
                return []
        elif self.format() in (1, 2):
            if hasattr(self, 'format_ext'):
                fmt_ext = self.format_ext()
                if fmt_ext == 0:
                    try:
                        return self._decode_range(1024)
                    except:
                        return []
                elif fmt_ext == 4:
                    try:
                        return self._decode_range(512)
                    except:
                        return []
                elif fmt_ext == 5:
                    try:
                        return self._decode_range(256)
                    except:
                        return []
                elif fmt_ext == 6:
                    try:
                        return self._decode_range(128)
                    except:
                        return []
                elif fmt_ext == 7:
                    try:
                        return self._decode_bitmapvar()
                    except:
                        return []
        return []
    
    def _decode_bitmap0(self):
        # shift / filter each bit of the ARFCN_list
        ar_val, ar_len, arfcns = self.ARFCN_list(), self.ARFCN_list.BitLen, []
        for i in range(ar_len):
            if (ar_val >> (ar_len-i)) & 0b1:
                arfcns.append(ar_len+1-i)
        return sorted(arfcns)
    
    def _decode_bitmapvar(self):
        # get ORIG-ARFCN
        o_arfcn = self.orig_arfcn()
        arfcns = [o_arfcn]
        # shift / filter each bit of relative RRFCN_list
        rr_val, rr_len = self.RRFCN_list(), self.RRFCN_list.BitLen
        for i in range(rr_len):
            if (rr_val >> (rr_len-i)) & 0b1:
                arfcns.append((o_arfcn + i) % 1024)
        return sorted(arfcns)
        
    def _decode_range(self, fmt):
        # go over all W fields and apply the computation algorithm
        # as of 10.5.2.3.13.3
        # some discrepancies exist between the 4 ranges:
        # 1) computing the next F
        # 2) initial and number of F
        if fmt == 1024:
            if self.F0(): ar_list = [0]
            else: ar_list = []
            ind_max = 17
            app = lambda N: ar_list.append(N)
        elif fmt in (128, 256, 512):
            ar_list = [self.orig_arfcn()]
            if fmt == 128: ind_max = 29
            elif fmt == 256: ind_max = 22
            elif fmt == 512: ind_max = 18
            app = lambda N: ar_list.append((ar_list[0]+N) % 1024)
        #
        # loop over all non-null W values to compute corresponding F
        for ind in range(1, ind_max):
            if getattr(self, 'W_%i' % ind)():
                app(self._WtoF(ind, fmt))
                #
                if self.dbg >= DBG:
                    log(DBG, 'L3GSM_IE ARFCN WtoF - index %i; W %i; F %i' % (ind, \
                        getattr(self, 'W_%i' % ind)(), ar_list[-1]))
            else:
                break
        #
        return sorted(ar_list)
    
    def _WtoF(self, index, fmt):
        #J := GREATEST_POWER_OF_2_LESSER_OR_EQUAL_TO(INDEX);
        J = [ j for j in [1, 2, 4, 8, 16, 32, 64, 128] if j <= index ].pop()
        N = getattr(self, 'W_%i' % index)()
        #
        while index > 1:
            if (2*index) < (3*J):
                index = index - (J/2)
                # for range 1024, we have to take W(PARENT)
                par = self._get_W_parent(index, fmt)
                N = ((N + par + (fmt/J) - 2) % (((fmt*2)/J) - 1)) + 1
            else:
                index = index - J
                # for range 1024, we have to take W(PARENT)
                par = self._get_W_parent(index, fmt)
                N = (N + par + ((fmt*2)/J) - 2) % (((fmt*2)/J) - 1) + 1
            J = J/2
        if self.dbg >= DBG:
            log(DBG, 'L3GSM_IE ARFCN WtoF - N: %i' % N)
        return N
    
    def _get_W_parent(self, index, fmt):
        if fmt in (128, 256, 512):
            return getattr(self, 'W_%i' % index)()
        elif fmt == 1024:
            # what is exactly W(PARENT) ???
            # this is a guess ??? TBC
            # TODO
            return getattr(self, 'W_%i' % (index-1))()

# 44.018, section 10.5.2.22
class BCCHFreq(CellChan):
    constructorList = [
        Bit('format', Pt=0, BitLen=2, Repr='hum', Dict=CellChanFmtMSB_dict),
        Bit('ext', Pt=0, BitLen=1, Repr='hex'),
        Bit('ba', Pt=0, BitLen=1, Repr='hex'),
        Bit('ARFCN_list', Pt=0, BitLen=124, Repr='hex')]

# 44.018, section 10.5.2.22
ExtCellChanFmtMSB_dict = {
    0 : 'bit map 0',
    1 : 'range or variable bit map'
    }
class ExtBCCHFreq(CellChan):
    constructorList = [
        Bit('format', Pt=0, BitLen=1, Repr='hum', Dict=ExtCellChanFmtMSB_dict),
        Bit('multiband', Pt=0, BitLen=2, Repr='hum'),
        Bit('ba', Pt=0, BitLen=1, Repr='hex'),
        Bit('ARFCN_list', Pt=0, BitLen=124, Repr='hex')]
    
    def map(self, string='\0'):
        # check bit 128, for format: bit map 0, or range / variable
        # check bit 124 for format range 1024
        # check bit 123, 122 for little ranges and var bit map
        MSB = ord(string[0])
        # we have to select the right format from self._fmts
        if (MSB >> 7) == 0:
            self._rebuild('map0')
        elif (MSB >> 7) == 1:
            if ((MSB >> 3) & 0b1) == 0:
                self._rebuild('r1024')
            else:
                fmt_ext = (MSB >> 1) & 0b11
                if fmt_ext == 0:
                    self._rebuild('r512')
                elif fmt_ext == 1:
                    self._rebuild('r256')
                elif fmt_ext == 2:
                    self._rebuild('r128')
                elif fmt_ext == 3:
                    self._rebuild('mapvar')
        Layer.map(self, string) 

###
# 44.018, section 10.5.2.29: RACH control parameters
MaxRetrans_dict = {
    0 : '1 retransmission max',
    1 : '2 retransmissions max',
    2 : '4 retransmissions max',
    3 : '7 retransmissions max'}
TxInteger_dict = {
    0 : '3 slots',
    1 : '4 slots',
    2 : '5 slots',
    3 : '6 slots',
    4 : '7 slots',
    5 : '8 slots',
    6 : '9 slots',
    7 : '10 slots',
    8 : '11 slots',
    9 : '12 slots',
    10 : '14 slots',
    11 : '16 slots',
    12 : '20 slots',
    13 : '25 slots',
    14 : '32 slots',
    15 : '50 slots'}
CellAccess_dict = {
    0 : 'cell not barred',
    1 : 'cell barred'}
CallReestab_dict = {
    0 : 'allowed',
    1 : 'not allowed'}
class RACHCtrl(Layer):
    constructorList = [
        Bit('max_retrans', Pt=0, BitLen=2, Repr='hum', Dict=MaxRetrans_dict),
        Bit('Tx_integer', ReprName='Tx slots to spread transmission', Pt=0, \
            BitLen=4, Repr='hum', Dict=TxInteger_dict),
        Bit('CellAccess', Pt=0, BitLen=1, Repr='hum', Dict=CellAccess_dict),
        Bit('CallReestab', Pt=0, BitLen=1, Repr='hum', Dict=CallReestab_dict),
        Int('AC', ReprName='Access Control Class', Pt=0, Type='uint16', \
            Repr='hex')]

###
# 44.018, section 10.5.2.11: Control Channel description
CCCHconf_dict = {
    0 : '1 PHY chan for CCCH, not combined with SDCCH',
    1 : '1 PHY chan for CCCH, combined with SDCCH',
    2 : '2 PHY chan for CCCH, combined with SDCCH',
    4 : '3 PHY chan for CCCH, combined with SDCCH',
    6 : '4 PHY chan for CCCH, combined with SDCCH',
    }
class CChanDesc(Layer):
    constructorList = [
        Bit('MSCR', ReprName='MSC Release', Pt=0, BitLen=1, Repr='hum', \
            Dict={0:'R98 or older', 1:'R99 onwards'}),
        Bit('ATT', ReprName='IMSI attach-detach allowed', Pt=0, BitLen=1, \
            Repr='hum'),
        Bit('BS_AG_BLKS_RES', Pt=0, BitLen=3),
        Bit('CCCH_CONF', Pt=0, BitLen=3, Repr='hum', Dict=CCCHconf_dict),
        Bit('spare', Pt=0, BitLen=1),
        Bit('CBCQ3', Pt=0, BitLen=2),
        Bit('spare', Pt=0, BitLen=2),
        Bit('BS_PA_MFRMS', Pt=0, BitLen=3),
        Int('T3212', ReprName='Periodic updating timeout (decihours)', \
            Pt=0, Type='uint8')]

###
# 44.018, section 10.5.2.3: BCCH Cell Options
DTX_dict = {
    0 : 'MS may use uplink discontinuous Tx',
    1 : 'MS shall use uplink discontinuous Tx',
    2 : 'MS shall not use uplink discontinuous Tx',
    }
class CellOpt(Layer):
    constructorList = [
        Bit('DN', ReprName='Dynamic ARFCN mapping support', Pt=0, BitLen=1, \
            Repr='hum'),
        Bit('PWRC', ReprName='Power Control set', Pt=0, BitLen=1, Repr='hum'),
        Bit('DTX', Pt=0, BitLen=2, Repr='hum', Dict=DTX_dict),
        Bit('LinkTo', ReprName='Radio Link Timeout', Pt=0, BitLen=4, \
            Repr='hex')]
###
# 44.018, section 10.5.2.4: Cell selection
CELL_RESEL_dict = {
    0 : '0 dB RXLEV hysteresis for LA re-selection',
    1 : '2 dB RXLEV hysteresis for LA re-selection',
    2 : '4 dB RXLEV hysteresis for LA re-selection',
    3 : '6 dB RXLEV hysteresis for LA re-selection',
    4 : '8 dB RXLEV hysteresis for LA re-selection',
    5 : '10 dB RXLEV hysteresis for LA re-selection',
    6 : '12 dB RXLEV hysteresis for LA re-selection',
    7 : '14 dB RXLEV hysteresis for LA re-selection',
    }
ACS_SI3_dict = {
    0 : 'SI 16 and 17 are not broadcast on the BCCH',
    1 : 'SI 16 and 17 are broadcast on the BCCH'}
ACS_SI4_dict = {
    0 : 'SI 4 rest octets and SI 7 and SI 8 rest octets shall be used to ' \
        'derive the value of PI and possibly C2 and others parameters',
    1 : 'Value of PI and possibly C2 and others parameters in a SI 7 or 8 ' \
        'shall be used'}
NECI_dict = {
    0 : 'New establishment causes are not supported',
    1 : 'New establishment causes are supported'}
class CellSel(Layer):
    constructorList = [
        Bit('CELL_RESELECT_HYSTERESIS', Pt=0, BitLen=3, Repr='hum', \
            Dict=CELL_RESEL_dict),
        Bit('MS_TXPWR_MAX_CCH', ReprName='Max TX power control level on CCH', \
            Pt=0, BitLen=5, Repr='hum'),
        Bit('ACS', Pt=0, BitLen=1, Repr='hum'),
        Bit('NECI', Pt=0, BitLen=1, Repr='hum', Dict=NECI_dict),
        Bit('RXLEV_ACCESS_MIN ', ReprName='Min RX level to access the system', \
            Pt=0, BitLen=6, Repr='hex')
        ]

###
# 44.018, section 10.5.2.5
TDMAoff_dict = {
    1 : 'TCH/F + ACCHs; TSC Set 1 shall be used',
    17 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 0',
    18 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 1',
    4 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 0',
    5 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 1',
    6 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 2',
    7 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 3',
    8 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 0',
    9 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 1',
    10 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 2',
    11 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 3',
    12 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 4',
    13 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 5',
    14 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 6',
    15 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 7',
    }
HopChan_dict = {
    0 : 'Single RF channel',
    1 : 'RF hopping channel',
    }
class ChanDesc(Layer):
    # byte unalignment is needed to map properly last elements
    # due to the 'hopping' flag
    _byte_aligned = False
    constructorList = [
        Bit('TDMAoffset', ReprName='Channel Type and TDMA Offset', Pt=1, \
            BitLen=5, Repr='hum', Dict=TDMAoff_dict),
        Bit('TN', ReprName='Timeslot Number', Pt=0, BitLen=3, Repr='hum'),
        Bit('TSC', ReprName='Training Sequence Code', Pt=0, \
            BitLen=3, Repr='hum'),
        Bit('HopChan', ReprName='Hopping Channel', Pt=0, BitLen=1, \
            Repr='hum', Dict=HopChan_dict),
        Bit('spare', Pt=0, BitLen=2, Repr='hex'),
        Bit('ARFCN', Pt=0, BitLen=10, Repr='hum'),
        Bit('MAIO', ReprName='Mobile Allocation Index Offset', Pt=0, \
            BitLen=6, Repr='hum'),
        Bit('HSN', ReprName='Hopping Sequence Number', Pt=0, \
            BitLen=6, Repr='hum'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # manage single / hopping channel conditional fields
        self.spare.Trans = self.HopChan
        self.ARFCN.Trans = self.HopChan
        self.spare.TransFunc = lambda x: True if x() == 1 else False
        self.ARFCN.TransFunc = lambda x: True if x() == 1 else False
        self.MAIO.Trans = self.HopChan
        self.HSN.Trans = self.HopChan
        self.MAIO.TransFunc = lambda x: True if x() == 0 else False
        self.HSN.TransFunc = lambda x: True if x() == 0 else False

###
# 44.018, section 10.5.2.20
# 16 bytes to convey measurement results in CSN1' style
# aargh: crappy CSN1 notation again...
class NCELLReport(CSN1):
    csn1List = [
        Bit('RXLEV_NCELL', Pt=0, BitLen=6),
        Bit('BCCH_FREQ_NCELL', Pt=0, BitLen=5),
        Bit('BSIC_NCELL', Pt=0, BitLen=6)
        ]

MeasVal_dict = {
    0 : 'measurement results are valid',
    1 : 'measurement results are not valid',
    }
# TODO: pretty sure decoders are completely buggy on this one!
class MeasRes(CSN1):
    max_bitlen = 128
    csn1List = [
        Bit('BA_USED', Pt=0, BitLen=1),
        Bit('DTX_USED', Pt=0, BitLen=1),
        Bit('RXLEV_FULL_SERVING_CELL', Pt=0, BitLen=6),
        Bit('3G_BA_USED', Pt=0, BitLen=1),
        Bit('MEAS_VALID', Pt=1, BitLen=1, Repr='hum', Dict=MeasVal_dict),
        Bit('RXLEV_SUB_SERVING_CELL', Pt=0, BitLen=6),
        Bit('spare', Pt=0, BitLen=1),
        Bit('RXQUAL_FULL_SERVING_CELL', Pt=0, BitLen=3),
        Bit('RXQUAL_SUB_SERVING_CELL', Pt=0, BitLen=3),
        {'111':Bit('padding', Pt=0, BitLen=102, Repr='hex'),
         '001':(NCELLReport(), Bit('undecoded', Pt=0, BitLen=85, Repr='hex')),
         '010':(NCELLReport(), NCELLReport(), \
                Bit('undecoded', Pt=0, BitLen=68, Repr='hex')),
         '011':(NCELLReport(), NCELLReport(), NCELLReport(), \
                Bit('undecoded', Pt=0, BitLen=51, Repr='hex')),
         '100':(NCELLReport(), NCELLReport(), NCELLReport(), NCELLReport(), \
                Bit('undecoded', Pt=0, BitLen=34, Repr='hex')),
         '101':(NCELLReport(), NCELLReport(), NCELLReport(), NCELLReport(), \
                NCELLReport(), Bit('undecoded', Pt=0, BitLen=17, Repr='hex')),
         '110':(NCELLReport(), NCELLReport(), NCELLReport(), NCELLReport(), \
                NCELLReport(), NCELLReport())}
        ]
        


###
# 44.018, section 10.5.2.21
# 1 to 4 bytes, when used in SI Type 4
# more globally between 1 and 8 bytes
class MobAlloc(Layer):
    constructorList = [
        Bit('MA_RFchan', ReprName='Mobile Allocation RF channel mask', \
            Pt=0, BitLen=8, Repr='bin')]
    
    def __init__(self, Len=1, **kwargs):
        # the standard initialization confines arg value if greater than 255
        Layer.__init__(self, **kwargs)
        # Now force the correct mask length and value
        if Len != 1:
            self.MA_RFchan.BitLen = Len*8
    
    def map(self, string='\0'):
        self.MA_RFchan.BitLen = len(string[:8])*8
        Layer.map(self, string)

###
# 44.018, section 10.5.2.25a: Packet channel description
# CSN1 style
MA_NUM_dict = {
    0 : 'MA NUMBER = 14',
    1 : 'MA NUMBER = 15'}
class PChanDesc(CSN1):
    csn1List = [
        Bit('spare', Pt=1, BitLen=5),
        Bit('TN', ReprName='Timeslot Number', BitLen=3, Repr='hum'),
        Bit('TSC', ReprName='Training Sequence Code', BitLen=3, Repr='hum'),
        {'0':{'0':(Bit('spare', BitLen=1), Bit('ARFCN', BitLen=10, Repr='hum')),
              '1':(Bit('spare', BitLen=1), Bit('MAIO', BitLen=6, Repr='hum'), \
                   Bit('MA_NUMBER_IND', BitLen=1, Repr='hum', Dict=MA_NUM_dict),
                   {'0':Bit('spare', BitLen=2), 
                    '1':Bit('CHANGE_MARK_1', BitLen=2, Repr='hum')})},
         '1':(Bit('MAIO', BitLen=6, Repr='hum'), \
              Bit('HSN', BitLen=6, Repr='hum'))}
        ]

###
# 44.018, section 10.5.2.30: request reference
class ReqRef(Layer):
    constructorList = [
        Int('RA', ReprName='Random Reference', Type='uint8'),
        Bit('T1prime', BitLen=5, Repr='hum'),
        Bit('T3', BitLen=6, Repr='hum'),
        Bit('T2', BitLen=5, Repr='hum'),
        ]

###
# 44.018, section 10.5.2.7c: classmark enquiry
class CmEnq(Layer):
    constructorList = [
        Bit('CmChange', ReprName='Classmark Change requested', Pt=0, BitLen=1, \
            Repr='hum'),
        Bit('UTRANCmChange', ReprName='UTRAN Classmark Change requested', \
            Pt=0, BitLen=3, Repr='hum'),
        Bit('CDMACmChange', ReprName='CDMA2000 Classmark Change requested', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('GERANIuCmChange', ReprName='GERAN Iu Mode Classmark Change resuested', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('spare', Pt=0, BitLen=2),
        ]
#
