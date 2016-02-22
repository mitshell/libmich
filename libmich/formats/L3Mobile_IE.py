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
# * File Name : formats/L3Mobile_IE.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# exporting
__all__ = [# 2G / 3G:
           'StrBCD', 'BCDNumber', 'BCDType_dict', 'NumPlan_dict',
           'LAI', 'RAI', 'ID', 'MSCm1', 'MSCm2', 'MSCm3', 'DRX', 'VoicePref',
           'SuppCodecs', 'PLMN', 'PLMNList', 'AuxState', 'NetName',
           'BearerCap', 'CCCap', 'AccessTechnoType_dict', 'MSNetCap', 'MSRACap',
           'PDPAddr', 'QoS', 'ProtID', 'ProtConfig', 'PacketFlowID',
           # Supplementary Services
           'SSversion',
           #'Facility', 'SS_Invoke', 'SS_ReturnResult', 'SS_ReturnError', 'SS_Reject',
           # LTE / EPC specifics:
           'IntegAlg_dict', 'CiphAlg_dict', 'NASKSI_dict', 'NASSecToEUTRA',
           'GUTI', 'EPSFeatSup', 'TAI', 'PartialTAIList', 'PartialTAIList0',
           'PartialTAIList1', 'PartialTAIList2', 'TAIList', 'UENetCap',
           'UESecCap', 'APN_AMBR',
           # SIM / USIM specifics:
           'AccessTechnology'
           ]

from struct import unpack
#
from libmich.core.element import Bit, Int, Str, Layer
from libmich.core.shtr import shtr
from libmich.core.IANA_dict import IANA_dict
from libmich.core.CSN1 import CSN1, BREAK, BREAK_LOOP
#
from .MCCMNC import MCC_dict, MNC_dict
from .PPP import *


# TS 24.008 defines L3 signalling for mobile networks
# section 10: IE coding
#
# describes mobile L3 signalling information element
# each L3 message composed of Information Element (IE)
# It's going to rock again!
#
# Take care with naming convention here
# as it is used to pull automatically IEs into L3 messages when parsing them


# generic BCR Str() element with encoding / decoding facilities
class StrBCD(Str):
    
    def decode(self):
        ret = []
        for c in self():
            # get 4 MSB, 4 LSB
            n1, n2 = ord(c)>>4, ord(c)&0xf
            if n2 < 0xA: ret.append( hex(n2)[2:] )
            else: break
            if n1 < 0xA: ret.append( hex(n1)[2:] )
            else: break
        return ''.join(ret)
    
    def encode(self, num='12345'):
        if len(num) % 2 == 1:
            num += 'F'
        ret = []
        for i in range(0, len(num), 2):
            try:
                ret.append( chr((int(num[i+1], 16)<<4) + int(num[i], 16)) )
            except ValueError:
                log(ERR, '(StrBCD) assigning invalid number')
        self < None
        self > ''.join(ret)
    
    def __repr__(self):
        if self.Repr == 'hum' \
        and (self.Pt is not None or self.Val is not None):
            return self.decode()
        else:
            return Str.__repr__(self)

# section 10.5.4.7
# BCD number
BCDType_dict = {
    0 : 'unknown',
    1 : 'international number',
    2 : 'national number',
    3 : 'network specific number',
    4 : 'dedicated access, short code',
    }
NumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN / telephony numbering plan (E.164 / E.163)',
    3 : 'data numbering plan (X.121)',
    4 : 'telex numbering plan (F.69)',
    8 : 'national numbering plan',
    9 : 'private numbering plan',
    11 : 'reserved for CTS',
    }

class BCDNumber(Layer):
    constructorList = [
        Bit('Ext', ReprName='Extension', Pt=1, BitLen=1, Repr='hum'),
        Bit('Type', ReprName='Type of number', Pt=1, BitLen=3, \
            Repr='hum', Dict=BCDType_dict),
        Bit('NumPlan', ReprName='Numbering plan identification', Pt=1, \
            BitLen=4, Repr='hum', Dict=NumPlan_dict),
        StrBCD('Num', Pt='\x21\x43\x65')
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        if 'Num' in kwargs:
            self.Num.encode(kwargs['Num'])


# section 10.5.1.13
# PLMN list
class PLMN(Layer):
    constructorList = [
        Bit('MCC2', Pt=0, BitLen=4, Repr='hum'),
        Bit('MCC1', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC3', Pt=0, BitLen=4, Repr='hum'),
        Bit('MCC3', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC2', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC1', Pt=0, BitLen=4, Repr='hum')]
    
    def __init__(self, MCCMNC='00101'):
        Layer.__init__(self)
        self.set_mcc(MCCMNC[:3])
        self.set_mnc(MCCMNC[3:])
    
    def get_mcc(self):
        return '{0}{1}{2}'.format(self.MCC1(), self.MCC2(), self.MCC3())
    
    def get_mnc(self):
        if self.MNC3() == 0b1111:
            return '{0}{1}'.format(self.MNC1(), self.MNC2())
        else:
            return '{0}{1}{2}'.format(self.MNC1(), self.MNC2(), self.MNC3())
    
    def get_mccmnc(self):
        if self.MNC3() == 0b1111:
            return '{0}{1}{2}{3}{4}'.format(self.MCC1(), self.MCC2(), self.MCC3(), 
                                            self.MNC1(), self.MNC2())
        else:
            return '{0}{1}{2}{3}{4}{5}'.format(self.MCC1(), self.MCC2(), self.MCC3(),
                                               self.MNC1(), self.MNC2(), self.MNC3())
    
    def set_mcc(self, MCC='001'):
        if not MCC.isdigit() or len(MCC) != 3:
            if self.dbg >= WNG:
                log(WNG, '(L3Mobile_IE - PLMN) trying to set invalid MCC: %s' \
                         % MCC)
            return
        self.MCC1 > int(MCC[0])
        self.MCC2 > int(MCC[1])
        self.MCC3 > int(MCC[2])
    
    def set_mnc(self, MNC='01'):
        if not MNC.isdigit() or len(MNC) not in (2, 3):
            if self.dbg >= WNG:
                log(WNG, '(L3Mobile_IE - PLMN) trying to set invalid MNC: %s' \
                         % MNC)
            return
        self.MNC1 > int(MNC[0])
        self.MNC2 > int(MNC[1])
        if len(MNC) == 2:
            self.MNC3 > 0b1111
        else:
            self.MNC3 > int(MNC[2])
    
    def set_mccmnc(self, MCCMNC='000101'):
        self.set_mcc(MCCMNC[:3])
        self.set_mnc(MCCMNC[3:])
    
    def __repr__(self):
        return '<[PLMN]: MCC: %s / MNC: %s>' % (self.get_mcc(), self.get_mnc())
    
    def interpret(self):
        # this makes use of large dictionnaries will many countries and MNO
        MCC, MNC = int(self.get_mcc()), int(self.get_mnc())
        MNC_str = MNC_dict[(MCC, MNC)][1] if (MCC, MNC) in MNC_dict.keys() else MNC
        MCC_str = MCC_dict[MCC][0] if MCC in MCC_dict.keys() else MCC
        return '<[PLMN]: %i:%s / %i:%s>' % (MCC, MCC_str, MNC, MNC_str)

class PLMNList(Layer):
    constructorList = [ ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self)
        self.add_plmn(*args)
    
    def add_plmn(self, *args):
        for arg in args:
            if arg.isdigit() and len(arg) in (5, 6):
                self.append( PLMN(arg) )
            elif isinstance(arg, PLMN):
                self.append( arg )
            elif isinstance(arg, (list, tuple)):
                # this is truly recursive :)
                for e in arg:
                    self.add_plmn(e)
    
    def add_PLMN(self, plmn=PLMN()):
        # this was the old method
        if isinstance(plmn, PLMN):
            self.append(plmn)
    
    def map(self, s=''):
        Layer.map(self, s)
        s = s[3:]
        while len(s) > 0:
            self.append( PLMN() )
            self[-1].map(s)
            s = s[3:]
    
    def interpret(self):
        return ''.join([str(plmn.interpret()) for plmn in self])

# section 10.5.1.3
# Local Area Identifier, LAC is MNO-specific
class LAI(Layer):
    constructorList = [
        PLMN(),
        Int('LAC', Pt=0, Type='uint16', Repr='hex')
        ]
    
    def __init__(self, MCCMNC='00101', LAC=0x0000):
        Layer.__init__(self)
        self.PLMN.set_mcc(MCCMNC[:3])
        self.PLMN.set_mnc(MCCMNC[3:])
        self.LAC > LAC
    
    def __repr__(self):
        return '<[LAI]: %s / LAC: 0x%.4x>' % (self.PLMN.__repr__(), self.LAC())

# section 10.5.5.15
# Routing Area Identifier (LAI + RAC)
class RAI(Layer):
    constructorList = [
        PLMN(),
        Int('LAC', Pt=0, Type='uint16', Repr='hex'),
        Int('RAC', Pt=0, Type='uint8', Repr='hex')
        ]
    
    def __init__(self, MCCMNC='00101', LAC=0x0000, RAC=0x00):
        Layer.__init__(self)
        self.PLMN.set_mcc(MCCMNC[:3])
        self.PLMN.set_mnc(MCCMNC[3:])
        self.LAC > LAC
        self.RAC > RAC
    
    def __repr__(self):
        return '<[RAI]: %s / LAC: 0x%.4x / RAC: 0x%.2x>' \
                % (self.PLMN.__repr__(), self.LAC(), self.RAC())


# section 10.5.1.4
# Mobile Identity
# + 23.401, 9.9.3.12: GUTI...
# TODO: handling of TMGI / MBMS identities
IDtype_dict = IANA_dict({
    0:'No Identity',
    1:'IMSI',
    2:'IMEI',
    3:'IMEISV',
    4:'TMSI',
    5:'TMGI',
    6:'ffu'})

class ID(Layer):
    constructorList = [
        Bit('digit1', Pt=0, BitLen=4, Repr='hum'),
        Bit('odd', Pt=1, BitLen=1, Repr='hum'),
        Bit('type', BitLen=3, Dict=IDtype_dict, Repr='hum')]
    
    def __init__(self, val='0', type='No Identity'):
        Layer.__init__(self)
        self.type > IDtype_dict[type]
        if type in ('IMSI', 'IMEI', 'IMEISV'):
            self.__handle_digits(val)
            if len(val)%2 == 0:
                self.odd > 0
        elif type == 'TMSI':
            self.digit1 > 0b1111
            self.odd > 0
            self.append(Str('tmsi', Pt=val[0:4], Len=4, Repr='hex'))
        elif self.type() > 4:
            self.append(Str('data', Pt=val, Repr='hex'))
    
    def map(self, s=''):
        Layer.map(self, s)
        # imsi, imei, imeisv
        if self.type() in (1,2,3):
            self.__handle_digits(''.join(['0']*(len(s[1:9])*2)))
            #if self.odd() == 0:
            #    self[-1].CallName = 'end'
        # tmsi
        elif self.type() == 4:
            self.append(Str('tmsi', Len=4, Repr='hex'))
        elif self.type() > 4:
            self.append(Str('data', Repr='hex'))
        Layer.map(self, s)
    
    def __handle_digits(self, digits=''):
        try:
            self.digit1 > int(digits[0])
        except ValueError:
            debug(self.dbg, 2, '(ID) non digit character: %s' % digits[0])
        ext, i = [], 2
        for d in digits[1:]:
            try:
                ext.append(Bit('digit%i'%i, Pt=int(d), BitLen=4, Repr='hum'))
            except ValueError:
                ext.append(Bit('digit%i'%i, Pt=0, BitLen=4, Repr='hum'))
            if len(ext) == 2:
                ext.reverse()
                self.extend(ext)
                ext = []
            i+=1
        if len(ext) == 1:
            ext.append(Bit('digit%i'%i, Pt=0b1111, BitLen=4, Repr='hum'))
            #ext.append(Bit('end', Pt=0b1111, BitLen=4, Repr='hum'))
            ext.reverse()
            self.extend(ext)
    
    def __repr__(self):
        t = self.type()
        # no id
        if t == 0:
            repr = IDtype_dict[t]
        # imsi, imei, imeisv
        elif self.type() in (1, 2, 3):
            repr = '%s:%s' % (IDtype_dict[t], self.get_bcd())
        # tmsi
        elif t == 4:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.tmsi))
        # not handled
        else:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.data))
        return '<[ID]: %s>' % repr
    
    def get_imsi(self):
        if self.type() == 1:
            return self.get_bcd()
        else:
            return ''
    
    def get_imei(self):
        if self.type() in (2, 3):
            return self.get_bcd()
        else:
            return ''
    
    def get_bcd(self):
        return ''.join([str(getattr(self, 'digit%s'%i)()) \
                        for i in range(1, len(self)*2+self.odd()-1)])
    
    def anon(self):
        # for IMSI and IMEI, clear some digits to anonymize identities 
        if self.type() in (1, 2, 3):
            if hasattr(self, 'digit8'):
                self.digit8 < None
                self.digit8 > 0
            if hasattr(self, 'digit9'):
                self.digit9 < None
                self.digit9 > 0
            if hasattr(self, 'digit10'):
                self.digit10 < None
                self.digit10 > 0
            if hasattr(self, 'digit11'):
                self.digit11 < None
                self.digit11 > 0
            if hasattr(self, 'digit12'):
                self.digit12 < None
                self.digit12 > 0

# section 10.5.1.5
# Mobile Station Classmark 1
Revision_level = {
    0:'Reserved for GSM phase 1',
    1:'GSM phase 2 MS',
    2:'MS supporting R99 or later',
    3:'FFU'
    }
RFclass_dict = {
    0:'class 1',
    1:'class 2',
    2:'class 3',
    3:'class 4',
    4:'class 5'
    }
class MSCm1(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('rev', Pt=1, BitLen=2, Repr='hum', Dict=Revision_level),
        Bit('ES', ReprName='Controlled early classmark sending', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('noA51', Pt=0, BitLen=1, Repr='hum'),
        Bit('RFclass', Pt=0, BitLen=3, Repr='hum', Dict=RFclass_dict)]

# SS screening indicator
# TS 24.080, section 3.7.1
SSscreen_dict = {
    0:'default value of phase 1',
    1:'capability of handling of ellipsis notation and phase 2 error handling',
    2:'ffu',
    3:'ffu'
    }

# section 10.5.1.6
# Mobile Station Classmark 2        
class MSCm2(Layer):
    constructorList = [
        Bit('spare1', Pt=0, BitLen=1),
        Bit('rev', Pt=1, BitLen=2, Repr='hum', Dict=Revision_level),
        Bit('ES', ReprName='Controlled early classmark sending', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('noA51', Pt=0, BitLen=1, Repr='hum'),
        Bit('RFclass', Pt=0, BitLen=3, Repr='hum', Dict=RFclass_dict),
        Bit('spare2', Pt=0, BitLen=1),
        Bit('PScap', Pt=0, BitLen=1, Repr='hum'),
        Bit('SSscreen', Pt=0, BitLen=2, Dict=SSscreen_dict, Repr='hum'),
        Bit('SMcap', Pt=0, BitLen=1, Repr='hum'),
        Bit('VBSnotif', Pt=0, BitLen=1, Repr='hum'),
        Bit('VGCSnotif', Pt=0, BitLen=1, Repr='hum'),
        Bit('Freqcap', Pt=0, BitLen=1, Repr='hum'),
        Bit('Classmark3', Pt=0, BitLen=1, Repr='hum'),
        Bit('spare3', Pt=0, BitLen=1),
        Bit('LCSVAcap', Pt=0, BitLen=1, Repr='hum'),
        Bit('UCS2', Pt=0, BitLen=1, Repr='hum'),
        Bit('SoLSA', Pt=0, BitLen=1, Repr='hum'),
        Bit('CMSP', ReprName='CM service prompt', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit('A53', Pt=0, BitLen=1, Repr='hum'),
        Bit('A52', Pt=0, BitLen=1, Repr='hum')]

# section 10.5.1.7
# Mobile Station Classmark 3
# CSN1' style
class A5bits(CSN1):
    csn1List = [
        Bit('A57', Pt=0, BitLen=1),
        Bit('A56', Pt=0, BitLen=1),
        Bit('A55', Pt=0, BitLen=1),
        Bit('A54', Pt=0, BitLen=1)
        ]

class RSupport(CSN1):
    csn1List = [
        Bit('RGSMBandAssociatedRadioCapability', Pt=0, BitLen=3),
        ]

class HSCSDMultiSlotCapability(CSN1):
    csn1List = [
        Bit('HSCSDMultiSlotClass', Pt=0, BitLen=5),
        ]

class MSMeasurementCapability(CSN1):
    csn1List = [
        Bit('SMS_VALUE', Pt=0, BitLen=4),
        Bit('SM_VALUE', Pt=0, BitLen=4),
        ]

class MSPositioningMethodCapability(CSN1):
    csn1List = [
        Bit('MSPositioningMethod', Pt=0, BitLen=5),
        ]

class ECSDMultiSlotCapability(CSN1):
    csn1List = [
        Bit('ECSDMultiSlotClass', Pt=0, BitLen=5),
        ]

class PSK8(CSN1):
    csn1List = [
        Bit('ModulationCapability', Pt=0, BitLen=1),
        {'0':BREAK, '1':Bit('PSK8RFPowerCapability1', Pt=0, BitLen=2)},
        {'0':BREAK, '1':Bit('PSK8RFPowerCapability2', Pt=0, BitLen=2)},
        ]

class SingleBandSupport(CSN1):
    csn1List = [
        Bit('GSMBand', Pt=0, BitLen=4),
        ]

class GERANIuModeCapabilities(CSN1):
    csn1List = [
        Bit('Length', Pt=0, BitLen=4),
        # Rel.6 addition:
        Bit('FLOIuCapability', Pt=0, BitLen=1),
        Bit('spare', Pt=0)
        ]
    def __init__(self, **kwargs):
        CSN1.__init__(self, **kwargs)
        self.csn1List[2].BitLen = self.csn1List[0]
        self.csn1List[2].BitLenFunc = lambda l: l()

class MSCm3(CSN1):
    csn1List = [
        Bit('spare', Pt=0, BitLen=1),
        {'000':A5bits(),
         '101':(A5bits(), \
                Bit('AssociatedRadioCapability2', Pt=0, BitLen=4), \
                Bit('AssociatedRadioCapability1', Pt=0, BitLen=4)),
         '110':(A5bits(), \
                Bit('AssociatedRadioCapability2', Pt=0, BitLen=4), \
                Bit('AssociatedRadioCapability1', Pt=0, BitLen=4)),
         '001':(A5bits(), \
                Bit('spare', Pt=0, BitLen=4), \
                Bit('AssociatedRadioCapability1', Pt=0, BitLen=4)),
         '010':(A5bits(), \
                Bit('spare', Pt=0, BitLen=4), \
                Bit('AssociatedRadioCapability1', Pt=0, BitLen=4)),
         '100':(A5bits(), \
                Bit('spare', Pt=0, BitLen=4), \
                Bit('AssociatedRadioCapability1', Pt=0, BitLen=4))},
        {'0':BREAK, '1':RSupport()},
        {'0':BREAK, '1':HSCSDMultiSlotCapability()},
        Bit('UCS2treatment', Pt=0, BitLen=1),
        Bit('ExtendedMeasurementCapability', Pt=0, BitLen=1),
        {'0':BREAK, '1':MSMeasurementCapability()},
        {'0':BREAK, '1':MSPositioningMethodCapability()},
        {'0':BREAK, '1':ECSDMultiSlotCapability()},
        {'0':BREAK, '1':PSK8()},
        {'0':BREAK, '1':(Bit('GSM400BandsSupported', Pt=1, BitLen=2),
                        Bit('GSM400AssociatedRadioCapability', Pt=0, BitLen=4))},
        {'0':BREAK, '1':Bit('GSM850AssociatedRadioCapability', Pt=0, BitLen=4)},
        {'0':BREAK, '1':Bit('GSM1900AssociatedRadioCapability', Pt=0, BitLen=4)},
        Bit('UMTSFDDRadioAccessTechnologyCapability', Pt=0, BitLen=1),
        Bit('UMTS384McpsTDDRadioAccessTechnologyCapability', Pt=0, BitLen=1),
        Bit('CDMA2000RadioAccessTechnologyCapability', Pt=0, BitLen=1),
        {'0':BREAK, 
         '1':(Bit('DTMGPRSMultiSlotClass', Pt=0, BitLen=2),
              Bit('SingleSlotDTM', Pt=0, BitLen=1),
              {'0':BREAK, '1':Bit('DTMEGPRSMultiSlotClass', Pt=0, BitLen=2)})},
        # Rel.4:
        {'0':BREAK, '1':SingleBandSupport()},
        {'0':BREAK, '1':Bit('GSM750AssociatedRadioCapability', Pt=0, BitLen=4)},
        Bit('UMTS128McpsTDDRadioAccessTechnologyCapability', Pt=0, BitLen=1),
        Bit('GERANFeaturePackage1', Pt=0, BitLen=1),
        {'0':BREAK, 
         '1':(Bit('ExtendedDTMGPRSMultiSlotClass', Pt=0, BitLen=2),
              Bit('ExtendedDTMEGPRSMultiSlotClass', Pt=0, BitLen=2))},
        # Rel.5:
        {'0':BREAK, '1':Bit('HighMultislotCapability', Pt=0, BitLen=2)},
        {'0':BREAK, '1':GERANIuModeCapabilities()},
        Bit('GERANFeaturePackage2', Pt=0, BitLen=1),
        Bit('GMSKMultislotPowerProfile', Pt=0, BitLen=2),
        Bit('PSK8MultislotPowerProfile', Pt=0, BitLen=2),
        # Rel.6:
        {'0':BREAK, '1':(Bit('TGSM400BandsSupported', Pt=1, BitLen=2),
                        Bit('TGSM400AssociatedRadioCapability', Pt=0, BitLen=4))},
        Bit('unused', Pt=0, BitLen=1),
        Bit('DownlinkAdvancedReceiverPerformance', Pt=0, BitLen=2),
        Bit('DTMEnhancementsCapability', Pt=0, BitLen=1),
        {'0':BREAK,
         '1':(Bit('DTMGPRSHighMultiSlotClass', Pt=0, BitLen=3),
              Bit('OffsetRequired', Pt=0, BitLen=1),
              {'0':BREAK, '1':Bit('DTMEGPRSHighMultiSlotClass', Pt=0, BitLen=3)})},
        Bit('RepeatedACCHCapability', Pt=0, BitLen=1),
        # Rel.7:
        {'0':BREAK, '1':Bit('GSM710AssociatedRadioCapability', Pt=0, BitLen=4)},
        {'0':BREAK, '1':Bit('TGSM810AssociatedRadioCapability', Pt=0, BitLen=4)},
        Bit('CipheringModeSettingCapability', Pt=0, BitLen=1),
        Bit('AdditionalPositioningCapabilities', Pt=0, BitLen=1),
        # Rel.8:
        Bit('EUTRAFDDSupport', Pt=0, BitLen=1),
        Bit('EUTRATDDSupport', Pt=0, BitLen=1),
        Bit('EUTRAMeasurementAndReportingSupport', Pt=0, BitLen=1),
        Bit('PriorityBasedReselectionSupport', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=1),
        # Rel.9:
        Bit('UTRACSGCellsReporting', Pt=0, BitLen=1),
        Bit('VAMOSLevel', Pt=0, BitLen=2),
        # Rel.10:
        Bit('TIGHTERCapability', Pt=0, BitLen=2),
        Bit('SelectiveCipheringDownlinkSACCH', Pt=0, BitLen=1),
        # Rel.11:
        Bit('CStoPSSRVCCfromGERANtoUTRA', Pt=0, BitLen=2),
        Bit('CStoPSSRVCCfromGERANtoEUTRA', Pt=0, BitLen=2),
        Bit('GERANNetworkSharing', Pt=0, BitLen=1),
        Bit('EUTRAWidebandRSRQmeasurements', Pt=0, BitLen=1),
        # Rel.12:
        Bit('ERBand', Pt=0, BitLen=1),
        Bit('UTRAMultipleFrequencyBandInd', Pt=0, BitLen=1),
        Bit('EUTRAMultipleFrequencyBandInd', Pt=0, BitLen=1),
        Bit('Extended TSCSetCapability', Pt=0, BitLen=1),
        Bit('ExtendedEARFCNValueRange', Pt=0, BitLen=1)
        ]

# section 10.5.3.5a
# Network name
CodingScheme_dict = {
    0 : 'GSM 7 bit default alphabet',
    1 : 'UCS2 (16 bit)'
    }    
class NetName(Layer):
    constructorList = [
        Bit('ext', Pt=1, BitLen=1, Repr='hum'),
        Bit('coding', Pt=0, BitLen=3, Repr='hum', Dict=CodingScheme_dict),
        Bit('AddCI', Pt=0, BitLen=1, Repr='hum'),
        Bit('spare_bits', Pt=0, BitLen=3, Repr='hum'),
        Str('text', Pt='', Repr='hex')
        ]

# section 10.5.4.4
# Auxiliary states
AuxHold_dict = {
    0:'idle',
    1:'hold request',
    2:'call held',
    3:'retrieve request'}
AuxMPTY_dict = {
    0:'idle',
    1:'MPTY request',
    2:'call in MPTY',
    3:'split request'}

class AuxState(Layer):
    constructorList = [
        Bit('ext', Pt=1, BitLen=1),
        Bit('spare', Pt=0, BitLen=3),
        Bit('hold', Pt=0, BitLen=2, Repr='hum', Dict=AuxHold_dict),
        Bit('MPTY', Pt=0, BitLen=2, Repr='hum', Dict=AuxMPTY_dict)]

# section 10.5.4.5
# Bearer capability (welcome to 3gpp...)
# TODO: handle the complete IE
Chan_dict = {
    0:'reserved',
    1:'full rate support only MS',
    2:'dual rate support MS/half rate preferred',
    3:'dual rate support MS/full rate preferred'}
TransferMode_dict = {
    0:'circuit',
    1:'packet'}
TransferCap_dict = {
    0:'speech',
    1:'unrestricted digital information',
    2:'3.1 kHz audio, ex PLMN',
    3:'facsimile group 3',
    5:'Other ITC (See Octet 5a)',
    7:'reserved, to be used in the network.'}

class BearerCap(Layer):
    constructorList = [
        Bit('ext', Pt=0, BitLen=1, Repr='hum'),
        Bit('chan', ReprName='Radio channel requirement', Pt=1, \
            BitLen=2, Repr='hum'),
        Bit('coding', Pt=0, BitLen=1, Repr='hum'),
        Bit('mode', Pt=0, BitLen=1, Repr='hum', Dict=TransferMode_dict),
        Bit('capability', Pt=0, BitLen=3, Repr='hum', Dict=TransferCap_dict),
        Str('undecoded_information', Pt='', Repr='hex')]
        
        
class CCCap(Layer):
    constructorList = [
        Bit('maxsupport', ReprName='Maximum supported bearers', Pt=1, \
            BitLen=4, Repr='hum'),
        Bit('MCAT', ReprName='Multimedia CAT support', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit('ENICM', ReprName='Enhanced net-initiated in-call modif support', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('PCP', ReprName='Prolonged clearing procedure support', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('DTMF', ReprName='DTMF support', Pt=0, BitLen=1, Repr='hum'),
        Bit('spare', Pt=0, BitLen=4),
        Bit('maxspeech', ReprName='Maximum speech bearers', Pt=1, \
            BitLen=4, Repr='hum')]

# TS 24.008, section 10.5.5.12a
AccessTechnoType_dict = {
    0 : 'GSM P',
    1 : 'GSM E  --note that GSM E covers GSM P',
    2 : 'GSM R  --note that GSM R covers GSM E and GSM P',
    3 : 'GSM 1800',
    4 : 'GSM 1900',
    5 : 'GSM 450',
    6 : 'GSM 480',
    7 : 'GSM 850',
    8 : 'GSM 750',
    9 : 'GSM T 380',
    10 : 'GSM T 410',
    11 : 'unused',
    12 : 'GSM 710',
    13 : 'GSM T 810',
    }

# QoS : TS 24.008, section 10.5.6.5
ReliabClass_dict = {
    0 : 'subscribed reliability class',
    1 : 'unused; interpreted as unack GTP, ack LLC and RLC, protected data',
    2 : 'unack GTP, ack LLC and RLC, protected data',
    3 : 'unack GTP and LLC, ack RLC, protected data',
    4 : 'unack GTP, LLC and RLC, protected data',
    5 : 'unack GTP, LLC and RLC, unprotected data',
    6 : 'unack GTP and RLC, ack LLC, protected data',
    7 : 'reserved',
    }
DelayClass_dict = {
    0 : 'subscribed delay class',
    1 : 'delay class 1',
    2 : 'delay class 2',
    3 : 'delay class 3',
    4 : 'delay class 4 (best effort)',
    5 : 'delay class 4 (best effort)',
    6 : 'delay class 4 (best effort)',
    7 : 'reserved',
    }
PrecedClass_dict = {
    0 : 'subscribed precedence',
    1 : 'high priority',
    2 : 'normal priority',
    3 : 'low priority',
    4 : 'normal priority',
    5 : 'normal priority',
    6 : 'normal priority',
    7 : 'reserved',
    }
PeakTP_dict = {
    0 : 'subscribed peak throughput',
    1 : 'Up to 1 000 octet/s',
    2 : 'Up to 2 000 octet/s',
    3 : 'Up to 4 000 octet/s',
    4 : 'Up to 8 000 octet/s',
    5 : 'Up to 16 000 octet/s',
    6 : 'Up to 32 000 octet/s',
    7 : 'Up to 64 000 octet/s',
    8 : 'Up to 128 000 octet/s',
    9 : 'Up to 256 000 octet/s',
    }
# TODO: more dict to implement
#
class QoS(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=2, Repr='hex'),
        Bit('DelayClass', Pt=0, BitLen=3, Dict=DelayClass_dict, Repr='hum'),
        Bit('ReliabilityClass', Pt=0, BitLen=3, Dict=ReliabClass_dict, Repr='hum'), # 1
        Bit('PeakThroughput', Pt=0, BitLen=4, Dict=PeakTP_dict, Repr='hum'),
        Bit('spare', Pt=0, BitLen=1, Repr='hex'),
        Bit('PrecedenceClass', Pt=0, BitLen=3, Dict=PrecedClass_dict, Repr='hum'), # 2
        Bit('spare', Pt=0, BitLen=3, Repr='hex'),
        Bit('MeanThroughput', Pt=0, BitLen=5), # 3
        Bit('TrafficClass', Pt=0, BitLen=3),
        Bit('DeliveryOrder', Pt=0, BitLen=2),
        Bit('DeliveryOfErrSDU', Pt=0, BitLen=3), # 4
        Int('MaxSDUSize', Pt=0, Type='uint8'),
        Int('MaxULBitRate', Pt=0, Type='uint8'),
        Int('MaxDLBitRate', Pt=0, Type='uint8'), # 7
        Bit('ResidualBitErrRate', Pt=0, BitLen=4),
        Bit('SDUErrRatio', Pt=0, BitLen=4), # 8
        Bit('TransferDelay', Pt=0, BitLen=6),
        Bit('TrafficHandlingPrio', Pt=0, BitLen=2), # 9
        Int('GuarantULBitRate', Pt=0, Type='uint8'),
        Int('GuarantDLBitRate', Pt=0, Type='uint8'), # 11
        Bit('spare', Pt=0, BitLen=3, Repr='hex'),
        Bit('SignallingInd', Pt=0, BitLen=1),
        Bit('SourceStatDesc', Pt=0, BitLen=4), # 12
        Int('MaxDLBitRateExt', Pt=0, Type='uint8'),
        Int('GuarantDLBitRateExt', Pt=0, Type='uint8'),
        Int('MaxULBitRateExt', Pt=0, Type='uint8'),
        Int('GuarantULBitRateExt', Pt=0, Type='uint8'), # 16
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # for the last 4 integer values: if not explicitly provided,
        # make them transparent
        if 'MaxDLBitRateExt' not in kwargs \
        and 'GuarantDLBitRateExt' not in kwargs:
            for i in range(-4, 0):
                self[i].Trans = True
        if 'MaxULBitRateExt' not in kwargs \
        and 'GuarantULBitRateExt' not in kwargs:
            for i in range(-2, 0):
                self[i].Trans = True
    
    # rewrite map() in order to remove up to the 4 last Int() fields,
    # which are sometimes not provided... sometimes...
    def map(self, s=''):
        s_len = len(s)
        if s_len < 16:
            self[-1].Trans = True
        if s_len < 15:
            self[-2].Trans = True
        if s_len < 14:
            self[-3].Trans = True
        if s_len < 13:
            self[-4].Trans = True
        if s_len < 12:
            self[-5].Trans = True
            self[-6].Trans = True
            self[-7].Trans = True
        Layer.map(self, s)

#
# PDP address and type: 24.008, 10.5.6.4
PDPTypeOrga_dict = {
    0 : 'ETSI allocated',
    1 : 'IETF allocated',
    15 : 'Empty PDP type',
    }
PDPTypeNum0_dict = {
    0 : 'reserved',
    1 : 'PPP',
    }
PDPTypeNum1_dict = {
    33 : 'IPv4',
    87 : 'IPv6',
    141 : 'IPv4v6',
    }
class PDPAddr(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=4, Repr='hex'),
        Bit('PDPTypeOrga', Pt=0, BitLen=4, Dict=PDPTypeOrga_dict, Repr='hum'),
        Int('PDPType', Pt=33, Type='uint8', Dict=PDPTypeNum1_dict),
        Str('Addr', Repr='ipv4'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.Addr.Len = self.PDPType
        self.Addr.LenFunc = lambda t: {33:4, 87:16, 141:20}[t()] \
                                      if t() in (33, 87, 141) else 0
#
# Protocol configuration options: 24.008, 10.5.6.3
# crazy !
# LCP, PAP, CHAP and IPCP: refer to RFC 3232
ProtID_dict = {
    0x0001 : 'P-CSCF IPv6 Address Request',
    0x0002 : 'IM CN Subsystem Signaling Flag',
    0x0003 : 'DNS Server IPv6 Address Request',
    0x0004 : 'Policy Control rejection code',
    0x0005 : 'Selected Bearer Control Mode',
    0x0006 : 'Reserved',
    0x0007 : 'DSMIPv6 Home Agent Address',
    0x0008 : 'DSMIPv6 Home Network Prefix',
    0x0009 : 'DSMIPv6 IPv4 Home Agent Address',
    0x000A : 'IP address allocation via NAS signalling',
    0x000B : 'Reserved',
    0x000C : 'P-CSCF IPv4 Address',
    0x000D : 'DNS server IPv4 address request',
    0x000E : 'MSISDN Request',
    0xC021 : 'LCP',
    0xC023 : 'PAP',
    0xC223 : 'CHAP',
    0x8021 : 'IPCP'
    }
class ProtID(Layer):
    constructorList = [
        Int('ID', Pt=0, Type='uint16', Dict=ProtID_dict, Repr='hum'),
        Int('length', Pt=0, Type='uint8'),
        Str('content', Pt=''), #, Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.content
        self.length.PtFunc = lambda c: len(c)
        self.content.Len = self.length
        self.content.LenFunc = lambda l: l()
    
    def map(self, s=''):
        if s:
            Layer.map(self, s)
            c = self.content()
            if c and self.ID() in (0xC021, 0xC023, 0xC223, 0x8021):
                ncp = NCP()
                if self.ID() == 0x8021:
                    ncp.map(c, ipcp=True)
                else:
                    ncp.map(c, ipcp=False)
                self.content.Val = None
                self.content.Pt = ncp

#
class ProtConfig(Layer):
    constructorList = [
        Bit('ext', Pt=1, BitLen=1),
        Bit('spare', Pt=0, BitLen=4, Repr='hex'),
        Bit('ConfigProt', Pt=0, BitLen=3, Dict={0:'PPP with IP PDP'}, Repr='hum'),
        ]
    # when mapping a buffer, append much ProtID() as needed 
    def map(self, s=''):
        if s:
            Layer.map(self, s)
            s = s[1:]
            while len(s) >= 3:
                length = ord(s[2:3])
                if len(s) >= 3+length:
                    self.append(ProtID())
                    self[-1].map(s)
                    s = s[len(self[-1]):]
                else:
                    break
#
# 24.008, 10.5.6.11
PFlowID_dict = IANA_dict({
    0 : 'Best Effort',
    1 : 'Signalling',
    2 : 'SMS',
    3 : 'TOM8',
    4 : 'reserved',
    7 : 'reserved',
    8 : ' dynamically assigned',
    127 : ' dynamically assigned',
    })
class PacketFlowID(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('PFlowID', Pt=0, BitLen=7, Dict=PFlowID_dict, Repr='hum'),
        ]

#
# 24.008, 10.5.5.6
DRXS1_dict = {
    0: 'unspecified',
    6: '32',
    7: '64',
    8: '128',
    9: '256',
    }
class DRX(Layer):
    constructorList = [
        Int('SPLIT_PG_CYCLE_CODE', Pt=0, Type='uint8'),
        Bit('DRX_S1mode', Pt=0, BitLen=4, Repr='hum', Dict=DRXS1_dict),
        Bit('SPLIT_on_CCCH', Pt=0, BitLen=1, Repr='hum'),
        Bit('nonDRX_timer', Pt=0, BitLen=3, Repr='bin')
        ]

#
# 24.008, 10.5.5.28, Voice domain preference
VoiceDom_dict = {
    0:'CS Voice only',
    1:'IMS PS Voice only',
    2:'CS voice preferred, IMS PS Voice as secondary',
    3:'IMS PS voice preferred, CS Voice as secondary'
    }
class VoicePref(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=5, Repr='bin'),
        Bit('UEusage', Pt=0, BitLen=1, Repr='hum',
            Dict={0:'voice centric', 1:'data centric'}),
        Bit('VoiceDom', ReprName='Voice domain preference for E-UTRAN', Pt=0,
            BitLen=2, Repr='hum', Dict=VoiceDom_dict)
        ]

#
# 24.008, 10.5.4.32, Supported codec list
CodecSysID_dict = {
    0:'GSM',
    4:'UMTS'
    }
class CodecBitmap(Layer):
    constructorList = [
        Bit('TDMA_EFR', Pt=0, BitLen=1, Repr='hum'),
        Bit('UMTS_AMR2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UMTS_AMR', Pt=0, BitLen=1, Repr='hum'),
        Bit('HR_AMR', Pt=0, BitLen=1, Repr='hum'),
        Bit('FR_AMR', Pt=0, BitLen=1, Repr='hum'),
        Bit('GSM_EFR', Pt=0, BitLen=1, Repr='hum'),
        Bit('GSM_HR', Pt=0, BitLen=1, Repr='hum'),
        Bit('GSM_FR', Pt=0, BitLen=1, Repr='hum'),
        Bit('reserved', Pt=0, BitLen=1, Repr='hum'),
        Bit('reserved', Pt=0, BitLen=1, Repr='hum'),
        Bit('OHR_AMR-WB', Pt=0, BitLen=1, Repr='hum'),
        Bit('OFR_AMR-WB', Pt=0, BitLen=1, Repr='hum'),
        Bit('OHR_AMR', Pt=0, BitLen=1, Repr='hum'),
        Bit('UMTS_AMR-WB', Pt=0, BitLen=1, Repr='hum'),
        Bit('FR_AMR-WB', Pt=0, BitLen=1, Repr='hum'),
        Bit('PDC_EFR', Pt=0, BitLen=1, Repr='hum'),
        ]
    
    def map(self, buf=''):
        if len(buf) == 1:
            for i in range(8, 16):
                self[i].Trans = True
        Layer.map(buf)

class CodecSysID(Layer):
    constructorList = [
        Int('SysID', Pt=0, Type='uint8', Dict=CodecSysID_dict),
        Int('BMLen', Type='uint8'),
        CodecBitmap()
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.BMLen.Pt = self[2]
        self.BMLen.PtFunc = lambda x: len(x)
    
    def map(self, buf=''):
        self[0:2].map(buf)
        Len = self.BMLen()
        if Len == 1:
            self[2].map(buf[2:3])
        elif Len == 2:
            self[2].map(buf[2:4])
        elif Len > 2:
            self[2].map(buf[2:4])
            self.append(Str('extra', Val=buf[4:2+Len], Len=Len-2, Repr='hex'))

class SuppCodecs(Layer):
    constructorList = [
        CodecSysID()
        ]
    
    def map(self, buf=''):
        self[0].map(buf)
        buf = buf[len(self[0]):]
        while buf:
            self.append( CodecSysID() )
            self[-1].map(buf)
            buf = buf[len(self[-1]):]

#
# 24.008, 10.5.5.12, MS network capability
class ExtGEABits(CSN1):
    csn1List = [
        Bit('GEA2', Pt=0, BitLen=1),
        Bit('GEA3', Pt=0, BitLen=1),
        Bit('GEA4', Pt=0, BitLen=1),
        Bit('GEA5', Pt=0, BitLen=1),
        Bit('GEA6', Pt=0, BitLen=1),
        Bit('GEA7', Pt=0, BitLen=1),
        ]
class MSNetCap(CSN1):
    csn1List = [
        Bit('GEA1', Pt=1, BitLen=1),
        Bit('SMCapDediChan', Pt=0, BitLen=1),
        Bit('SMCapGPRSChan', Pt=0, BitLen=1),
        Bit('UCS2', Pt=0, BitLen=1),
        Bit('SSScreeningInd', Pt=0, BitLen=2),
        Bit('SoLSACap', Pt=0, BitLen=1),
        Bit('RevLevelInd', Pt=0, BitLen=1),
        Bit('PFCFeatMode', Pt=0, BitLen=1),
        ExtGEABits(),
        Bit('LCSVACap', Pt=0, BitLen=1),
        Bit('PSinterRATHOfromGERANtoUTRANIuModeCap', Pt=0, BitLen=1),
        Bit('PSinterRATHOfromGERANtoEUTRANS1ModeCap', Pt=0, BitLen=1),
        Bit('EMMCombProcCap', Pt=0, BitLen=1),
        Bit('ISR', Pt=0, BitLen=1),
        Bit('SRVCCtoGERANUTRANCap', Pt=0, BitLen=1),
        Bit('EPCCap', Pt=0, BitLen=1),
        Bit('NFCap', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=57),
        ]
    def map(self, s=''):
        buflen = len(s)*8
        if buflen > 23:
            # length adaption for the spare field
            self.csn1List[-1].BitLen = buflen-23
        CSN1.map(self, s)
#
# 24.008, 10.5.5.12a, MS Radio Access Capability
class MSRAA5bits(CSN1):
    csn1List = [
        Bit('A51', Pt=0, BitLen=1),
        Bit('A52', Pt=0, BitLen=1),
        Bit('A53', Pt=0, BitLen=1),
        Bit('A54', Pt=0, BitLen=1),
        Bit('A55', Pt=0, BitLen=1),
        Bit('A56', Pt=0, BitLen=1),
        Bit('A57', Pt=0, BitLen=1),
        ]
#
class MultislotCap(CSN1):
    csn1List = [
        {'0':BREAK, '1':Bit('HSCSDMultislotClass', Pt=0, BitLen=5)},
        {'0':BREAK, '1':(Bit('GPRSMultislotClass', Pt=0, BitLen=5),
                         Bit('GPRSExtDynamicAllocCap', Pt=0, BitLen=1))},
        {'0':BREAK, '1':(Bit('SMS_VALUE', Pt=0, BitLen=4),
                         Bit('SM_VALUE', Pt=0, BitLen=4))},
        {'0':BREAK, '1':Bit('ECSDMultislotClass', Pt=0, BitLen=5)},
        {'0':BREAK, '1':(Bit('EGPRSMultislotClass', Pt=0, BitLen=5),
                         Bit('EGPRSExtDynamicAllocCap', Pt=0, BitLen=1))},
        {'0':BREAK, '1':(Bit('DTMGPRSMultislotClass', Pt=0, BitLen=2),
                         Bit('SingleslotDTM', Pt=0, BitLen=1),
                         {'0':BREAK,
                          '1':Bit('DTMEGPRSMultislotClass', Pt=0, BitLen=2)})},
        ]
#
class GERANIuModeCap(CSN1):
    csn1List = [
        Bit('Length', Pt=4, BitLen=4, Repr='hum'),
        Bit('FLOIuCap', Pt=0, BitLen=1),
        Bit('spare', Pt=0, BitLen=3)
        ]
    def __init__(self, *args, **kwargs):
        CSN1.__init__(self, *args, **kwargs)
        # this triggers infinite loop... commenting it
        #self.csn1List[0].Pt = self.csn1List[2]
        #self.csn1List[0].PtFunc = lambda s: 4+self.csn1List[1].bit_len()+self.csn1List[2].bit_len()
        self.csn1List[1].BitLen = self.csn1List[0]
        self.csn1List[1].BitLenFunc = lambda l: 1 if l()>4 else 0
        self.csn1List[2].BitLen = self.csn1List[0]
        self.csn1List[2].BitLenFunc = lambda l: l()-5 if l()>5 else 0
#
class EnhancedFlexibleTimeslotAssign(CSN1):
    csn1List = [
        {'0':BREAK, '1':Bit('AlternativeEFTAMultislotClass', Pt=0, BitLen=4)}
        ]
#
class MSRAContent(CSN1):
    csn1List = [
        Bit('RFPowerCap', Pt=0, BitLen=3),
        {'0':BREAK, '1':MSRAA5bits()},
        Bit('ESInd', Pt=0, BitLen=1),
        Bit('PS', Pt=0, BitLen=1),
        Bit('VGCS', Pt=0, BitLen=1),
        Bit('VBS', Pt=0, BitLen=1),
        {'0':BREAK, '1':MultislotCap()},
        {'0':BREAK, '1':Bit('8PSKPowerCap', Pt=0, BitLen=2)},
        Bit('COMPACTInterferenceMeasCap', Pt=0, BitLen=1),
        Bit('RevLevelInd', Pt=0, BitLen=1),
        Bit('UMTSFDDRATCap', Pt=0, BitLen=1),
        Bit('UMTS3.84McpsTDDRATCap', Pt=0, BitLen=1),
        Bit('CDMA2000RATCap', Pt=0, BitLen=1),
        Bit('UMTS1.28McpsTDDRATCap', Pt=0, BitLen=1),
        Bit('GERANFeatPkg1', Pt=0, BitLen=1),
        {'0':BREAK, '1':(Bit('ExtDTMGPRSMultislotClass', Pt=0, BitLen=2),
                         Bit('ExtDTMEGPRSMultislotClass', Pt=0, BitLen=2))},
        Bit('ModlationBasedMultislotClass', Pt=0, BitLen=1),
        {'0':BREAK, '1':Bit('HighMultislotCap', Pt=0, BitLen=2)},
        {'0':BREAK, '1':GERANIuModeCap()},
        Bit('GMSKMultislotPowerProfile', Pt=0, BitLen=2),
        Bit('8PSKMultislotPowerProfile', Pt=0, BitLen=2),
        Bit('MultipleTBFCap', Pt=0, BitLen=1),
        Bit('DLAdvancedReceiverPerf', Pt=0, BitLen=2),
        Bit('ExtRLCMACCtrlMsgSegmentCap', Pt=0, BitLen=1),
        Bit('DTMEnhancementsCap', Pt=0, BitLen=1),
        {'0':BREAK, '1':(Bit('DTMGPRSHighMultislotClass', Pt=0, BitLen=3),
                         {'0':BREAK, '1':Bit('DTMEGPRSHighMultislotClass', Pt=0, 
                                             BitLen=3)})},
        Bit('PSHOCap', Pt=0, BitLen=1),
        Bit('DTMHOCap', Pt=0, BitLen=1),
        {'0':BREAK, '1':(Bit('MultislotCapReducDLDualCarrier', Pt=0, BitLen=3),
                         Bit('DLDualCarrierDTMCap', Pt=0,BitLen=1))},
        Bit('FlexibleTimeslotAssign', Pt=0, BitLen=1),
        Bit('GANPSHOCap', Pt=0, BitLen=1),
        Bit('RLCNonPersistentMode', Pt=0, BitLen=1),
        Bit('ReducedLatencyCap', Pt=0, BitLen=1),
        Bit('UplinkEGPRS2', Pt=0, BitLen=2),
        Bit('DownlinkEGPRS2', Pt=0, BitLen=2),
        Bit('EUTRAFDD', Pt=0, BitLen=1),
        Bit('EUTRATDD', Pt=0, BitLen=1),
        Bit('GERANtoEUTRAinGERANPktTransMode', Pt=0, BitLen=2),
        Bit('PriorityBasedReselection', Pt=0, BitLen=1),
        EnhancedFlexibleTimeslotAssign(),
        Bit('UpLayerPDUStartCapRLCUM', Pt=0, BitLen=1),
        Bit('EMSTCap', Pt=0, BitLen=1),
        Bit('MTTICap', Pt=0, BitLen=1),
        ]
#
class MSRAAccessCap(CSN1):
    csn1List = [
        Bit('Length', Pt=0, BitLen=7, Repr='hum'),
        MSRAContent(),
        #Bit('spare', Pt=0, BitLen=0)
        ]
    def __init__(self, *args, **kwargs):
        CSN1.__init__(self, *args, **kwargs)
        self.csn1List[0].Pt = self.csn1List[1]
        self.csn1List[0].PtFunc = lambda c: c.bit_len()
    #
    def map(self, s='', byte_offset=0):
        # WNG: it is clear from this crappy structure that 
        # some network-side CSN1 parser will be buggy right here !
        CSN1.map(self, s, byte_offset)
        total_len, cont_len = self[0](), self[1].bit_len()
        if total_len < cont_len:
            # in case the AccessCap is too long, remove IE 1 per 1
            while self[1].bit_len() > total_len:
                self[1].remove(self[1][-1])
            # in case its becoming too short, add spare bits
            if self[1].bit_len() < total_len:
                self.append(Bit('spare', Pt=0, BitLen=0))
                self[-1].BitLen = total_len - self[1].bit_len()
        #
        elif total_len > cont_len:
            self.append(Bit('spare', Pt=0, BitLen=0))
            self[-1].BitLen = total_len - cont_len
#
class MSRAAddTech(CSN1):
    csn1List = [
        Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum',
            Dict=AccessTechnoType_dict),
        Bit('GMSKPowerClass', Pt=0, BitLen=3),
        Bit('8PSKPowerClass', Pt=0, BitLen=2),
        ]
class MSRAAdd(CSN1):
    csn1List = [
        Bit('Length', Pt=0, BitLen=7, Repr='hum'),
        ]
    def map(self, s='', byte_offset=0):
        CSN1.map(self, s, byte_offset)
        l = self[0]()
        bufsh = shtr(s)<<7
        while l >= 10:
            # add as much as RAT to fill in the indicated length
            # and possibly 1 to 4 spare bits...
            # crappy CSN1 !
            if bufsh.left_val(1) == 0:
                # condition for having nothing...
                self.append(Bit(self.cond_name, Val=0, BitLen=1))
                bufsh=bufsh<<1
                l-=1
            else:
                self.append(Bit(self.cond_name, Val=1, BitLen=1))
                bufsh=bufsh<<1
                l-=1
                for ie in MSRAAddTech.csn1List:
                    self.append(ie.clone())
                    self[-1].map(bufsh)
                    bufsh=bufsh<<self[-1].bit_len()
                l-=9
        if l > 0:
            # some more spare bits ?
            self.append(Bit(self.pad_name, BitLen=l))
            self[-1].map(bufsh)
# The following is a very bad / unefficient implementation
# however, with such a CSN1 syntax, hard to do better
class MSRACap(CSN1):
    csn1List = [
        Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum',
            Dict=AccessTechnoType_dict),
        MSRAAccessCap(),
        Bit('spare', Pt=0, BitLen=0),
        ]
    def map(self, s=''):
        buflen = len(s)*8
        bufsh = shtr(s)
        self.elementList = []
        # check if we have a single RAT or multiple one
        self.append(Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum',
                        Dict=AccessTechnoType_dict))
        self[-1].map(bufsh)
        mapped_len = 4
        bufsh = bufsh<<4
        while buflen - mapped_len >= 11:
            #print 'entering loop'
            if self[-1]() == 0xF:
                #print 'appending additional RAT'
                self.append(MSRAAdd())
                self[-1].map(bufsh)
            else:
                #print 'appending RAT capabilities'
                self.append(MSRAAccessCap()),
                self[-1].map(bufsh)
            ie_bitlen = self[-1].bit_len()
            mapped_len += ie_bitlen
            #print 'mapped_len', mapped_len
            bufsh = bufsh << ie_bitlen
            # now check if we have 0 -> continue, 1 -> loop on 1st while
            self.append(Bit(self.cond_name, BitLen=1))
            self[-1].map(bufsh)
            mapped_len += 1
            bufsh = bufsh<<1
            while buflen - mapped_len >= 11 and self[-1]() == 0:
                #print 'entering loop for conditional bit' 
                self.append(Bit(self.cond_name, BitLen=1))
                self[-1].map(bufsh)
                mapped_len += 1
                #print 'mapped_len', mapped_len
                bufsh = bufsh<<1
            if self[-1]() == 1:
                #print 'appending RAT'
                self.append(Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum',
                                Dict=AccessTechnoType_dict))
                self[-1].map(bufsh)
                mapped_len += 4
                bufsh = bufsh << 4
        # possibly spare bits at the end
        if mapped_len < buflen:
            #print 'appending spare bits'
            self.append(Bit(self.pad_name, BitLen=buflen-mapped_len))
            self[-1].map(bufsh)

###
# TS 24.301: LTE / EPC Information Element
# section 9
###

# section 9.9.3.23, Ciphering & Integrity Protection Algorithms
IntegAlg_dict = {
    0 : 'EIA0',
    1 : '128-EIA1',
    2 : '128-EIA2',
    3 : '128-EIA3',
    4 : 'EIA4',
    5 : 'EIA5',
    6 : 'EIA6',
    7 : 'EIA7' \
    }
CiphAlg_dict = {
    0 : 'EEA0',
    1 : '128-EEA1',
    2 : '128-EEA2',
    3 : '128-EEA3',
    4 : 'EEA4',
    5 : 'EEA5',
    6 : 'EEA6',
    7 : 'EEA7'
    }

# section 9.9.3.21, NAS Key Set Identifier
NASKSI_dict = { \
    0 : 'Native security context (for KSI_asme): KSI 0',
    1 : 'Native security context (for KSI_asme): KSI 1',
    2 : 'Native security context (for KSI_asme): KSI 2',
    3 : 'Native security context (for KSI_asme): KSI 3',
    4 : 'Native security context (for KSI_asme): KSI 4',
    5 : 'Native security context (for KSI_asme): KSI 5',
    6 : 'Native security context (for KSI_asme): KSI 6',
    7 : 'Native security context: no key is available (from MS) ' \
        '/ reserved (from network)',
    8 : 'Mapped security context (for KSI_sgsn): KSI 0',
    9 : 'Mapped security context (for KSI_sgsn): KSI 1',
    10 : 'Mapped security context (for KSI_sgsn): KSI 2',
    11 : 'Mapped security context (for KSI_sgsn): KSI 3',
    12 : 'Mapped security context (for KSI_sgsn): KSI 4',
    13 : 'Mapped security context (for KSI_sgsn): KSI 5',
    14 : 'Mapped security context (for KSI_sgsn): KSI 6',
    15 : 'Mapped security context: no key is available (from MS) ' \
        '/ reserved (from network)'
    }

# section 9.9.2.7
class NASSecToEUTRA(Layer):
    constructorList = [
        Str('NonceMME', Pt=3*'\0', Len=3, Repr='hex'),
        Bit('spare', Pt=0, BitLen=1),
        Bit('CiphAlg', Pt=0, BitLen=3, Repr='hum', Dict=CiphAlg_dict),
        Bit('spare', Pt=0, BitLen=1),
        Bit('IntegAlg', Pt=0, BitLen=3, Repr='hum', Dict=IntegAlg_dict),
        Bit('spare', Pt=0, BitLen=4),
        Bit('NASKSI', Pt=0, BitLen=4, Repr='hum', Dict=NASKSI_dict)
        ]
        
# section 9.9.3.12, EPS ID
# IMSI is same as ID(type='IMSI')
# IMEI is same as ID(type='IMEISV')
EPSIDType_dict = IANA_dict({
    1:'IMSI',
    2:'reserved',
    3:'IMEI',
    4:'reserved',
    6:'GUTI',
    7:'reserved'
    })
class GUTI(Layer):
    constructorList = [
        Bit('spare', Pt=0b1111, BitLen=4),
        Bit('odd', Pt=0, BitLen=1, Repr='hum'),
        Bit('type', BitLen=3, Pt=6, Dict=EPSIDType_dict, Repr='hum'),
        PLMN(),
        Int('MMEGroupID', Pt=0, Type='uint16', Repr='hex'),
        Int('MMECode', Pt=0, Type='uint8', Repr='hex'),
        Str('MTMSI', Pt=4*'\0', Len=4, Repr='hex')
        ]
    def __init__(self, MCCMNC='00101', **kwargs):
        Layer.__init__(self, **kwargs)
        self.PLMN.set_mcc(MCCMNC[:3])
        self.PLMN.set_mnc(MCCMNC[3:])

# section 9.9.3.12A
CSLCS_dict = {
    0:'No info available',
    1:'Location services via CS supported',
    2:'Location services via CS not supported',
    3:'reserved'
    }
class EPSFeatSup(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=2),
        Bit('ESR_PS', ReprName='Extended Service Request for Packet Services',
            Pt=0, BitLen=1, Repr='hum'),
        Bit('CS_LCS', ReprName='Location Services Indicator in CS', Pt=0,
            BitLen=2, Repr='hum', Dict=CSLCS_dict),
        Bit('EPC_LCS', ReprName='Location Services Indicator in EPC', Pt=0,
            BitLen=1, Repr='hum'),
        Bit('EMC_BS', ReprName='Emergency Bearer Services Indicator', Pt=0,
            BitLen=1, Repr='hum'),
        Bit('IMS_VoPS', ReprName='IMS Voice over PS Session un S1 mode', Pt=0,
            BitLen=1, Repr='hum')
        ]

# section 9.9.3.32
class TAI(Layer):
    constructorList = [
        PLMN(),
        Int('TAC', Pt=0, Type='uint16', Repr='hex')
        ]
    def __init__(self, MCCMNC='00101', TAC=0x0000):
        Layer.__init__(self)
        self.PLMN.set_mcc(MCCMNC[:3])
        self.PLMN.set_mnc(MCCMNC[3:])
        self.TAC > TAC

# section 9.9.3.33
PartialTAI_dict = {
    0 : 'Non-consecutive TAC belonging to one PLMN',
    1 : 'Consecutive TAC belonging to one PLMN',
    2 : 'TAIs belonging to different PLMNs',
    3 : 'reserved'
    }

class PartialTAIList(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('Type', Pt=0, BitLen=2, Repr='hum', Dict=PartialTAI_dict),
        Bit('Num', Pt=1, BitLen=5, Repr='hum'),
        PLMN(),
        Int('TAC', Pt=0, Type='uint16', Repr='hex')
        ]
    
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, **kwargs)
        if 'PLMN' in kwargs:
            self._set_plmn( kwargs['PLMN'] )
        for arg in args:
            if isinstance(arg, PLMN):
                self._set_plmn( arg )
    
    def _set_plmn(self, plmn):
        if isinstance(plmn, PLMN):
            self.PLMN.set_mcc( plmn.get_mcc() )
            self.PLMN.set_mnc( plmn.get_mnc() )
    
    def add_tac(self, *args):
        for arg in args:
            if isinstance(arg, int):
                self.append( Int('TAC', Pt=arg, Type='uint16', Repr='hex') )
            elif isinstance(arg, (list, tuple)):
                # the recursive way
                for e in arg:
                    self.add_tac(e)
    
    def add_tai(self, *args):
        for arg in args:
            if isinstance(arg, TAI):
                self.append( arg[0] ) # append PLMN
                self.append( arg[1] ) # append TAC
            elif isinstance(arg, (list, tuple)):
                for e in arg:
                    self.add_tai(e)
    
    def map(self, s):
        Layer.map(self, s)
        s = s[5:]
        # depending of Type(), stack the correct structure
        if self.Type() == 0:
            # stacking only additional TAC uint16 values, Num()-1 number of time
            max_tacs = min(len(s)//2, self.Num()-1)
            self.add_tac( unpack('!'+'H'*max_tacs, s[:2*max_tacs]) )
        elif self.Type() == 2:
            # stacking complete TAI (PLMN + TAC) struct, Num()-1 number of time
            max_tais = min(len(s)//5, self.Num()-1)
            for i in range(max_tais):
                tai = TAI()
                tai.map(s)
                self.add_tai( tai )
                s = s[5:]

class PartialTAIList0(PartialTAIList):
    # Non-consecutive TAC belonging to one PLMN
    #
    # constructorList is the same as partialTAIList
    def __init__(self, *args, **kwargs):
        PartialTAIList.__init__(self, *args, **kwargs)
        self.Type > 0
        # automate Num(), corresponding to the number of stacked TACs
        self.Num.Pt = self
        self.Num.PtFunc = lambda s: len([t for t in self[5:] \
                                          if t.CallName=='TAC'])

class PartialTAIList1(PartialTAIList):
    # Consecutive TAC belonging to one PLMN
    #
    # constructorList is the same as partialTAIList
    def __init__(self, *args, **kwargs):
        PartialTAIList.__init__(self, *args, **kwargs)
        self.Type > 1
        # Num() has to be filled by hand
        # according to the number of consecutive TAC

class PartialTAIList2(PartialTAIList):
    # TAIs belonging to different PLMNs
    #
    # constructorList is the same as partialTAIList
    def __init__(self, *args, **kwargs):
        PartialTAIList.__init__(self, *args, **kwargs)
        self.Type > 2
        # add (possibly multiple) TAI(s)
        for arg in args:
            if isinstance(arg, (TAI, list, tuple)):
                self.add_tai(arg)
        if 'TAI' in kwargs and isinstance(kwargs['TAI'], (TAI, list, tuple)):
            self.add_tai( kwargs['TAI'] )
        # automate Num(), corresponding to the number of stacked TAIs
        self.Num.Pt = self
        self.Num.PtFunc = lambda s: len([p for p in self[5:] \
                                          if p.CallName=='PLMN'])

class TAIList(Layer):
    constructorList = [ ]
    
    def __init__(self, *args):
        Layer.__init__(self)
        for arg in args:
            if isinstance(arg, PartialTAIList):
                self.append(arg)
    
    def map(self, s=''):
        while len(s) >= 6:
            self.append( PartialTAIList() )
            self[-1].map(s)
            s = s[len(self[-1]):]

# section 9.9.3.34
class UENetCap(Layer):
    constructorList = [
        Bit('EEA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA7', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA7', Pt=0, BitLen=1, Repr='hum'),
        # from here: optional infos
        Bit('UEA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA7', Pt=0, BitLen=1, Repr='hum'), # EOO 5
        Bit('UCS2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA7', Pt=0, BitLen=1, Repr='hum'), # EOO 6
        Bit('ProSe-dd', Pt=0, BitLen=1, Repr='hum'),
        Bit('ProSe', Pt=0, BitLen=1, Repr='hum'),
        Bit('H245_ASH', Pt=0, BitLen=1, Repr='hum'),
        Bit('ACC_CSFB', Pt=0, BitLen=1, Repr='hum'),
        Bit('LPP', Pt=0, BitLen=1, Repr='hum'), 
        Bit('LCS', Pt=0, BitLen=1, Repr='hum'), 
        Bit('SRVCC_CDMA', Pt=0, BitLen=1, Repr='hum'), 
        Bit('NF', Pt=0, BitLen=1, Repr='hum'), # EEO 7
        Bit('spare', Pt=0, BitLen=7),
        Bit('ProSe-dc', Pt=0, BitLen=1, Repr='hum'), # EEO 8
        Str('spare', Pt=7*'\0', Len=7, Repr='hex', Trans=True)
        ]
    def map(self, s='\0\0'):
        s_len = len(s)
        if s_len == 2:
            for ie in self[16:]:
                ie.Trans = True
        elif s_len == 3:
            for ie in self[24:]:
                ie.Trans = True
        elif s_len == 4:
            for ie in self[32:]:
                ie.Trans = True
        elif s_len == 5:
            for ie in self[40:]:
                ie.Trans = True
        elif s_len == 6:
            for ie in self[42:]:
                ie.Trans = True
        elif s_len > 6:
            self[-1].Trans = False
            self.spare.Len = max(s_len-6, 7)
        Layer.map(self, s)

class UESecCap(Layer):
    _byte_aligned = False
    constructorList = [
        Bit('EEA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('EEA7', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('EIA7', Pt=0, BitLen=1, Repr='hum'), # 2 bytes
        Bit('UEA0', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('UEA7', Pt=0, BitLen=1, Repr='hum'),
        Bit('spare', Pt=0, BitLen=1),
        Bit('UIA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('UIA7', Pt=0, BitLen=1, Repr='hum'), # 4 bytes
        Bit('spare', Pt=0, BitLen=1),
        Bit('GEA1', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA2', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA3', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA4', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA5', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA6', Pt=0, BitLen=1, Repr='hum'),
        Bit('GEA7', Pt=0, BitLen=1, Repr='hum'),
        ]
    def map(self, s=2*'\0'):
        s_len = len(s)
        if s_len == 2:
            for ie in self[16:]:
                ie.Trans = True
        elif s_len == 3:
            for ie in self[24:]:
                ie.Trans = True
        elif s_len == 4:
            for ie in self[32:]:
                ie.Trans = True
        # else, we get all indicators
        Layer.map(self, s)

APN_AMBR_dict = {}
APN_AMBR_EXT_dict = {}
APN_AMBR_EXT2_dict = {}

class APN_AMBR(Layer):
    constructorList = [
        Int('APN_AMBR_DL', Pt=0, Type='uint8', Dict=APN_AMBR_dict),
        Int('APN_AMBR_UL', Pt=0, Type='uint8', Dict=APN_AMBR_dict),
        Int('APN_AMBR_DL_ext', Pt=0, Type='uint8', Dict=APN_AMBR_EXT_dict),
        Int('APN_AMBR_UL_ext', Pt=0, Type='uint8', Dict=APN_AMBR_EXT_dict),
        Int('APN_AMBR_DL_ext2', Pt=0, Type='uint8', Dict=APN_AMBR_EXT2_dict),
        Int('APN_AMBR_UL_ext2', Pt=0, Type='uint8', Dict=APN_AMBR_EXT2_dict),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        # generate Dict for those bitrates
        self.APN_AMBR_DL.DictFunc = self._gen_dict
        self.APN_AMBR_UL.DictFunc = self._gen_dict
        self.APN_AMBR_DL_ext.DictFunc = self._gen_ext_dict
        self.APN_AMBR_UL_ext.DictFunc = self._gen_ext_dict
        self.APN_AMBR_DL_ext2.DictFunc = self._gen_ext2_dict
        self.APN_AMBR_UL_ext2.DictFunc = self._gen_ext2_dict
    
    def _gen_dict(self, d={}):
        if d == {}:
            d[0] = 'reserved'
            for v in range(1, 64):
                d[v] = '%i kbps' % v
            for v in range(64, 127):
                d[v] = '%i kbps' % ((v-0b01000000)*8)
            for v in range(128, 255):
                d[v] = '%i kbps' % ((v-0b10000000)*64)
            d[255] = '0 kbps'
        return d
    
    def _gen_ext_dict(self, d={}):
        if d == {}:
            d[0] = 'see APN_AMBR'
            for v in range(1, 75):
                d[v] = '%i kbps' % ((v*100)+8600)
            for v in range(75, 187):
                d[v] = '%i Mbps' % ((v-0b01001010)+16)
            for v in range(187, 251):
                d[v] = '%i Mbps' % (((v-0b10111010)*2)+128)
            for v in range(251, 256):
                d[v] = '256 Mbps'
        return d
    
    def _gen_ext2_dict(self, d={}):
        if d == {}:
            d[0] = 'see APN_AMBR_ext'
            for v in range(1, 255):
                d[v] = '%i Mbps more' % (v*256)
            d[255] = 'see APN_AMBR_ext'
        return d

###
# TS 24.080: Supplementary Services IE
# section 3
###
# WNG: This implementation of SS is not working well
# better use the ASN.1 version
# >>> from libmich.asn1.processor import *
# >>> ASN1.ASN1Obj.CODEC = BER
# >>> load_mobule('SS')
# >>> GLOBAL.TYPE['Facility']
###
'''
#
# section 3.6.1: Facility Component
# ASN.1 BER codec (Tag-Length-Value style)
#

class BER_TLV(Layer):
    _byte_aligned = False
    _map_recursive = True # parse recursively contructed type
    #_len_undef = 1024 # length allocated to V for indefinite length form
    constructorList = [
        Int('T', Pt=0, Type='uint8', Repr='hum'),
        Bit('L_form', Pt=0, BitLen=1, Repr='hum', Dict={0:'short', 1:'long'}),
        Bit('L_pre', Pt=1, BitLen=7, Repr='hum'),
        Bit('L', Pt=0, BitLen=7, Repr='hum'),
        Str('V', Pt='', Repr='hex')
        ]
    
    def __init__(self, **kwargs):
        Layer.__init__(self)
        if 'T' in kwargs:
            self.T.Pt = kwargs['T']
        if 'V' in kwargs:
            self.V.Pt = kwargs['V']
            self.L.BitLen = 8*int(round(len(hex(len(self.V.Pt))[2:].replace('L',''))/2.0))
        self.L_form.Pt = self.L
        self.L_form.PtFunc = lambda l: 1 if l() >= 128 else 0
        self.L_pre.Trans = self.L_form
        self.L_pre.TransFunc = lambda f: False if f() else True
        self.L_pre.Pt = self.L
        self.L_pre.PtFunc = lambda l: l.BitLen//8
        self.L.Pt = self.V
        self.L.PtFunc = lambda v: len(v)
        self.V.Len = self.L
        self.V.LenFunc = lambda l: l()
    
    def set_val(self, V=''):
        if len(V) >= 128:
            self.L.BitLen = 8*int(round(len(hex(len(V))[2:].replace('L',''))/2.0))
        else:
            self.L.BitLen = 7
        self.L_form.Val = None
        self.L_pre.Val = None
        self.L.Val = None
        self.V.Pt = V
    
    def map(self, s=''):
        self.__init__()
        if len(s) <= 1:
            return
        ord_s1 = ord(s[1])
        if ord_s1 & 0x80 == 0:
            Layer.map(self, s)
        else:
            self.L.BitLen = 8*(ord_s1 & 0x7F)
            if self.L.BitLen == 0:
                # indefinite length form
                self.V.LenFunc = None
                self.V.Len = len(s)-2
            Layer.map(self, s)
        # BER-TLV recursive parsing
        # if Tag is for a constructed object
        if self._map_recursive and self.T() & 0x20:
            buf = self.V()
            comp = []
            while True:
                comp.append( BER_TLV() )
                comp[-1].map(buf)
                buf = buf[len(comp[-1]):]
                if len(buf) <= 1:
                    break
            if ''.join(map(str, comp)) == self.V():
                self.V.Val = None
                self.V.Pt = comp
                self.V.Repr = 'hum'

# 24.080, section 3.6.3
SSComponentID_dict = {
    2 : 'Invoke ID',
    128 : 'Linked ID'
    }

class SS_InvokeID(BER_TLV):
    def __init__(self, **kwargs):
        BER_TLV.__init__(self, T=2, **kwargs)
        self.T.Dict = SSComponentID_dict

class SS_LinkedID(BER_TLV):
    def __init__(self, **kwargs):
        BER_TLV.__init__(self, **kwargs)
        self.T.Pt = 128
        self.T.Dict = SSComponentID_dict

# from ASN.1 definitions
SSOperations_dict = {
    10 : 'registerSS',
    11 : 'eraseSS',
    12 : 'activateSS',
    13 : 'deactivateSS',
    14 : 'interrogateSS',
    16 : 'notifySS',
    17 : 'registerPassword',
    18 : 'getPassword',
    19 : 'processUnstructuredSS-Data',
    38 : 'forwardCheckSS-Indication',
    59 : 'processUnstructuredSS-Request',
    60 : 'unstructuredSS-Request',
    61 : 'unstructuredSS-Notify',
    109 : 'lcs-PeriodicLocationCancellation',
    110 : 'lcs-LocationUpdate',
    111 : 'lcs-PeriodicLocationRequest',
    112 : 'lcs-AreaEventCancellation',
    113 : 'lcs-AreaEventReport',
    114 : 'lcs-AreaEventRequest',
    115 : 'lcs-MOLR',
    116 : 'lcs-LocationNotification',
    117 : 'callDeflection',
    118 : 'userUserService',
    119 : 'accessRegisterCCEntry',
    120 : 'forwardCUG-Info',
    121 : 'splitMPTY',
    122 : 'retrieveMPTY',
    123 : 'holdMPTY',
    124 : 'buildMPTY',
    125 : 'forwardChargeAdvice',
    126 : 'explicitCT',
    }
SSErrors_dict = {
    1 : 'unknownSubscriber',
    9 : 'illegalSubscriber',
    10 : 'bearerServiceNotProvisioned',
    11 : 'teleserviceNotProvisioned',
    12 : 'illegalEquipment',
    13 : 'callBarred',
    14 : 'forwardingViolation',
    16 : 'illegalSS-Operation',
    17 : 'ss-ErrorStatus',
    18 : 'ss-NotAvailable',
    19 : 'ss-SubscriptionViolation',
    20 : 'ss-Incompatibility',
    21 : 'facilityNotSupported',
    27 : 'absentSubscriber',
    34 : 'systemFailure',
    35 : 'dataMissing',
    36 : 'unexpectedDataValue',
    37 : 'pw-RegistrationFailure',
    38 : 'negativePW-Check',
    43 : 'numberOfPW-AttemptsViolation',
    47 : 'forwardingFailed',
    71 : 'unknownAlphabet',
    72 : 'ussd-Busy',
    121 : 'rejectedByUser',
    122 : 'rejectedByNetwork',
    123 : 'deflectionToServedSubscriber',
    124 : 'specialServiceCode',
    125 : 'invalidDeflectedToNumber',
    126 : 'maxNumberOfMPTY-ParticipantsExceeded',
    127 : 'resourcesNotAvailable'
    }

class SS_OperationCode(BER_TLV):
    def __init__(self, **kwargs):
        BER_TLV.__init__(self, **kwargs)
        self.T.Pt = 2
        self.T.Dict = {2:'Operation Code'}
    def map(self, s=''):
        BER_TLV.map(self, s)
        if self.L() == 1:
            code = Int('Code', Pt=ord(self.V()), Type='uint8',
                       Dict=SSOperations_dict, Repr='hum')
            self.V.Val = None
            self.V.Pt = code
            self.V.Repr = 'hum'

class SS_ErrorCode(BER_TLV):
    def __init__(self, **kwargs):
        BER_TLV.__init__(self, **kwargs)
        self.T.Pt = 2
        self.T.Dict = {2:'Error Code'}
    def map(self, s=''):
        BER_TLV.map(self, s)
        if self.L() == 1:
            code = Int('Code', Pt=ord(self.V()), Type='uint8',
                       Dict=SSErrors_dict, Repr='hum')
            self.V.Val = None
            self.V.Pt = code
            self.V.Repr = 'hum'

# 24.080, section 3.6.7, Problem Code
SSProblemTag_dict = {
    128 : 'General problem',
    129 : 'Invoke problem',
    130 : 'Return Result problem',
    131 : 'Return Error problem'
    }
SSProblemCodeGeneral_dict = {
    0 : 'Unrecognized component',
    1 : 'Mistyped component',
    2 : 'Badly structured component'
    }
SSProblemCodeInvoke_dict = {
    0 : 'Duplicate Invoke ID',
    1 : 'Unrecognized operation',
    2 : 'Mistyped parameter',
    3 : 'Resource limitation',
    4 : 'Initiating release',
    5 : 'Unrecognized Linked ID',
    6 : 'Linked response unexpected',
    7 : 'Unexpected linked operation'
    }    
SSProblemCodeRetRes_dict = {
    0 : 'Unrecognized Invoke ID',
    1 : 'Return Result unexpected',
    2 : 'Mistyped parameter'
    }
SSProblemCodeRetErr_dict = {
    0 : 'Unrecognized Invoke ID',
    1 : 'Return Error unexpected',
    2 : 'Unrecognized error',
    3 : 'Unexpected error',
    4 : 'Mistyped parameter'
    }
class SS_ProblemCode(BER_TLV):
    def __init__(self, **kwargs):
        BER_TLV.__init__(self, **kwargs)
        self.T.Pt = 128
        self.T.Dict = SSProblemTag_dict
    
    def map(self, s=''):
        BER_TLV.map(self, s)
        if self.L() == 1:
            code = Int('Code', Pt=ord(self.V()), Type='uint', Repr='hum')
            code.Dict = self.T
            code.DictFunc = lambda t: {128:SSProblemCodeGeneral_dict,
                                       129:SSProblemCodeInvoke_dict,
                                       130:SSProblemCodeRetRes_dict,
                                       131:SSProblemCodeRetErr_dict}
            self.V.Val = None
            self.V.Pt = code
            self.V.Repr = 'hum'

class SS_Parameters(BER_TLV):
    pass

# 24.080, section 3.6.2, Component Type
SSComponentType_dict = {
    161 : 'Invoke',
    162 : 'Return Result',
    163 : 'Return Error',
    164 : 'Reject'
    }

class SS_Invoke(Layer):
    constructorList = [
        Int('T', Pt=161, Type='uint8', Dict=SSComponentType_dict),
        Int('L', Type='uint8'),
        SS_InvokeID(),
        SS_LinkedID(), # optional
        SS_OperationCode(),
        SS_Parameters() # optional
        ]
    def map(self, s=''):
        part = self[0:3]
        part.map(s)
        s = s[len(part):]
        if s:
            if ord(s[0]) == 2:
                self[3].Trans = True
                self[4].map(s)
                s = s[len(self[4]):]
            else:
                part = self[3:5]
                part.map(s)
                s = s[len(part):]
        if s:
            self[-1].map(s)
        else:
            self[-1].Trans = True

class SS_ReturnResult(Layer):
    constructorList = [
        Int('T', Pt=162, Type='uint8', Dict=SSComponentType_dict),
        Int('L', Type='uint8'),
        SS_InvokeID(),
        Int('T_seq', Pt=48, Type='uint8'), # optional, together with L_seq
        Int('L_seq', Pt=0, Type='uint8'), # optional, together with T_seq
        SS_OperationCode(), # optional
        SS_Parameters() # optional
        ]
    def map(self, s=''):
        part = self[0:3]
        part.map(s)
        s = s[len(part):]
        if s:
            if ord(s[0]) != 48:
                self.T_seq.Trans = True
                self.L_seq.Trans = True
            else:
                part = self[3:5]
                part.map(s)
                s = s[len(part):]
        if s:
            if ord(s[0]) != 2:
                self[-2].Trans = True
            else:
                self[-2].map(s)
                s = s[len(self[-2]):]
        if s:
            self[-1].map(s)
        else:
            self[-1].Trans = True

class SS_ReturnError(Layer):
    constructorList = [
        Int('T', Pt=163, Type='uint8', Dict=SSComponentType_dict),
        Int('L', Pt=0, Type='uint8'),
        SS_InvokeID(),
        SS_ErrorCode(),
        SS_Parameters() # optional
        ]
    def map(self, s=''):
        part = self[0:4]
        part.map(s)
        s = s[len(part):]
        if s:
            self[-1].map(s)
        else:
            self[-1].Trans = True

class SS_Reject(Layer):
    constructorList = [
        Int('T', Pt=164, Type='uint8', Dict=SSComponentType_dict),
        Int('L', Type='uint8'),
        SS_InvokeID(),
        SS_ProblemCode()
        ]

# 24.080, section 3.6, Facility IE
class Facility(Layer):
    constructorList = []
    def map(self, s=''):
        if not s:
            return
        t = ord(s[0])
        if t == 161:
            self.append( SS_Invoke() )
        elif t == 162:
            self.append( SS_ReturnResult() )
        elif t == 163:
            self.append( SS_ReturnError() )
        elif t == 164:
            self.append( SS_Reject() )
        else:
            self.append( BER_TLV() )
        Layer.map(self, s)
'''

# 24.080, section 3.7.2, SS version IE
SSversion_dict = IANA_dict({
    0:'phase 2 service, ellipsis notation, and phase 2 error handling is supported',
    1:'SS-Protocol version 3 is supported, and phase 2 error handling is supported'
    })
class SSversion(Layer):
    constructorList = [
        Int('SSversion', Pt=0, Type='uint8', Dict=SSversion_dict)
        ]

# 31.102, USIM files
# Access Technology
class AccessTechnology(Layer):
    constructorList = [
        Bit('UTRAN', Pt=0, BitLen=1, Repr='hum'),
        Bit('E_UTRAN', Pt=0, BitLen=1, Repr='hum'),
        Bit('RFU', Pt=0, BitLen=6, Repr='bin'),
        Bit('GSM', Pt=0, BitLen=1, Repr='hum'),
        Bit('GSM_COMPACT', Pt=0, BitLen=1, Repr='hum'),
        Bit('CDMA2000_HRPD', Pt=0, BitLen=1, Repr='hum'),
        Bit('CDMA2000_1xRTT', Pt=0, BitLen=1, Repr='hum'),
        Bit('RFU', Pt=0, BitLen=4, Repr='bin'),
        ]
    
    def get_AT(self):
        AT = []
        if self.GSM(): AT.append('GSM')
        if self.GSM_COMPACT(): AT.append('GSM COMPACT')
        if self.CDMA2000_1xRTT(): AT.append('CDMA2000 1xRTT')
        if self.CDMA2000_HRPD(): AT.append('CDMA2000 HRPD')
        if self.UTRAN(): AT.append('UTRAN')
        if self.E_UTRAN(): AT.append('E-UTRAN')
        return AT
    
    def __repr__(self):
        return '<[AT]: {0}>'.format('|'.join(self.get_AT()))
