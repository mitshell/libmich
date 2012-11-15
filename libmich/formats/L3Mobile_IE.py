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
__all__ = ['StrBCD', 'BCDnum',
           'LAI', 'ID', 'MSCm1', 'MSCm2', 'MSCm3',
           'PLMN', 'PLMNlist', 'AuxState',
           'BearerCap', 'CCCap', 'AccessTechnoType_dict', 'MSNetCap', 'MSRACap',
           'PDPAddr', 'QoS', 'ProtID', 'ProtConfig', 'PacketFlowID',
           ]

# for convinience
from binascii import hexlify
#
from libmich.core.element import Bit, Int, Str, Layer, \
    show, debug, log, ERR, WNG, DBG
from libmich.core.shtr import shtr
from libmich.core.IANA_dict import IANA_dict
from libmich.core.CSN1 import CSN1, BREAK, BREAK_LOOP
from libmich.formats.MCCMNC import MCC_dict, MNC_dict


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
        ret = ''
        for c in self():
            n1, n2 = ord(c)>>4, ord(c)&0xf
            ret += hex(n2)[2:]
            if n1 < 0xF:
                ret += hex(n1)[2:]
            else:
                break
        return ret
        
    def encode(self, num='12345'):
        if len(num) % 2 == 1:
            num += 'F'
        ret = ''
        for i in range(0, len(num), 2):
            try:
                ret += chr( (int(num[i+1], 16)<<4) + int(num[i], 16) )
            except ValueError:
                log(ERR, '(StrBCD) assigning invalid number')
        self.map(ret)
    
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

class BCDnum(Layer):
    constructorList = [
        Bit('ext', Pt=1, BitLen=1),
        Bit('Type', ReprName='Type of number', Pt=1, BitLen=3, \
            Repr='hum', Dict=BCDType_dict),
        Bit('NumPlan', ReprName='Numbering plan identification', Pt=1, \
            BitLen=4, Repr='hum', Dict=NumPlan_dict),
        StrBCD('Num', Pt='\x12')
        ]
    def __init__(self, number='', **kwargs):
        Layer.__init__(self, **kwargs)
        if number:
            self.Num.encode(number)


# section 10.5.1.3
# Local Area Identifier, LAC is MNO-specific
class LAI(Layer):
    constructorList = [
        Bit('MCC2', Pt=0, BitLen=4, Repr='hum'),
        Bit('MCC1', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC3', Pt=0, BitLen=4, Repr='hum'),
        Bit('MCC3', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC2', Pt=0, BitLen=4, Repr='hum'),
        Bit('MNC1', Pt=0, BitLen=4, Repr='hum'),
        Str('LAC', Pt='\0\0', Len=2, Repr='hex')]
    
    def __init__(self, mccmnc='001001', lac='\0\0'):
        Layer.__init__(self)
        self.LAC > lac[:2]
        if len(mccmnc) not in (5, 6):
            return
        self.MCC1 > int(mccmnc[0])
        self.MCC2 > int(mccmnc[1])
        self.MCC3 > int(mccmnc[2])
        self.MNC1 > int(mccmnc[3])
        self.MNC2 > int(mccmnc[4])
        if len(mccmnc) == 5:
            self.MNC3 > 0b1111
            return
        self.MNC3 > int(mccmnc[5])
        
    def __repr__(self):
        return '<[LAI]: MCC: %s / MNC: %s / LAC: %s>' \
               % (self.MCC(), self.MNC(), hexlify(self.LAC()))
    
    def MCC(self):
        return '%i%i%i' % (self.MCC1(), self.MCC2(), self.MCC3())
    
    def MNC(self):
        if self.MNC3() == 0b1111:
            return '%i%i' % (self.MNC1(), self.MNC2())
        else:
            return '%i%i%i' % (self.MNC1(), self.MNC2(), self.MNC3())
    
#

# section 10.5.1.4
# Mobile Identity
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
            repr = '%s:%s' % (IDtype_dict[t], \
                              ''.join([str(getattr(self, 'digit%s'%i)()) \
                                       for i in range(1, len(self)*2+self.odd()-1)]))
        # tmsi
        elif t == 4:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.tmsi))
        # not handled
        else:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.data))
        return '<[ID]: %s>' % repr
    
    def get_imsi(self):
        # this is easier than using self.__repr__()[12:]...
        if self.type() == 1:
            return ''.join([str(getattr(self, 'digit%s'%i)()) \
                            for i in range(1, len(self)*2+self.odd()-1)])
        else:
            return ''
#

# section 10.5.1.5
# Mobile Station Classmark 1
Revision_level = {
    0:'Reserved for GSM phase 1',
    1:'GSM phase 2 MS',
    2:'MS supporting R99 or later',
    3:'FFU'}

RFclass_dict = {
    0:'class 1',
    1:'class 2',
    2:'class 3',
    3:'class 4',
    4:'class 5'}

class MSCm1(Layer):
    constructorList = [
        Bit('spare', Pt=0, BitLen=1),
        Bit('rev', Pt=1, BitLen=2, Repr='hum', Dict=Revision_level),
        Bit('ES', ReprName='Controlled early classmark sending', \
            Pt=0, BitLen=1, Repr='hum'),
        Bit('noA51', Pt=0, BitLen=1, Repr='hum'),
        Bit('RFclass', Pt=0, BitLen=3, Repr='hum', Dict=RFclass_dict)]

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
        Bit('SSscreen', Pt=0, BitLen=2),
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
        ]


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
    
    def __init__(self, mccmnc='00101'):
        Layer.__init__(self)
        if len(mccmnc) not in (5, 6):
            return
        self.MCC1 > int(mccmnc[0])
        self.MCC2 > int(mccmnc[1])
        self.MCC3 > int(mccmnc[2])
        self.MNC1 > int(mccmnc[3])
        self.MNC2 > int(mccmnc[4])
        if len(mccmnc) == 5:
            self.MNC3 > 0b1111
            return
        self.MNC3 > int(mccmnc[5])
        
    def __repr__(self):
        MCC = '%i%i%i' % (self.MCC1(), self.MCC2(), self.MCC3())
        if self.MNC3() == 0b1111:
            MNC = '%i%i' % (self.MNC1(), self.MNC2())
        else:
            MNC = '%i%i%i' % (self.MNC1(), self.MNC2(), self.MNC3())
        return '<[PLMN]: MCC: %s / MNC: %s>' % (MCC, MNC)
    
    def interpret(self):
        MCC = int('%i%i%i' % (self.MCC1(), self.MCC2(), self.MCC3()))
        MCC = MCC_dict[MCC] if MCC in MCC_dict.keys() else MCC
        if self.MNC3() == 0b1111:
            MNC = int('%i%i' % (self.MNC1(), self.MNC2()))
        else:
            MNC = int('%i%i%i' % (self.MNC1(), self.MNC2(), self.MNC3()))
        MNC = MNC_dict[MNC] if MNC in MNC_dict.keys() else MNC
        return '<[PLMN]: %s / %s>' % (MCC, MNC)

class PLMNlist(Layer):
    constructorList = [ ]
    
    def __init__(self, mccmnc='00101'):
        Layer.__init__(self)
        self.append( PLMN(mccmnc) )
    
    def map(self, s=''):
        Layer.map(self, s)
        s = s[self.map_len():]
        while len(s) > 0:
            self.append( PLMN() )
            self[-1].map(s)
            s = s[self[-1].map_len():]
    
    def add_PLMN(self, plmn=PLMN()):
        if isinstance(plmn, PLMN):
            self.append(plmn)
    
    def interpret(self):
        return ''.join([str(plmn.interpret()) for plmn in self])

#       

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
        Bit('ReliabilityClass', Pt=0, BitLen=3, Dict=ReliabClass_dict, Repr='hum'),
        Bit('PeakThroughput', Pt=0, BitLen=4, Dict=PeakTP_dict, Repr='hum'),
        Bit('spare', Pt=0, BitLen=1, Repr='hex'),
        Bit('PrecedenceClass', Pt=0, BitLen=3, Dict=PrecedClass_dict, Repr='hum'),
        Bit('spare', Pt=0, BitLen=3, Repr='hex'),
        Bit('MeanThroughput', Pt=0, BitLen=5),
        Bit('TrafficClass', Pt=0, BitLen=3),
        Bit('DeliveryOrder', Pt=0, BitLen=2),
        Bit('DeliveryOfErrSDU', Pt=0, BitLen=3),
        Int('MaxSDUSize', Pt=0, Type='uint8'),
        Int('MaxULBitRate', Pt=0, Type='uint8'),
        Int('MaxDLBitRate', Pt=0, Type='uint8'),
        Bit('ResidualBitErrRate', Pt=0, BitLen=4),
        Bit('SDUErrRatio', Pt=0, BitLen=4),
        Bit('TransferDelay', Pt=0, BitLen=6),
        Bit('TrafficHandlingPrio', Pt=0, BitLen=2),
        Int('GuarantULBitRate', Pt=0, Type='uint8'),
        Int('GuarantDLBitRate', Pt=0, Type='uint8'),
        Bit('spare', Pt=0, BitLen=3, Repr='hex'),
        Bit('SignallingInd', Pt=0, BitLen=1),
        Bit('SourceStatDesc', Pt=0, BitLen=4),
        Int('MaxDLBitRateExt', Pt=0, Type='uint8'),
        Int('GuarantDLBitRateExt', Pt=0, Type='uint8'),
        Int('MaxULBitRateExt', Pt=0, Type='uint8'),
        Int('GuarantULBitRateExt', Pt=0, Type='uint8'),
        ]
    # rewrite map() in order to remove up to the 4 last Int() fields,
    # which are sometimes not provided... sometimes...
    def map(self, buf=''):
        Layer.map(self, buf)
        diff = len(self) - len(buf)
        if 0 < diff <= 4:
            for i in range(diff):
                self[-i-1].Trans = True
    
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
ProtID_dict = {
    0xC021 : 'LCP',
    0xC023 : 'PAP',
    0xC223 : 'CHAP',
    0x8021 : 'IPCP'
    }
class ProtID(Layer):
    constructorList = [
        Int('ID', Pt=0, Type='uint16', Dict=ProtID_dict, Repr='hum'),
        Int('length', Pt=0, Type='uint8'),
        Str('content', Pt='', Repr='hex'),
        ]
    def __init__(self, **kwargs):
        Layer.__init__(self, **kwargs)
        self.length.Pt = self.content
        self.length.PtFunc = lambda c: len(c)
        self.content.Len = self.length
        self.content.LenFunc = lambda l: l()
#
class ProtConfig(Layer):
    constructorList = [
        Bit('ext', Pt=1, BitLen=1),
        Bit('spare', Pt=0, BitLen=4, Repr='hex'),
        Bit('ConfigProt', Pt=0, BitLen=3, Dict={0:'PPP with IP PDP'}, Repr='hum'),
        ]
    # when mapping a buffer, append much ProtID() as needed 
    def map(self, buf=''):
        if buf:
            Layer.map(self, buf)
            buf = buf[1:]
            while len(buf) >= 3:
                length = ord(buf[2:3])
                if len(buf) >= 3+length:
                    self.append(ProtID())
                    self[-1].map(buf)
                    buf = buf[len(self[-1]):]
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
        {'0':BREAK, '1':(Bit('ExtDTMGPRSMultislotClass', Pt=0, BitLen=2), \
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
                         {'0':BREAK, '1':Bit('DTMEGPRSHighMultislotClass', Pt=0, BitLen=3)})},
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
        Bit('spare', Pt=0, BitLen=0)
        ]
    def __init__(self, *args, **kwargs):
        CSN1.__init__(self, *args, **kwargs)
        self.csn1List[0].Pt = self.csn1List[1]
        self.csn1List[0].PtFunc = lambda c: c.bit_len()
    #
    def map(self, string='', byte_offset=0):
        # WNG: it is clear from this crappy structure that 
        # some network-side CSN1 parser will be buggy right here !
        CSN1.map(self, string, byte_offset)
        total_len, cont_len = self[0](), self[1].bit_len()
        if total_len < cont_len:
            # in case the AccessCap is too long, remove IE 1 per 1
            while self[1].bit_len() > total_len:
                self[1].remove(self[1][-1])
            # in case its becoming too short, add spare bits
            if self[1].bit_len() < total_len:
                self.append(self.csn1List[2])
                self[-1].BitLen = total_len - self[1].bit_len()
        #
        elif total_len > cont_len:
            self.append(self.csn1List[2])
            self[-1].BitLen = total_len - cont_len
#
class MSRAAddTech(CSN1):
    csn1List = [
        Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum', \
            Dict=AccessTechnoType_dict),
        Bit('GMSKPowerClass', Pt=0, BitLen=3),
        Bit('8PSKPowerClass', Pt=0, BitLen=2),
        ]
class MSRAAdd(CSN1):
    csn1List = [
        Bit('Length', Pt=0, BitLen=7, Repr='hum'),
        ]
    def map(self, string='', byte_offset=0):
        CSN1.map(self, string, byte_offset)
        l = self[0]()
        bufsh = shtr(string)<<7
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
                    self.append(ie)
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
        Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum', \
            Dict=AccessTechnoType_dict),
        MSRAAccessCap(),
        Bit('spare', Pt=0, BitLen=0),
        ]
    def map(self, s=''):
        buflen = len(s)*8
        bufsh = shtr(s)
        self.elementList = []
        # check if we have a single RAT or multiple one
        self.append(Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum', \
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
                self.append(Bit('AccessTechnoType', Pt=0, BitLen=4, Repr='hum', \
                                Dict=AccessTechnoType_dict))
                self[-1].map(bufsh)
                mapped_len += 4
                bufsh = bufsh << 4
        # possibly spare bits at the end
        if mapped_len < buflen:
            #print 'appending spare bits'
            self.append(Bit(self.pad_name, BitLen=buflen-mapped_len))
            self[-1].map(bufsh)
#