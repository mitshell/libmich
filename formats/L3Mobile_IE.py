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
# * File Name : formats/L3Mobile_IE.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from binascii import hexlify
from libmich.core.element import Bit, Int, Str, Layer, \
    show, debug
from libmich.core.IANA_dict import IANA_dict
from libmich.formats.MCCMNC import MCC_dict, MNC_dict
#from libmich.formats.TS24007 import PD_dict

# TS 24.008 defines L3 signalling for mobile networks
#
# section 10: 
# IE coding
#
# describes mobile L3 signalling information element
# each L3 message composed of Information Element (IE)
#
# ...
# It's going to rock again!


#
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
        MCC = '%i%i%i' % (self.MCC1(), self.MCC2(), self.MCC3())
        if self.MNC3() == 0b1111:
            MNC = '%i%i' % (self.MNC1(), self.MNC2())
        else:
            MNC = '%i%i%i' % (self.MNC1(), self.MNC2(), self.MNC3())
        return '<[LAI]: MCC: %s / MNC: %s / LAC: %s>' % (MCC, MNC, hexlify(self.LAC()))
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
            s = ''
            for i in range(1, len(self)*2+self.odd()-1):
                s = ''.join((s, str(getattr(self, 'digit%s'%i)())))
            repr = '%s:%s' % (IDtype_dict[t], s)
        # tmsi
        elif t == 4:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.tmsi))
        else:
            repr = '%s:0x%s' % (IDtype_dict[t], hex(self.data))
        return '<[ID]: %s>' % repr
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

# section 10.5.1.10a
# Protocol Discriminator and Service Access Point Identifier
#SAPI_dict = {
#    0:'SAPI 0',
#    1:'reserved',
#    2:'reserved',
#    3:'SPAI 3'}
#    
#class SAPI_PD(Layer):
#    constructorList = [
#        Bit('spare', Pt=0, BitLen=2),
#        Bit('SPAI', ReprName='Service access point identifier', \
#            Pt=0, BitLen=2, Repr='hum', Dict=SAPI_dict),
#        Bit('PD', ReprName='Protocol discriminator', Pt=6, \
#            BitLen=4, Repr='hum', Dict=PD_dict)]

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
        s = ''
        for plmn in self:
            s = ''.join((s, str(plmn.interpret())))
        return s
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

#




#