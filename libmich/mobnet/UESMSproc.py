# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich
# * Version : 0.3.0
# *
# * Copyright © 2015. Benoit Michau. ANSSI.
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
# * File Name : mobnet/UESMSproc.py
# * Created : 2015-09-16
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#############
# TS 24.011 #
#############

from libmich.formats.L3Mobile_SMS import *
from .utils import *


class UESMSSigProc(UESigProc):
    '''
    UE related SMS control layer signalling procedure
    
    instance attributes:
        - Name: procedure name
        - Type: (protocol discriminator, type) of the initiating message
        - Filter: list of (protocol discriminator, type) expected in response
        - Timer: name of the timer to be run when a response is expected
        - Kwargs: procedure configuration parameters, used during initialization
        - UE: reference to the UEd instance to which the procedure applies
        - MME: reference to the MMEd instance handling the UEd / ENBd instances
        - _nas_resp: NAS PDU to be responded by output()
    
    init args:
        - UEd instance
        - potential kwargs that must match the keys in the local .Kwargs attribute
    
    process(pdu=None):
        - process the SMS CP PDU received by the MME server from the UE within NAS signalling
    
    output():
        - return the SMS CP PDU to be sent to the UE within a NAS signalling message structure, or None
    '''
    # to keep track of all PDU exchanged within the procedure, into the _pdu attribute
    # WNG: it will consume memory (nothing will be garbage-collected)
    TRACE = True
    
    # NAS domain
    Dom = 'SMS'
    # SMS-CP message type(s) expected on response
    Filter = None # or [(9, 4), (9 ,16)]
    # Timer name, referencing UEmgr.UEd timer
    Timer = None # or 'T1234'
    
    # specific SMS CP procedures parameters:
    Kwargs = {'TI': 0, 'TIO': 0}
    
    def __init__(self, ued, **kwargs):
        self.UE = ued
        self.SMSd = self.UE.MME.SMSd
        self.Name = self.__class__.__name__
        self._pdu = []
        #
        self.Kwargs = cpdict(self.__class__.Kwargs)
        for kw in kwargs:
            if kw in self.Kwargs:
                self.Kwargs[kw] = kwargs[kw]
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype='DBG', msg=''):
        self.UE._log(logtype, '[{0}] {1}'.format(self.Name, msg))
    
    def _trace(self, direction='UL', pdu=None):
        if self.TRACE:
            self._pdu.append( (time(), direction, pdu) )
        self.UE._log('TRACE_SMS_{0}'.format(direction), pdu.show())
    
    def process(self, naspdu=None):
        self._log('ERR', '[process] unsupported')
        # feeds with any input SMS-CP PDU value
    
    def output(self):
        self._log('ERR', '[output] unsupported')
        # returns a dict ('Code', 'Kwargs') to configure the S1AP MME initiated procedure
        return None
    
    def init_timer(self):
        if self.Timer is not None:
            self.TimerValue = getattr(self.UE, self.Timer, 10)
            self.TimerStart = time()
            self.TimerStop = self.TimerStart + self.TimerValue
    
    def timeout(self):
        self._log('WNG', 'timeout')
        self._end()
    
    def _end(self, state=None):
        # remove the SMS procedure (after verifying it's in the transaction stack)
        if self.UE.Proc['SMS'] and self.Kwargs['TIO'] in self.UE.Proc['SMS']:
            del self.UE.Proc['SMS'][self.Kwargs['TIO']]


# section 5, CM-procedures, Mobile Terminated SMS
# MME: CP-DATA -> UE: CP-ACK -> MME 
class SmsCpMt(UESMSSigProc):
    Filter = [(9, 4), (9, 16)]
    Timer = 'TC1star'
    Kwargs = {
        'TI': 0, # 1 bit, transaction alloc (0: sender, 1: receiver)
        'TIO': 0, # 3 bit, transaction id
        'Type': None, # 4 bit, message type (1: CP-DATA, 4: CP-ACK, 16: CP-ERROR)
        'Data': None, # bytes, message data for CP-DATA (SMS-RP, ...)
        }
    
    # default CP error cause, 17: network failure
    CAUSE_DEF = 17
    
    def output(self):
        # prepare the CP-DATA message to be sent to the UE
        cppdu = CP_DATA()
        #
        # transaction allocator and id
        cppdu[0].Pt = self.Kwargs['TI']
        cppdu[1].Pt = self.Kwargs['TIO']
        #
        if cppdu[3]() == 1 and self.Kwargs['Data'] is not None:
            cppdu[4].V.Pt = self.Kwargs['Data']
        #
        self._trace('DL', cppdu)
        self.init_timer()
        return cppdu
    
    def process(self, cppdu):
        self._trace('UL', cppdu)
        self._end()
        # log CP-ERROR, or just _end() with CP-ACK
        if cppdu[3]() == 16:
            self._log('ERR', 'CP-ERROR: {0}'.format(repr(cppdu[-1])))

# section 5, CM-procedures, Mobile Originated SMS
# UE: CP-DATA -> MME: CP-ACK -> UE 
class SmsCpMo(UESMSSigProc):
    Filter = None
    Timer = None
    Kwargs = {
        'TI': 0, # 1 bit, transaction alloc (0: sender, 1: receiver)
        'TIO': 0, # 3 bit, transaction id
        'Type': None, # 4 bit, message type (1: CP-DATA, 4: CP-ACK, 16: CP-ERROR)
        'CPCause': None, # uint8, CP error cause for CP-ERROR
        }
    
    def process(self, cppdu):
        self._trace('UL', cppdu)
        # build the TI for responding (opposite to the UE TI)
        TI = (1, 0)[cppdu[0]()]
        TIO = cppdu[1]()
        self.Kwargs['TIO'] = TIO
        #
        if cppdu[3]() != 1:
            # not CP-DATA: returns CP-ERROR, not compatible with protocol state
            cperr = CP_ERROR(TI=TI, TIO=TIO, CPCause=98)
            if isinstance(self.Kwargs['CPCause'], int):
                cperr[4].Pt = self.Kwargs['CPCause']
            self._end()
            self._trace('DL', cperr)
            return cperr
        #
        # forward the CP-DATA to the SMS relay (MME.SMSd)
        rppdu = cppdu[4].getobj()
        rpresp = None
        if rppdu:
            rpresp = self.SMSd.process_rp(rppdu)
        #
        # send back CP-ACK
        cpack = CP_ACK(TI=TI, TIO=TIO)
        self._end()
        self._trace('DL', cpack)
        #
        if rpresp:
            # and any CP_DATA including RP response if available
            proc = self.UE.init_sms_proc(SmsCpMt, TI=TI, TIO=TIO, Data=rpresp)
            return [cpack, proc.output()]
        else:
            return cpack
