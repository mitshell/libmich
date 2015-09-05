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
# * File Name : mobnet/ENBmgr.py
# * Created : 2015-07-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# export filtering
#__all__ = ['ENBd']

from .utils import *


class ENBd(SigStack):
    '''
    The ENBd instance handles all S1AP procedure related to an eNB itself (not UE-related).
    
    attributes:
        GID: Global eNB ID (PLMN, cellID)
        ID_PLMN: PLMN
        ID_ENB: cellID
        MME: reference to the MMEd parent instance
        
        Proc: dict of ongoing procedures (ENBSigProc), indexed by procedure code
        Proc_last: procedure code of the last procedure to have sent an S1AP PDU to the eNB
        
        Config: dict of parameters returned by the eNB at S1Setup (including 'SupportedTAs')
    '''
    # to keep track of all procedures run, into the _proc attribute
    # WNG: it will consume memory (nothing will be garbage-collected)
    TRACE = True
    
    def _log(self, logtype='DBG', msg=''):
        self.MME._log(logtype, '[eNB: {0}] {1}'.format(self.GID, msg))
    
    def __init__(self, enb_gid, mmed):
        # init identity
        self.GID = enb_gid
        self.ID_PLMN, self.ID_ENB = enb_gid[0], enb_gid[1]
        # reference to MME
        self.MME = mmed
        # init S1AP procedure stack
        self.Proc = {}
        self.Proc_last = None
        self._proc = []
        # init eNB Config information (filled-in during S1Setup)
        self.Config = {}
    
    def set_sk(self, sk):
        if sk is None:
            self.SK = None
            self.ADDRS = None
        else:
            self.SK = sk
            self.ADDRS = sk.getpaddrs()
    
    def reset(self):
        self.Proc = {}
        self.Proc_last = None
    
    #---------------#
    # dispatch PDU received  
    # to S1AP procedures
    #---------------#
    
    def process_pdu(self, pdu):
        # PDU can correspond to:
        # 1) a Class 2 eNB-initiated procedure -> process, no response (or send error)
        # 2) a Class 1 eNB-initiated procedure -> process, send response
        # 3) a Class 1 MME-initiated procedure pending -> process response, no response (or send error)
        procCode = pdu[1]['procedureCode']
        #
        # eNB-initiated procedure (class 1 or 2)
        if pdu[0] == 'initiatingMessage':
            if procCode == 15:
                # 1) handle error message reported by the eNB
                pIEs = pdu[1]['value'][1]['protocolIEs']
                for pIE in pIEs:
                    if pIE['id'] == 2:
                        cause = pIE['value'][1]
                        break
                self._log('ERR', 'eNB error ind, Cause: {0}'.format(cause))
                # this must correspond to the last procedure for which an S1AP PDU has been sent
                if self.Proc_last is not None and self.Proc_last in self.Proc:
                    # if this procedure is still ongoing, disable it
                    proc = self.Proc[self.Proc_last]
                    self._log('INF', 'disabling procedure: {0} ({1})'.format(proc.Name, proc.Code))
                    del self.Proc[self.Proc_last]
                    self.Proc_last = None
            elif procCode in ENBSigProcDispatch:
                # 2) initiate a procedure and potentially respond to it
                proc = ENBSigProcDispatch[procCode](self)
                if self.TRACE:
                    self._proc.append(proc)
                if proc in self.Proc:
                    # an identical procedure is already ongoing
                    self._log('WNG', 'overwriting procedure: {0} ({1})'.format(self.ENB, proc.Name, proc.Code))
                # this overwrites potential existing S1 procedure of the same type
                self.Proc[procCode] = proc
                self.Proc_last = proc.Code
                proc.process(pdu)
                return proc.output()
            else:
                # 3) invalid procedure code used by the eNB
                proc = MMEErrorInd(self, Cause=('protocol', 'semantic-error'))
                if self.TRACE:
                    self._proc.append(proc)
                self.Proc_last = proc.Code
                return proc.output()
        #
        # MME-initiated procedure (class 1)
        else:
            if procCode in self.Proc:
                # 1) the PDU must correspond to an already initiated procedure
                proc = self.Proc[procCode]
                proc.process(pdu)
                return proc.output()
            else:
                # 2) otherwise, send an error
                proc = MMEErrorInd(self, Cause=('protocol', 'semantic-error'))
                if self.TRACE:
                    self._proc.append(proc)
                self.Proc_last = proc.Code
                return proc.output()
    
    #---------------#
    # initiate S1AP procedure
    # and send PDU to eNB
    #---------------#
    
    def init_proc(self, proc, **kwargs):
        if self.SK is None:
            self._log('WNG', 'unable to initiate procedure {0} ({1}): no SCTP stream'.format(proc.Name, proc.Code))
            return
        proc = proc(self, **kwargs)
        if proc.Code in Class1SigProc:
            if proc.Code in self.Proc:
                self._log('WNG', 'a procedure {0} ({1}) is already ongoing'.format(proc.Name, proc.Code))
                return
            self.Proc[proc.Code] = proc
        if self.TRACE:
            self._proc.append(proc)
        self.Proc_last = proc.Code
        for pdu in proc.output():
            self.MME.send_enb(self.SK, pdu)


class ENBSigProc(SigProc):
    '''
    ENB related S1AP signalling procedure
    
    instance attributes:
        - Code: procedure code
        - Name: procedure name
        - Kwargs: procedure configuration parameters, used during initialization
        - ENB: reference to the ENBd instance responsible for the procedure
        - MME: reference to the MMEd instance handling the ENBd instance
        - _ret_pdu: list of PDU(s) to be sent to the eNB on .output()
    
    init args:
        - ENBd instance
        - potential kwargs that must match the keys in the local .Kwargs attribute
    
    process(pdu=None):
        - process the PDU received by the MME server from the eNB
    
    output():
        - return a list of PDU(s) to be sent by the MME server to the eNB;
          if empty, nothing to be sent to the eNB
    '''
    # to keep track of all PDU exchanged within the procedure, into the _pdu attribute
    # WNG: it will consume memory (nothing will be garbage-collected)
    TRACE = True
    
    # S1AP procedure code
    Code = None
    
    # specific dynamic procedures parameters:
    # S1AP ASN.1 protocolIE values are expected in initialization Kwargs
    Kwargs = {}
    
    def __init__(self, enbd, **kwargs):
        self.ENB = enbd
        self.MME = self.ENB.MME
        #
        self.Kwargs = cpdict(self.__class__.Kwargs)
        for kw in kwargs:
            if kw in self.Kwargs:
                self.Kwargs[kw] = kwargs[kw]
        #
        self.Name = self.__class__.__name__
        self._log('DBG', 'instantiating procedure')
        #
        self._pdu = []
        self._ret_pdu = []
    
    def _log(self, logtype='DBG', msg=''):
        self.ENB._log(logtype, '[{0}: {1}] {2}'.format(self.Code, self.Name, msg))
    
    def _trace(self, direction='UL', pdu=None):
        if self.TRACE:
            self._pdu.append( (time(), direction, pdu) )
    
    def process(self, pdu=None):
        self._log('ERR', '[process] unsupported')
        # feeds with any input PDU value
    
    def _build_error_ind(self, Cause=('protocol', 'abstract-syntax-error-reject')):
        # build an ErrorIndication to be encoded and sent
        self._log('WNG', 'error with Cause: {1}'.format(Cause))
        err = MMEErrorInd(self.ENB, Cause=Cause)
        if self.ENB.TRACE:
            self.ENB._proc.append(err)
        self.ENB.Proc_last = err.Code
        self._ret_pdu.extend( err.output() )
    
    def output(self):
        self._log('ERR', '[output] unsupported')
        # returns a list of output PDU values from .Kwargs
        return self._ret_pdu


#--------------------------#
# eNB-initiated procedures #
#--------------------------#

# Management, 8.7.1.2.2, class 1
class ENBReset(ENBSigProc):
    Code = 14

# Management, 8.7.2.2, class 2
# ErrorIndication PDU are caught in self.ENB.process_pdu()
class ENBErrorInd(ENBSigProc):
    Code = 15

# Management, 8.7.3, class 1
class S1Setup(ENBSigProc):
    Code = 17
    #
    Kwargs = {
        'TimeToWait': 'v10s', # enum: {v1s, v2s, v5s, v10s, v20s, v60s}
        }
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        # Global-ENB-ID is already collected by self.MME
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 1
        #
        if pIEs[ind]['id'] == 60:
            self.ENB.Config['ENBName'] = pIEs[ind]['value'][1]
            ind += 1
        #
        if pIEs[ind]['id'] == 64:
            TAs = pIEs[ind]['value'][1]
            self.ENB.Config['SupportedTAs'] = []
            #{'broadcastPLMNs':None, 'tAC':unpack('>H', TAs['tAC'])[0]}
            for ta in TAs:
                # convert to PLMN() / uint16
                plmns = []
                for bplmn in ta['broadcastPLMNs']:
                    plmns.append( PLMN() )
                    plmns[-1].map(bplmn)
                self.ENB.Config['SupportedTAs'].append( {'broadcastPLMNs':plmns, 'tAC':unpack('>H', ta['tAC'])[0]} )
            ind += 1
        else:
            self._build_s1setup_fail(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        if pIEs[ind]['id'] == 137:
            self.ENB.Config['PagingDRX'] = pIEs[ind]['value'][1]
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        # optional IEs
        while ind < len(pIEs):
            if pIEs[ind]['id'] == 128:
                self.ENB.Config['CSG-IdList'] = pIEs[ind]['value'][1]
                ind += 1
        #
        self._build_s1setup_resp()
        self.MME.add_enb(self.ENB)
    
    def _build_s1setup_fail(self, Cause=('misc', 'unspecified')):
        # build the S1SetupFailure to be encoded
        pIEs = []
        pIEs.append({'value': ('Cause', Cause),
                     'criticality': 'ignore',
                     'id': 2})
        if self.Kwargs['TimeToWait'] is not None:
            pIEs.append({'value': ('TimeToWait', self.Kwargs['TimeToWait']),
                         'criticality': 'ignore',
                         'id': 65})
        #
        self._ret_pdu.append( ('unsuccessfulOutcome',
                               {'procedureCode': self.Code,
                                'value': ('S1SetupFailure', {'protocolIEs':pIEs}),
                                'criticality': 'reject'}) )
        self.Stack._log('WNG', 'S1SetupFailure with Cause: {0}'.format(Cause))
    
    def _build_s1setup_resp(self):
        # build the S1SetupResponse to be encoded
        pIEs = []
        if self.MME.ConfigS1['MMEname'] is not None:
            pIEs.append({'value': ('MMEname', self.MME.ConfigS1['MMEname']),
                         'criticality': 'ignore',
                         'id': 61})
        pIEs.append({'value': ('ServedGUMMEIs', self.MME.ConfigS1['ServedGUMMEIs']),
                     'criticality': 'reject',
                     'id': 105})
        pIEs.append({'value': ('RelativeMMECapacity', self.MME.ConfigS1['RelativeMMECapacity']),
                     'criticality': 'ignore',
                     'id': 87})
        if self.MME.ConfigS1['MMERelaySupportIndicator'] is not None:
            pIEs.append({'value': ('MMERelaySupportIndicator', self.MME.ConfigS1['MMERelaySupportIndicator']),
                         'criticality': 'ignore',
                         'id': 163})
        #
        self._ret_pdu.append( ('successfulOutcome',
                               {'procedureCode': self.Code,
                                'value': ('S1SetupResponse', {'protocolIEs':pIEs}),
                                'criticality': 'reject'}) )
        self._log('DBG', 'S1SetupResponse, supported TAs: {0}'.format(self.ENB.Config['SupportedTAs']))
    
    def output(self):
        for pdu in self._ret_pdu:
            self._trace('DL', pdu)
        # remove from the ENB procedure stack
        del self.ENB.Proc[self.Code]
        # keep track as the last procedure to have sent PDU to the eNB
        self.ENB.Proc_last = self.Code
        #
        return self._ret_pdu


# Management, 8.7.4, class 1
class ENBConfigUpdate(ENBSigProc):
    Code = 29

# ENB direct info transfer, 8.13, class 2
class ENBDirectInfoTransfer(ENBSigProc):
    Code = 37

# ENB config transfer, 8.15, class 2
class ENBConfigTransfer(ENBSigProc):
    Code = 40

# LPPa transport, 8.17.2.4, class 2
class UplinkNonUELPPaTransport(ENBSigProc):
    Code = 47

#--------------------------#
# MME-initiated procedures #
#--------------------------#

# Paging, 8.5.1, class 2
class Paging(ENBSigProc):
    Code = 10
    #
    Kwargs = {
        'UEIdentityIndexValue': None,
        'UEPagingID': None,
        'PagingDRX': None, # optional
        'CNDomain': None,
        'TAIList': None,
        'CSG_IdList': None, # optional
        'PagingPriority': None, # optional
        }
    
    def output(self):
        # stack all protocol IEs
        pIEs = []
        pIEs.append({'value': ('UEIdentityIndexValue', self.Kwargs['UEIdentityIndexValue']),
                     'criticality': 'ignore',
                     'id': 80})
        pIEs.append({'value': ('UEPagingID', self.Kwargs['UEPagingID']),
                     'criticality': 'ignore',
                     'id': 43})
        if self.Kwargs['PagingDRX'] is not None:
            pIEs.append({'value': ('PagingDRX', self.Kwargs['PagingDRX']),
                         'criticality': 'ignore',
                         'id': 44})
        pIEs.append({'value': ('CNDomain', self.Kwargs['CNDomain']),
                     'criticality': 'ignore',
                     'id': 109})
        pIEs.append({'value': ('TAIList', self.Kwargs['TAIList']),
                     'criticality': 'ignore',
                     'id': 46})
        # TODO: process optional args: CSG_IdList, PagingPriority
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('Paging', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        self._log('DBG', 'identity: {0}'.format(self.Kwargs['UEPagingID']))
        # remove from the ENB procedure stack
        if self.Code in self.ENB.Proc:
            del self.ENB.Proc[self.Code]
        # keep track as the last procedure to have sent PDU to the eNB
        self.ENB.Proc_last = self.Code
        self._trace('DL', pdu)
        return [pdu]

# Management, 8.7.1.2.2, class 1
class MMEReset(ENBSigProc):
    Code = 14

# Management, 8.7.2.1, class 2
class MMEErrorInd(ENBSigProc):
    Code = 15
    #
    Kwargs = {
        'Cause': None, # optional
        'CriticalityDiagnostics': None # optional
        }
    
    def output(self):
        # build the ErrorIndication value to be encoded
        pIEs = []
        if self.Kwargs['Cause'] is not None:
            pIEs.append({'value': ('Cause', self.Kwargs['Cause']),
                         'criticality': 'ignore',
                         'id': 2})
        if self.Kwargs['CriticalityDiagnostics'] is not None:
            pIEs.append({'value': ('CriticalityDiagnostics', self.Kwargs['CriticalityDiagnostics']),
                         'criticality': 'ignore',
                         'id': 58})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('ErrorIndication', {'protocolIEs': pIEs}),
                'criticality': 'ignore'})
        #
        # remove from the ENB procedure stack
        if self.Code in self.ENB.Proc:
            del self.ENB.Proc[self.Code]
        self._trace('DL', pdu)
        return [pdu]

# Management, 8.7.5, class 1
class MMEConfigUpdate(ENBSigProc):
    Code = 30

# Management, 8.7.6, class 2
class OverloadStart(ENBSigProc):
    Code = 34

# Management, 8.7.7, class 2
class OverloadStop(ENBSigProc):
    Code = 35

# Warning message, 8.12.1, class 1
class WriteReplaceWarning(ENBSigProc):
    Code = 36

# Warning message, 8.12.2, class 1
class Kill(ENBSigProc):
    Code = 43

# RAN info transfer, 8.14, class 2
class MMEDirectInfoTransfer(ENBSigProc):
    Code = 38

# RAN config transfer, 8.16, class 2
class MMEConfigTransfer(ENBSigProc):
    Code = 41

# LPPa transport, 8.17.2.3, class 2
class DownlinkNonUELPPaTransport(ENBSigProc):
    Code = 46

#--------------------------#
# unimplemented procedures #
#--------------------------#

#39: PrivateMessage
#49: PWSRestartInd

#----------------------------#
# S1AP Signalling Procedures #
#----------------------------#

# utils.py: S1APENBProcCodes = [14, 15, 17, 29, 30, 34, 35, 36, 37, 38, 40, 41, 43, 46, 47]
# S1APENBProcCodes: S1AP procedure codes for eNB-related signalling
# Class 1 procedures: need response
#   initiatingMessage -> successfulOutcome [ / unsuccessfulOutcome]
Class1SigProc = [14, 17, 29, 30, 36, 43]
# class 2: does not need response
#   initiatingMessage
Class2SigProc = [10, 15, 34, 35, 37, 38, 40, 41, 46, 47]

# eNB initiated procedures
ENBSigProcDispatch = {
    # Mgt proc
    14: ENBReset, # class 1
    15: ENBErrorInd, # class 2
    17: S1Setup, # class 1
    29: ENBConfigUpdate, # class 1
    # Info transfer, class 2
    37: ENBDirectInfoTransfer,
    40: ENBConfigTransfer,
    # LPPa, class 2
    47: UplinkNonUELPPaTransport,
}

# MME initiated procedures
MMESigProcDispatch = {
    10: Paging, # class 2
    # Mgt proc
    14: MMEReset, # class 1
    15: MMEErrorInd, # class 2
    30: MMEConfigUpdate, # class 1
    34: OverloadStart, # class 2
    35: OverloadStop, # class 2
    # Warning message bcast, class 1
    36: WriteReplaceWarning,
    43: Kill,
    # Info transfer, class 2
    38: MMEDirectInfoTransfer,
    41: MMEConfigTransfer,
    # LPPa, class 2
    46: DownlinkNonUELPPaTransport,
}
