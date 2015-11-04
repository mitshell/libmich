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
# * File Name : mobnet/UES1proc.py
# * Created : 2015-07-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#############
# TS 36.413 #
#############

from socket import inet_ntoa, inet_aton
from .utils import *

#-----------------#
# S1AP signalling #
# procedures      #
#-----------------#

class UES1SigProc(UESigProc):
    '''
    UE related S1AP signalling procedure
    
    instance attributes:
        - Code: procedure code
        - Name: procedure name
        - Kwargs: procedure configuration parameters, used during initialization
        - UE: reference to the UEd instance to which the procedure applies
        - ENB: reference to the ENBd instance responsible for the procedure
        - MME: reference to the MMEd instance handling the UEd / ENBd instances
        - _ret_pdu: list of PDU(s) to be sent to the eNB on .output()
    
    init args:
        - UEd instance
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
    
    def __init__(self, ued, **kwargs):
        self.UE = ued
        self.MME = self.UE.MME
        self.Name = self.__class__.__name__
        #
        self.init_enb()
        #
        self.Kwargs = cpdict(self.__class__.Kwargs)
        for kw in kwargs:
            if kw in self.Kwargs:
                self.Kwargs[kw] = kwargs[kw]
        #
        self._log('DBG', 'instantiating procedure')
        self._pdu = []
        self._ret_pdu = []
    
    def init_enb(self):
        if self.UE.ENB is None:
            raise(MMEErr('[MME: {0}] [UE: {1}] Error, no active S1 connection'.format(self.MME.MME_GUMMEI, self.UE.IMSI)))
            #self._log('ERR', 'No active S1 connection')
        self.ENB = self.UE.ENB
        self.MME_UE_ID = self.UE.S1['MME_UE_ID']
        self.ENB_UE_ID = self.UE.S1['ENB_UE_ID']
    
    def _log(self, logtype='DBG', msg=''):
        self.UE._log(logtype, '[ENB (S1AP): {0}] [{1}: {2}] {3}'.format(self.ENB.GID, self.Code, self.Name, msg))
    
    def _trace(self, direction='UL', pdu=None):
        if self.TRACE:
            self._pdu.append( (time(), direction, pdu) )
    
    def process(self, pdu=None):
        self._log('ERR', '[process] unsupported')
        # feeds with any input PDU value
    
    def _build_error_ind(self, Cause=('protocol', 'abstract-syntax-error-reject')):
        # build an ErrorIndication to be encoded and sent
        self._log('WNG', 'error with Cause: {1}'.format(Cause))
        err = MMEErrorInd(self.UE, Cause=Cause)
        if self.ENB.TRACE:
            self.ENB._proc.append(err)
        self.ENB.Proc_last = err.Code
        self._ret_pdu.extend( err.output() )
    
    def output(self):
        self._log('ERR', '[output] unsupported')
        # returns a list of output PDU values from .Kwargs
        return self._ret_pdu
    
    def _process_nas(self, naspdu):
        nas_resp = self.UE.process_naspdu(naspdu)
        #
        if nas_resp:
            # check if the NAS response needs to be wrapped in a specific S1AP message
            if self.UE._s1dl_struct is not None:
                if isinstance(nas_resp, list):
                    # this case should never happened
                    self._log('ERR', 'packaging multiple DL NAS PDU within S1 ERAB procedure is not supported')
                    self.UE._s1dl_struct = None
                    return  
                # S1 specific parameters are stored in self.UE._s1dl_struct
                s1_struct = self.UE._s1dl_struct
                if s1_struct['Code'] == 5:
                    # E-RABSetup: set the NAS-PDU within the 1st ERAB ctxt
                    s1_struct['Kwargs']['E_RABToBeSetupListBearerSUReq'][0]['value'][1]['nAS-PDU'] = bytes(nas_resp)
                    proc = self.UE.init_s1_proc(ERABSetup, **s1_struct['Kwargs'])
                    self._ret_pdu.extend(proc.output())
                elif s1_struct['Code'] == 7:
                    # E-RABRelease: set the NAS-PDU in the S1AP PDU
                    s1_struct['Kwargs']['NAS_PDU'] = bytes(nas_resp)
                    proc = self.UE.init_s1_proc(ERABRelease, **s1_struct['Kwargs'])
                    self._ret_pdu.extend(proc.output())
                elif s1_struct['Code'] == 9:
                    # InitialContextSetup: set the NAS-PDU within the 1st ERAB ctxt
                    s1_struct['Kwargs']['E_RABToBeSetupListCtxtSUReq'][0]['value'][1]['nAS-PDU'] = bytes(nas_resp)
                    proc = self.UE.init_s1_proc(InitialContextSetup, **s1_struct['Kwargs'])
                    self._ret_pdu.extend(proc.output())
                elif s1_struct['Code'] == 23:
                    # UEContextRelease: it does not contain any NAS-PDU, so we need 2 S1AP PDU
                    proc_nas = self.UE.init_s1_proc(DownlinkNASTransport, NAS_PDU=nas_resp)
                    self._ret_pdu.extend(proc_nas.output())
                    proc_s1 = self.UE.init_s1_proc(UEContextRelease, **s1_struct['Kwargs'])
                    self._ret_pdu.extend(proc_s1.output())
                else:
                    self._log('ERR', 'S1AP message {0} for DL NAS PDU not supported, using DownlinkNASTransport instead'\
                              .format(s1_struct['Code']))
                    proc = self.UE.init_s1_proc(DownlinkNASTransport, NAS_PDU=nas_resp)
                    self._ret_pdu.extend(proc.output())
                self.UE._s1dl_struct = None
            else:
                if isinstance(nas_resp, list):
                    proc = []
                    for nr in nas_resp:
                        proc.append( self.UE.init_s1_proc(DownlinkNASTransport, NAS_PDU=nr) )
                        self._ret_pdu.extend(proc[-1].output())
                else:
                    proc = self.UE.init_s1_proc(DownlinkNASTransport, NAS_PDU=nas_resp)
                    self._ret_pdu.extend(proc.output())
        #
        elif self.UE._s1dl_struct is not None:
            s1_struct = self.UE._s1dl_struct
            if s1_struct['Code'] == 9:
                # in case of SERVICE REQUEST, ERAB needs to be established at S1 without NAS signalling
                proc = self.UE.init_s1_proc(InitialContextSetup, **s1_struct['Kwargs'])
            elif s1_struct['Code'] == 23:
                # UEContextRelease
                proc = self.UE.init_s1_proc(UEContextRelease, **s1_struct['Kwargs'])
            else:
                self._log('ERR', 'S1AP message {0} not supported'.format(s1_struct['Code']))
                # use an "empty" S1 procedure
                proc = self.__class__()
            self.UE._s1dl_struct = None
            self._ret_pdu.extend(proc.output())

#--------------------------#
# eNB-initiated procedures #
#--------------------------#

# E-RAB management, 8.2.3.2.2, class 2
class ERABReleaseInd(UES1SigProc):
    Code = 8

# Context management, 8.3.2, class 2
class UEContextReleaseRequest(UES1SigProc):
    Code = 18
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        if pIEs[ind]['id'] == 2:
            cause = pIEs[ind]['value'][1]
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        # optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        self._log('INF', 'Cause: {0}'.format(cause))
        #
        # ensures the UE still has an S1 connection
        if self.UE.ENB is not None:
            proc = self.UE.init_s1_proc(UEContextRelease, Cause=cause)
            self._ret_pdu.extend(proc.output())
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
    
    def output(self):
        return self._ret_pdu

# Handover, 8.4.1, class 1
class HandoverPreparation(UES1SigProc):
    Code = 0

# Handover, 8.4.3, class 2
class HandoverNotification(UES1SigProc):
    Code = 2

# Handover, 8.4.4, class 1 (new UE)
class PathSwitchRequest(UES1SigProc):
    Code = 3

# Handover, 8.4.5, class 1
class HandoverCancellation(UES1SigProc):
    Code = 4

# Handover, 8.4.6, class 2
class ENBStatusTransfer(UES1SigProc):
    Code = 24

# NAS transport, 8.6.2.1, class 2
class InitialUEMessage(UES1SigProc):
    Code = 12
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 1
        #
        if pIEs[ind]['id'] == 26:
            # NAS-PDU are decoded by the MMEd instance (see ue_decode_nas())
            nas_pdu = pIEs[ind]['value'][1]
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        if pIEs[ind]['id'] == 67:
            # convert the TAI
            self.UE.S1['TAI'] = convert_tai(pIEs[ind]['value'][1])
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        if pIEs[ind]['id'] == 100:
            # convert the Global CellID
            self.UE.S1['EUTRAN-CGI'].append( convert_eutran_cgi(pIEs[ind]['value'][1]) )
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        if pIEs[ind]['id'] == 134:
            self.UE.S1['RRC-Establishment-Cause'] = pIEs[ind]['value'][1]
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        # optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            if pIEs[ind]['id'] != 96:
                opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        self._process_nas(nas_pdu)
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
    
    def output(self):
        return self._ret_pdu

# NAS transport, 8.6.2.3, class 2
class UplinkNASTransport(UES1SigProc):
    Code = 13
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        if pIEs[ind]['id'] == 26:
            # NAS-PDU are decoded by the MMEd instance (see ue_decode_nas())
            nas_pdu = pIEs[ind]['value'][1]
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        if pIEs[ind]['id'] == 100:
            # convert the Global CellID
            self.UE.S1['EUTRAN-CGI'].append( convert_eutran_cgi(pIEs[ind]['value'][1]) )
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        if pIEs[ind]['id'] == 67:
            # convert the TAI
            self.UE.S1['TAI'] = convert_tai(pIEs[ind]['value'][1])
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-reject'))
            return
        #
        # optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        self._process_nas(nas_pdu)
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
    
    def output(self):
        return self._ret_pdu

# NAS transport, 8.6.2.4, class 2
class NASNonDeliveryInd(UES1SigProc):
    Code = 17

# Management, 8.7.2.2, class 2
# ErrorIndication PDU are caught in self.UE.process_pdu()
class ENBErrorInd(UES1SigProc):
    Code = 15

# S1 CDMA management, 8.8.2.2, class 2
class UplinkS1cdma2000tun(UES1SigProc):
    Code = 20

# UE capability info, 8.9, class 2
class UECapabilityInfoInd(UES1SigProc):
    Code = 22
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        if pIEs[ind]['id'] == 74:
            # try decode the LTE RRC info
            radcap = pIEs[ind]['value'][1]
            if self.UE.CAP['UERadCap'] is None or self.UE.CAP['UERadCap'][0] != radcap: 
                self.UE.CAP['UERadCap'] = (radcap, decode_UERadioCapability(radcap))
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
    
    def output(self):
        return self._ret_pdu

# Trace, 8.10.2, class 2
class TraceFailureInd(UES1SigProc):
    Code = 28

# Trace, 8.10.4, class 2
class CellTrafficTrace(UES1SigProc):
    Code = 42

# Location report, 8.11.2, class 2
class LocationReportingFailureInd(UES1SigProc):
    Code = 32

# Location report, 8.11.3, class 2
class LocationReport(UES1SigProc):
    Code = 33

# LPPa transport, 8.17.2.2, class 2
class UplinkUELPPaTransport(UES1SigProc):
    Code = 45

#--------------------------#
# MME-initiated procedures #
#--------------------------#

# E-RAB management, 8.2.1, class 1
class ERABSetup(UES1SigProc):
    Code = 5
    #
    Kwargs = {
        'UEAggregateMaximumBitrate': None,
        'E_RABToBeSetupListBearerSUReq': None, # contains the NAS-PDU
        }
    
    def output(self):
        # send ERABSetupRequest
        # (an InitialContextSetup must have happened already)
        #
        # E_RABSetupListReq, list of E-RABSetupItemReq:
        # e-RAB-ID, e-RABlevelQoSparameters, transportLayerAddress (IP address of the S-GW), gTP-TEID (TEID from the S-GW), nAS-PDU
        #
        # stack all protocol IEs
        pIEs = []
        #
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        if self.Kwargs['UEAggregateMaximumBitrate'] is not None:
            pIEs.append({'value': ('UEAggregateMaximumBitrate', self.Kwargs['UEAggregateMaximumBitrate']),
                         'criticality': 'reject',
                         'id': 66})
        #
        pIEs.append({'value': ('E-RABToBeSetupListBearerSUReq', self.Kwargs['E_RABToBeSetupListBearerSUReq']),
                     'criticality': 'reject',
                     'id': 16})
        #
        # TODO: process optional IEs
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('E-RABSetupRequest', {'protocolIEs':pIEs}),
                'criticality': 'reject'})
        #
        self._trace('DL', pdu)
        return [pdu]
    
    def process(self, pdu):
        # process ERABSetupResponse
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        # successful outcome is the only response possible
        if pIEs[ind]['id'] == 28:
            # check the E-RABSetupItemBearerSURes against self.UE.ESM['RAB']
            rabid_list = []
            for item in pIEs[ind]['value'][1]:
                if item['id'] == 39:
                    value = item['value'][1]
                    rabid = value['e-RAB-ID']
                    if rabid not in self.UE.ESM['RAB']:
                        self._log('WNG', 'invalid E-RAB-ID: {0}'.format(rabid))
                    else:
                        rab = self.UE.ESM['RAB'][rabid]
                        rab['ENB-GTP-TEID'] = unpack('>I', value['gTP-TEID'])[0]
                        rab['ENB-TransportLayerAddress'] = inet_ntoa(pack('>I', value['transportLayerAddress'][0]))
                        self.UE.gtp_enable(rabid)
                        rabid_list.append(rabid)
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        # optional IEs
        while ind < len(pIEs):
            if pIEs[ind]['id'] == 29:
                # list of E-RAB the eNB failed to establish
                self._log('WNG', 'failed E-RAB: {0}'.format(pIEs[ind]['value'][1]))
                # TODO: disable failed ERAB in self.UE.ESM['RAB']
                ind += 1
        #
        # unprocessed optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        self._log('DBG', 'successful outcome, E-RAB ID activated: {0}'.format(rabid_list))
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]


# E-RAB management, 8.2.2, class 1
class ERABModify(UES1SigProc):
    Code = 6

# E-RAB management, 8.2.3, class 1
class ERABRelease(UES1SigProc):
    Code = 7
    #
    Kwargs = {
        'UEAggregateMaximumBitrate': None, # optional
        'E_RABList': None,
        'NAS_PDU': None, # optional
        }
    
    def output(self):
        # send ERABReleaseCommand
        # (multiple E-RAB should have been established already)
        #
        # E_RABSList, list of E-RABItem:
        # e-RAB-ID, cause
        #
        # stack all protocol IEs
        pIEs = []
        #
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        if self.Kwargs['UEAggregateMaximumBitrate'] is not None:
            pIEs.append({'value': ('UEAggregateMaximumBitrate', self.Kwargs['UEAggregateMaximumBitrate']),
                         'criticality': 'reject',
                         'id': 66})
        pIEs.append({'value': ('E-RABList', self.Kwargs['E_RABList']),
                     'criticality': 'ignore',
                     'id': 33})
        if self.Kwargs['NAS_PDU'] is not None:
            pIEs.append({'value': ('NAS-PDU', self.Kwargs['NAS_PDU']),
                         'criticality': 'ignore',
                         'id': 26})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('E-RABReleaseCommand', {'protocolIEs':pIEs}),
                'criticality': 'reject'})
        #
        self._trace('DL', pdu)
        return [pdu]
    
    def process(self, pdu):
        # process ERABReleaseResponse
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        # successful outcome is the only response possible
        if pIEs[ind]['id'] == 69:
            # check the E-RABReleaseListBearerRelComp against self.UE.ESM['active']
            rabid_list = []
            for item in pIEs[ind]['value'][1]:
                if item['id'] == 15:
                    value = item['value'][1]
                    rabid = value['e-RAB-ID']
                    if rabid not in self.UE.ESM['active']:
                        self._log('WNG', 'invalid E-RAB-ID: {0}'.format(rabid))
                    else:
                        self.UE.gtp_disable(rabid)
                        rabid_list.append(rabid)
            ind += 1
        else:
            self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
        #
        # optional IEs
        while ind < len(pIEs):
            if pIEs[ind]['id'] == 34:
                # list of E-RAB the eNB failed to release
                self._log('WNG', 'failed E-RAB: {0}'.format(pIEs[ind]['value'][1]))
                # TODO: what to do with that ???
                ind += 1
        #
        # unprocessed optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        self._log('DBG', 'successful outcome, E-RAB ID released: {0}'.format(rabid_list))
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]

# Context management, 8.3.1, class 1
# WNG: limitation, only a single E-RAB context item is checked in the response
# IOCTL, interface with MME.GTPd to enable the GTP tunnel
class InitialContextSetup(UES1SigProc):
    Code = 9
    #
    Kwargs = {
        'UEAggregateMaximumBitrate': None,
        'E_RABToBeSetupListCtxtSUReq': None, # contains the NAS-PDU
        'UESecurityCapabilities': None,
        'SecurityKey': None,
        'TraceActivation': None, # optional
        'HandoverRestrictionList': None, # optional
        'UERadioCapability': None, # optional
        'SubscriberProfileIDforRFP': None, # optional
        'CSFallbaclIndicator': None, # optional
        'SRVCCOperationPossible': None, # optional
        'CSGMembershipStatus': None, # optional
        'LAI': None, # optional
        'GUMMEI': None, # optional
        'MME_UE_S1AP_ID_2': None, # optional
        'ManagementBasedMDTAllowed': None, # optional
        'MDTPLMNList': None, # optional
        'AdditionalCSFallbackIndicator': None, # optional
        }
    
    def output(self):
        # send InitialContextSetupRequest
        #
        # E_RABSetupListReq, list of E-RABSetupItemReq:
        # e-RAB-ID, e-RABlevelQoSparameters, transportLayerAddress (IP address of the S-GW), gTP-TEID (TEID from the S-GW), nAS-PDU
        #
        # stack all protocol IEs
        pIEs = []
        #
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        pIEs.append({'value': ('UEAggregateMaximumBitrate', self.Kwargs['UEAggregateMaximumBitrate']),
                     'criticality': 'reject',
                     'id': 66})
        #
        pIEs.append({'value': ('E-RABToBeSetupListCtxtSUReq', self.Kwargs['E_RABToBeSetupListCtxtSUReq']),
                     'criticality': 'reject',
                     'id': 24})
        #
        pIEs.append({'value': ('UESecurityCapabilities', self.Kwargs['UESecurityCapabilities']),
                     'criticality': 'reject',
                     'id': 107})
        #
        pIEs.append({'value': ('SecurityKey', self.Kwargs['SecurityKey']),
                     'criticality': 'reject',
                     'id': 73})
        #
        # TODO: process optional IEs
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('InitialContextSetupRequest', {'protocolIEs':pIEs}),
                'criticality': 'reject'})
        #
        self._trace('DL', pdu)
        return [pdu]
    
    def process(self, pdu):
        # process InitialContextSetupResponse or InitialContextSetupFailure
        self._trace('UL', pdu)
        #
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        if pdu[0] == 'successfulOutcome':
            rabid_list = []
            if pIEs[ind]['id'] == 51:
                # check the E-RABSetupItemCtxtSURes against self.UE.ESM['RAB']
                for item in pIEs[ind]['value'][1]:
                    if item['id'] == 50:
                        value = item['value'][1]
                        rabid = value['e-RAB-ID']
                        if rabid not in self.UE.ESM['RAB']:
                            self._log('WNG', 'invalid E-RAB-ID: {0}'.format(rabid))
                        else:
                            rab = self.UE.ESM['RAB'][rabid]
                            rab['ENB-GTP-TEID'] = unpack('>I', value['gTP-TEID'])[0]
                            rab['ENB-TransportLayerAddress'] = inet_ntoa(pack('>I', value['transportLayerAddress'][0]))
                            self.UE.gtp_enable(rabid)
                            rabid_list.append(rabid)
                ind += 1
            else:
                self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
            #
            # optional IEs
            while ind < len(pIEs):
                if pIEs[ind]['id'] == 48:
                    # list of E-RAB the eNB failed to establish
                    self._log('WNG', 'failed E-RAB: {1}'.format(pIEs[ind]['value'][1]))
                    ind += 1
            #
            # unprocessed optional IEs
            opt = []
            while ind < len(pIEs):
                # no need to process S-TMSI
                opt.append(pIEs[ind]['id'])
                # TODO: process others optional protocolIEs
                ind += 1
            if opt:
                self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
            #
            self._log('DBG', 'successful outcome, E-RAB ID activated: {0}'.format(rabid_list))
        #
        else:
            cause = None
            # unsuccessfulOutcome
            if pIEs[ind]['id'] == 2:
                cause = pIEs[ind]['value'][1]
                ind += 1
            else:
                self._build_error_ind(Cause=('protocol', 'abstract-syntax-error-ignore-and-notify'))
            # TODO: process optional CriticalityDiagnostics
            self._log('ERR', 'failure, cause: {1}'.format(cause))
            # disable all active E-RAB
            self.UE.gtp_disable()
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]

# Context management, 8.3.3, class 1
class UEContextRelease(UES1SigProc):
    Code = 23
    #
    Kwargs = {
        'Cause': ('misc', 'unspecified'),
        }
    
    def output(self):
        # send UEContextReleaseCommand
        UE_ID = ('uE-S1AP-ID-pair', {'mME-UE-S1AP-ID': self.MME_UE_ID,
                                     'eNB-UE-S1AP-ID': self.ENB_UE_ID})
        # stack all protocol IEs
        pIEs = []
        #
        pIEs.append({'value': ('UE-S1AP-IDs', UE_ID),
                     'criticality': 'reject',
                     'id': 99})
        #
        pIEs.append({'value': ('Cause', self.Kwargs['Cause']),
                     'criticality': 'ignore',
                     'id': 2})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('UEContextReleaseCommand', {'protocolIEs':pIEs}),
                'criticality': 'reject'})
        #
        self._log('DBG', 'command cause: {0}'.format(self.Kwargs['Cause']))
        self._trace('DL', pdu)
        return [pdu]
    
    def process(self, pdu):
        self._trace('UL', pdu)
        #
        # process UEContextReleaseComplete
        # collect all protocol IEs
        pIEs = pdu[1]['value'][1]['protocolIEs']
        ind = 2
        #
        # optional IEs
        opt = []
        while ind < len(pIEs):
            # no need to process S-TMSI
            opt.append(pIEs[ind]['id'])
            # TODO: process others optional protocolIEs
            ind += 1
        if opt:
            self._log('DBG', 'unprocessed optional IEs: {0}'.format(opt))
        #
        # remove S1AP connectivity info for the UE
        self.UE.s1_unset()
        # disable all active E-RAB
        self.UE.gtp_disable()
        # disable all ongoing NAS signalling procedures for the UE
        # TODO: this could depend on the ContextRelease Cause
        self.UE.nas_reset_proc()
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]

# Context management, 8.3.4, class 1
class UEContextModification(UES1SigProc):
    Code = 21
    
# Handover, 8.4.2, class 1
class HandoverResourceAlloc(UES1SigProc):
    Code = 1

# Handover, 8.4.7, class 2
class MMEStatusTransfer(UES1SigProc):
    Code = 25

# NAS transport, 8.6.2.2, class 2
class DownlinkNASTransport(UES1SigProc):
    Code = 11
    #
    Kwargs = {
        'NAS_PDU': None,
        'HandoverRestrictionList': None, # optional
        'SubscriberProfileIDforRFP': None # optional
        }
    
    def output(self):
        # send DownlinkNASTransport
        # stack all protocol IEs
        pIEs = []
        #
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        pIEs.append({'value': ('NAS-PDU', bytes(self.Kwargs['NAS_PDU'])),
                     'criticality': 'reject',
                     'id': 26})
        #
        # optional IEs
        if self.Kwargs['HandoverRestrictionList'] is not None:
            pIEs.append({'value': ('HandoverRestrictionList', self.Kwargs['HandoverRestrictionList']),
                         'criticality': 'ignore',
                         'id': 41})
        #
        if self.Kwargs['SubscriberProfileIDforRFP'] is not None:
            pIEs.append({'value': ('SubscriberProfileIDforRFP', self.Kwargs['SubscriberProfileIDforRFP']),
                         'criticality': 'ignore',
                         'id': 106})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('DownlinkNASTransport', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
        self._trace('DL', pdu)
        return [pdu]

# Management, 8.7.2.1, class 2
class MMEErrorInd(UES1SigProc):
    Code = 15
    #
    Kwargs = {
        'Cause': None, # optional
        'CriticalityDiagnostics': None # optional
        }
    
    def output(self):
        # send ErrorIndication
        # stack all protocol IEs
        pIEs = []
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        # optional IEs
        if self.Kwargs['Cause'] is not None:
            pIEs.append({'value': ('Cause', self.Kwargs['Cause']),
                         'criticality': 'ignore',
                         'id': 2})
        #
        if self.Kwargs['CriticalityDiagnostics'] is not None:
            pIEs.append({'value': ('CriticalityDiagnostics', self.Kwargs['CriticalityDiagnostics']),
                         'criticality': 'ignore',
                         'id': 58})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('ErrorIndication', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
        self._trace('DL', pdu)
        return [pdu]

# S1 CDMA management, 8.8.2.1, class 2
class DownlinkS1cdma2000tun(UES1SigProc):
    Code = 19

# Trace, 8.10.1, class 2
class TraceStart(UES1SigProc):
    Code = 27
    #
    Kwargs = {
        'E_UTRAN_Trace-ID': '\x02\xf8\x96\0\0\0\0\x01',
        'InterfacesToTrace': (0b11100000, 8),
        'TraceDepth': 'medium',
        'TransportLayerAddress': (unpack('!I', inet_aton('127.0.1.100'))[0], 32), # traceCollectionEntityIPAddress
        }
    
    def output(self):
        # pack everything in the TraceActivation
        traceActivation = {
            'e-UTRAN-Trace-ID': self.Kwargs['E_UTRAN_Trace-ID'],
            'interfacesToTrace': self.Kwargs['InterfacesToTrace'],
            'traceDepth': self.Kwargs['TraceDepth'],
            'traceCollectionEntityIPAddress': self.Kwargs['TransportLayerAddress']}
        
        # stack all protocol IEs
        pIEs = []
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        pIEs.append({'value': ('TraceActivation', traceActivation),
                     'criticality': 'ignore',
                     'id': 25})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('TraceStart', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
        self._trace('DL', pdu)
        return [pdu]

# Trace, 8.10.3, class 2
class DeactivateTrace(UES1SigProc):
    Code = 26

# Location reporting, 8.11.1, class 2
class LocationReportingCtrl(UES1SigProc):
    Code = 31
    #
    Kwargs = {
        'EventType': 'direct', # direct, change-of-serve-cell, stop-change-of-serve-cell
        'ReportArea': 'ecgi'
        }
    
    def output(self):
        # pack everything in the TraceActivation
        requestType = {
            'eventType': self.Kwargs['EventType'],
            'reportArea': self.Kwargs['ReportArea']}
        
        # stack all protocol IEs
        pIEs = []
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        pIEs.append({'value': ('RequestType', requestType),
                     'criticality': 'ignore',
                     'id': 98})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('LocationReportingControl', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
        self._trace('DL', pdu)
        return [pdu]
    

# LPPa transport, 8.17.2, class 2
class DownlinkUELPPaTransport(UES1SigProc):
    Code = 44
    #
    Kwargs = {
        'Routing_ID': 0,
        'LPPa_PDU': '\0\0'
        }
    
    def output(self):
        # stack all protocol IEs
        pIEs = []
        pIEs.append({'value': ('MME-UE-S1AP-ID', self.MME_UE_ID),
                     'criticality': 'reject',
                     'id': 0})
        #
        pIEs.append({'value': ('ENB-UE-S1AP-ID', self.ENB_UE_ID),
                     'criticality': 'reject',
                     'id': 8})
        #
        pIEs.append({'value': ('Routing-ID', self.Kwargs['Routing_ID']),
                     'criticality': 'reject',
                     'id': 148})
        #
        pIEs.append({'value': ('LPPa-PDU', self.Kwargs['LPPa_PDU']),
                     'criticality': 'reject',
                     'id': 147})
        #
        pdu = ('initiatingMessage',
               {'procedureCode': self.Code,
                'value': ('DownlinkUEAssociatedLPPaTransport', {'protocolIEs':pIEs}),
                'criticality': 'ignore'})
        #
        # remove the procedure from the UE S1 procedure stack
        if self.Code in self.UE.Proc['S1']:
            del self.UE.Proc['S1'][self.Code]
        self._trace('DL', pdu)
        return [pdu]

#--------------------------#
# unimplemented procedures #
#--------------------------#

#48: UERadioCapMatch

#----------------------------#
# S1AP Signalling Procedures #
# UE related                 #
#----------------------------#

# utils.py: S1APUEProcCodes: S1AP procedure codes for UE-related signalling
#S1APUEProcCodes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 42, 44, 45]
# Class 1 procedures: need response
#   initiatingMessage -> successfulOutcome [ / unsuccessfulOutcome]
Class1UESigProc = [0, 1, 3, 4, 5, 6, 7, 9, 21, 23]
# class 2: does not need response
#   initiatingMessage
Class2UESigProc = [2, 8, 11, 12, 13, 15, 16, 18, 19, 20, 22, 24, 25, 26, 27, 28, 31, 32, 33, 42, 44, 45]

# eNB initiated procedures
ENBUESigProcDispatch = {
    # E-RAB mgt, class 2, includes UE signalling
    8: ERABReleaseInd,
    # Ctxt mgt, class 2, includes UE signalling
    18: UEContextReleaseRequest,
    # Handover
    0: HandoverPreparation, # class 1
    2: HandoverNotification, # class 2
    3: PathSwitchRequest, # class 1, to re-allocate GTP DL endpoint
    4: HandoverCancellation, # class 1
    24: ENBStatusTransfer, # class 2, to transfer radio counters
    # NAS transport, class 2, includes UE signalling
    12: InitialUEMessage,
    13: UplinkNASTransport,
    16: NASNonDeliveryInd,
    # Mgt proc
    15: ENBErrorInd, # class 2
    # S1 CDMA2000 tunneling, class 2
    20: UplinkS1cdma2000tun,
    # UE cap info, class 2
    22: UECapabilityInfoInd,
    # Trace proc, class 2
    28: TraceFailureInd,
    42: CellTrafficTrace,
    # Location Reporting, class 2
    32: LocationReportingFailureInd,
    33: LocationReport,
    # LPPa, class 2
    45: UplinkUELPPaTransport,
}

# MME initiated procedures
MMEUESigProcDispatch = {
    # E-RAB mgt, includes UE signalling, class 1
    5: ERABSetup,
    6: ERABModify,
    7: ERABRelease,
    # Ctxt mgt, includes UE signalling, class 1
    9: InitialContextSetup,
    23: UEContextRelease,
    21: UEContextModification,
    # Handover
    1: HandoverResourceAlloc, # class 1
    25: MMEStatusTransfer, # class 2, to transfer radio counters
    # NAS transport, class 2, includes UE signalling
    11: DownlinkNASTransport,
    # Mgt proc
    15: MMEErrorInd, # class 2
    # S1 CDMA2000 tunneling, class 2
    19: DownlinkS1cdma2000tun,
    # Trace proc, class 2
    27: TraceStart,
    26: DeactivateTrace,
    # Location Reporting, class 2
    31: LocationReportingCtrl,
    # LPPa, class 2
    44: DownlinkUELPPaTransport,
}

