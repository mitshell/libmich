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
# * File Name : mobnet/UENASproc.py
# * Created : 2015-07-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#############
# TS 24.301 #
#############

from libmich.formats.L3Mobile_EMM import *
from libmich.formats.L3Mobile_ESM import *
from .utils import *

Layer3NASEMM._initiator = 'ME'

#----------------#
# NAS signalling #
# procedures     #
#----------------#


class UENASSigProc(UESigProc):
    '''
    UE related NAS signalling procedure
    
    instance attributes:
        - Name: procedure name
        - Dom: procedure domain ('EMM' / 'ESM')
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
        - process the NAS PDU received by the MME server from the eNB
    
    output():
        - return the NAS PDU to be sent to the eNB within an S1AP structure, or None
    '''
    # to keep track of all PDU exchanged within the procedure, into the _pdu attribute
    # WNG: it will consume memory (nothing will be garbage-collected)
    TRACE = True
    
    # NAS domain
    Dom = 'EMM' # / 'ESM'
    # NAS message (PD, Type) on procedure initiation
    Type = (2, 0)
    # NAS message type(s) expected on response
    Filter = None # or [(2, 0), ...]
    # Timer name, referencing UEmgr.UEd timer
    Timer = None # or 'T1234'
    
    # specific NAS procedures parameters:
    Kwargs = {}
    
    def __init__(self, ued, **kwargs):
        self.UE = ued
        self.MME = self.UE.MME
        self.Name = self.__class__.__name__
        self._pdu = []
        #
        self.Kwargs = cpdict(self.__class__.Kwargs)
        for kw in kwargs:
            if kw in self.Kwargs:
                self.Kwargs[kw] = kwargs[kw]
        #
        self._state_prev = getattr(self.UE, self.Dom)['state']
        if self.Dom == 'ESM':
            # reset potential previous S1AP struct
            self._s1_struct = None
        #
        self._log('DBG', 'instantiating procedure')
    
    def _log(self, logtype='DBG', msg=''):
        self.UE._log(logtype, '[{0}: {1}] {2}'.format(self.Type, self.Name, msg))
    
    def _trace(self, direction='UL', pdu=None):
        if self.TRACE:
            self._pdu.append( (time(), direction, pdu) )
        self.UE._log('TRACE_NAS_{0}'.format(direction), pdu.show())
    
    def process(self, naspdu=None):
        self._log('ERR', '[process] unsupported')
        # feeds with any input NAS PDU value
    
    def postprocess(self, proc=None):
        # for postprocessing after a nested procedure has ended
        pass
    
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
        # TODO: _end() the procedure
    
    def _end(self, state=None):
        # remove EMM / ESM the procedure (after verifying it's on the procedure stack)
        if self == self.UE.Proc[self.Dom][-1]:
            self.UE.Proc[self.Dom].pop()
        # restore (or force) the EMM / ESM state
        if state:
            getattr(self.UE, self.Dom)['state'] = state
        else:
            getattr(self.UE, self.Dom)['state'] = self._state_prev

#----------------#
# MME-initiated  #
# EMM procedures #
#----------------#

# EMM common procedures, 5.4, started at any time by the MME
# can be nested in an EMM specific procedure

# GUTI realloc, 5.4.1
# MME: GUTI REALLOCATION COMMAND -> UE: GUTI REALLOCATION COMPLETE -> MME
class GUTIReallocation(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 80)
    Filter = [(7, 81)]
    Timer = 'T3450'
    Kwargs = {
        'GUTI': None, # GUTI() or None; if None, MTMSI/GUTI is generated automatically
        'TAIList': None, # TAIList()
        }
    
    def output(self):
        #
        # change MME EMM state
        self.UE.EMM['state'] = 'EMM-COMMON-PROCEDURE-INITIATED'
        #
        if self.Kwargs['GUTI'] is None:
            self.Kwargs['GUTI'] = self.UE.nas_build_guti()
        if isinstance(self.Kwargs['GUTI'], GUTI):
            self._tmsi = self.Kwargs['GUTI'][6]()
        else:
            self._tmsi = None
        #
        # prepare the NAS msg
        naspdu = GUTI_REALLOCATION_COMMAND(GUTI=self.Kwargs['GUTI'])
        # optional IE
        if self.Kwargs['TAIList'] is not None:
            naspdu[4].Trans = False
            naspdu[4].V.Pt = self.Kwargs['TAIList']
        #
        self._trace('DL', naspdu)
        # start timer and send pdu
        self.init_timer()
        return naspdu
    
    def process(self, naspdu):
        self._trace('UL', naspdu)
        #
        # remove the old TMSI
        if self.UE.EMM['TMSI'] in self.MME.TMSI:
            del self.MME.TMSI[self.UE.EMM['TMSI']]
        # set the new one
        if self._tmsi is not None:
            self.MME.TMSI[self._tmsi] = self.UE.IMSI
            self.UE.EMM['TMSI'] = self._tmsi
            self._log('DBG', 'GUTI reallocated, TMSI {0}'.format(hexlify(self._tmsi)))
        #
        self._end()
        return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# Authentication, 5.4.2
# MME: EPS AUTHENTICATION REQUEST -> UE: EPS AUTHENTICATION RESPONSE -> MME [: EPS AUTHENTICATION REJECT -> UE]
# MME: EPS AUTHENTICATION REQUEST -> UE: EPS AUTHENTICATION FAILURE -> MME
# IOCTL, interface with MME.AUCd to:
# 1) get auth vector
# 2) resynchronize SQN
class Authentication(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 82)
    Filter = [(7, 83), (7, 92)]
    Timer = 'T3460'
    Kwargs = {
        'NASKSI': None, # 1..15, 7: no valid NASKSI
        #'RAND': None, # obtained from self.MME.AUCd
        #'AUTN': None, # obtained from self.MME.AUCd
        }
    
    def output(self):
        #
        # change MME EMM state
        self.UE.EMM['state'] = 'EMM-COMMON-PROCEDURE-INITIATED'
        #
        # select the NASKSI
        if not isinstance(self.Kwargs['NASKSI'], int):
            # hardcoded fixed-value NASKSI
            self.Kwargs['NASKSI'] = 0
        else:
            self.Kwargs['NASKSI'] = max(0, min(self.Kwargs['NASKSI'], 15))
        #
        # IOCTL.1: get a 4G auth vector (RAND, XRES, AUTN, Kasme) from the MME.AUCd
        # if self.UE.AUTH_RAND is None, AUCd provides a random one
        # if self.UE.AUTH_RAND is fixed, AUCd uses it to generate the auth vector
        try:
            self._vec = self.MME.AUCd.make_4g_vector(self.UE.IMSI, 
                                                     self.MME.MME_PLMN_BUF,
                                                     self.UE.AUTH_AMF,
                                                     self.UE.AUTH_RAND)
        except:
            self._log('ERR', 'no AUCd configured in the MME')
            self._vec = -1
        if self._vec == -1:
            # cannot get the vector
            self._log('ERR', 'unable to get an authentication vector')
            self._end()
            return None
        #
        # prepare the NAS msg
        naspdu = EPS_AUTHENTICATION_REQUEST(NASKSI=self.Kwargs['NASKSI'],
                                            RAND=self._vec[0],
                                            AUTN=self._vec[2])
        #
        # start timer and send pdu
        self._trace('DL', naspdu)
        self.init_timer()
        return naspdu
    
    def process(self, naspdu):
        self._trace('UL', naspdu)
        if naspdu[2]() == 92:
            return self._process_failure(naspdu)
        #
        res = naspdu[3].V()
        if not self.UE.AUTH_VERIF or res == self._vec[1][:8]:
            # UE authenticated
            self._log('DBG', 'authentication success')
            # store the auth vector and other SEC context parameters
            self.UE.SEC['vec'] = self._vec
            self.UE.SEC['KSI'][self.Kwargs['NASKSI']] = [0, 0, self._vec[3]]
            self.UE.SEC['active'] = self.Kwargs['NASKSI']
            self.UE.SEC['Fresh'] = True
            self.UE.SEC['Knas_enc'] = None
            self.UE.SEC['Knas_int'] = None
            # restore the initial state
            self._end()
            return None
        #
        else:
            # UE not authenticated
            self._log('ERR', 'authentication rejected: UE responded RES {0}, expected XRES {1}'.format(
                      hexlify(res), hexlify(self._vec[1][:8])))
            return self._reject()
    
    def _process_failure(self, naspdu):
        # UE did not accept AUTN
        self._log('WNG', 'authentication failure: {0}'.format(repr(naspdu[3])))
        #
        if naspdu[3]() == 21 and naspdu[4].Trans == False:
            # AUTS provided by the UE
            auts = naspdu[4].getobj()
            # IOCTL.2: resynchronize SQN with AUTS within MME.AUCd
            try:
                ret = self.MME.AUCd.synchronize(self.UE.IMSI,
                                                RAND=self._vec[0],
                                                AUTS=auts)
            except:
                self._log('ERR', 'no AUCd configured in the MME')
                ret == -1
            if ret == -1:
                # UE not authenticated during resynch
                self._log('ERR', 'authentication failure: invalid AUTS from the UE')
                return self._reject()
            else:
                # SQN should have be resynched successfully in the AUCd, 
                # so we restart with an AUTH REQ / RESP cycle
                self._log('DBG', 'SQN resynchronized in the AUC')
                return self.output()
        else:
            # if the procedure is on the UE stack, remove it
            self._end()
            self._clean_sec_ctx()
            # TBC: let the UE stop the radio connection
            return None
    
    def _clean_sec_ctx(self):
        # keep track of the auth vector that made everything fail
        self.UE.SEC['vec'] = self._vec
        # delete the corresponding NASKSI context, and associated data
        del self.UE.SEC['KSI'][self.Kwargs['NASKSI']]
        self.UE.SEC['active'] = None
        self.UE.SEC['Fresh'] = False
        self.UE.SEC['Knas_enc'] = None
        self.UE.SEC['Knas_int'] = None
    
    def _reject(self):
        rej = EPS_AUTHENTICATION_REJECT()
        self._clean_sec_ctx()
        # prepare an S1 UEContextRelease
        self.UE.s1_release_ctxt(('nas', 'authentication-failure'))
        # UE considered deregistered
        self._end(state='EMM-DEREGISTERED')
        self._trace('DL', rej)
        return rej
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()
        self._clean_sec_ctxt()

# Security mode control, 5.4.3
# MME: SECURITY MODE COMMAND -> UE: SECURITY MODE COMPLETE -> MME
# MME: SECURITY MODE COMMAND -> UE: SECURITY MODE REJECT -> MME
class SecurityModeControl(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 93)
    Filter = [(7, 94), (7, 95)]
    Timer = 'T3460'
    Kwargs = {
        'NASKSI': None, # 1..15, 7: no valid NASKSI; if None, takes the active one
        #'UESecCap': None, # UESecCap(); built automatically
        'IMEISVReq': None, # 0: dont, 1: do request
        'NonceUE': None, # 4-bytes
        'NonceMME': None, # 4-bytes
        }
    
    def output(self):
        #
        # change MME EMM state
        self.UE.EMM['state'] = 'EMM-COMMON-PROCEDURE-INITIATED'
        #
        # ensures UESecCap is here
        if self.UE.CAP['UESecCap'] is None:
            self.UE.nas_build_ueseccap()
        #
        # select the NASKSI
        ksi_l = self.UE.SEC['KSI'].keys()
        if not ksi_l:
            # 1) no valid NASKSI (no successful auth happened)
            self._log('ERR', 'no valid NASKSI available')
            return None
        else:
            # a valid KSI exists (at least 1 successful auth happened)
            if not isinstance(self.Kwargs['NASKSI'], int) or self.Kwargs['NASKSI'] not in self.UE.SEC['KSI']:
                # 2) get the NASKSI established during last successful auth 
                # default behavior
                self.Kwargs['NASKSI'] = self.UE.SEC['active']
            else:
                # 3) select a forced NASKSI that corresponds to a valid security context
                self.UE.SEC['active'] = self.Kwargs['NASKSI']
            #
            # select EEA / EIA alg
            for eea in self.UE.SMC_EEA:
                if self.UE.CAP['UESecCap'][eea]():
                    self.UE.SEC['EEA'] = eea
                    break
            for eia in self.UE.SMC_EIA:
                if self.UE.CAP['UESecCap'][8+eia]():
                    self.UE.SEC['EIA'] = eia
                    break
        #
        # prepare the NAS msg
        naspdu = SECURITY_MODE_COMMAND(NASSecAlg=eia+(eea<<4),
                                       NASKSI=self.Kwargs['NASKSI'],
                                       UESecCap=self.UE.CAP['UESecCap'])
        #
        # need for the IMEISV
        if self.UE.SMC_IMEI_POL == 2 \
        or (self.UE.SMC_IMEI_POL == 1 and self.UE.EMM['IMEISV'] is None) \
        or self.Kwargs['IMEISVReq']:
            naspdu[7].Trans = False
            naspdu[7].V.Pt = 1
        #
        # request with Nonce
        if isinstance(self.Kwargs['NonceUE'], bytes) and len(self.Kwargs['NonceUE']) >= 4:
            naspdu[8].Trans = False
            naspdu[8].V.Pt = self.Kwargs['NonceUE'][:4]
        if isinstance(self.Kwargs['NonceMME'], bytes) and len(self.Kwargs['NonceMME']) >= 4:
            naspdu[9].Trans = False
            naspdu[9].V.Pt = self.Kwargs['NonceMME'][:4]
        #
        self._trace('DL', naspdu)
        self.init_timer()
        return naspdu
    
    def process(self, naspdu):
        self._trace('UL', naspdu)
        self._end()
        #
        if naspdu[2]() == 95:
            # UE did not accept our parameters, or MAC
            self._log('WNG', 'security mode rejected: {0}'.format(repr(naspdu[3])))
            self._clean_sec_ctx()
            # TODO: stop S1 / radio connection
            return None
        #
        # if IMEISV is provided, write it back to the UE stack
        if not naspdu[3].Trans:
            ident = naspdu[3].getobj()
            if ident.type() == 3:
                self.UE.EMM['IMEISV'] = ident.get_bcd()
        #
        self._log('DBG', 'security mode completed: EEA{0} / EIA{1}'.format(
                  self.UE.SEC['EEA'], self.UE.SEC['EIA']))
        self.UE.SEC['SMC'] = False
        return None
    
    def _clean_sec_ctx(self):
        # delete the NASKSI context selected for SMC, and associated data
        del self.UE.SEC['KSI'][self.Kwargs['NASKSI']]
        self.UE.SEC['active'] = None
        self.UE.SEC['SMC'] = False
        self.UE.SEC['Knas_enc'] = None
        self.UE.SEC['Knas_int'] = None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()
        self._clean_sec_ctxt()


# Identification, 5.4.4
# MME: EPS IDENTITY REQUEST -> UE: EPS IDENTITY RESPONSE -> MME
class Identification(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 85)
    Filter = [(7, 86)]
    Timer = 'T3470'
    Kwargs = {
        'IDType': None # 1: IMSI, 2: IMEI, 3: IMEISV, 4: TMSI, private/ffu else
        }
    
    def output(self):
        #
        # change MME EMM state
        self.UE.EMM['state'] = 'EMM-COMMON-PROCEDURE-INITIATED'
        #
        # prepare the NAS msg
        if self.Kwargs['IDType'] is None:
            # request IMSI
            self.Kwargs['IDType'] = 1
            naspdu = EPS_IDENTITY_REQUEST(IDType=1)
        else:
            naspdu = EPS_IDENTITY_REQUEST(IDType=self.Kwargs['IDType'])
        #
        # start timer and send NAS PDU
        self._trace('DL', naspdu)
        self.init_timer()
        return naspdu
    
    def process(self, naspdu):
        # get the NAS msg content
        self._trace('UL', naspdu)
        # get the identity
        ident = naspdu[3].getobj()
        ident_t = ident.type()
        #
        self._end()
        #
        if ident_t != self.Kwargs['IDType']:
            stat = EMM_STATUS(EMMCause=95)
            self._log('WNG', 'ID type {0} requested, received response {1}, sending STATUS 95'.format(
                      self.Kwargs['IDType'], repr(ident)))
            self._trace('DL', stat)
            ret = stat
        #
        elif ident_t == 1:
            # IMSI
            imsi = ident.get_imsi()
            if imsi != self.UE.IMSI:
                self._log('ERR', 'IMSI mismatch: {0} versus {1} initially reported'.format(imsi, self.UE.IMSI))
                # TODO: send DETACH REQUEST and never re-attach...
                ret = None
        #
        elif ident_t == 2:
            # IMEI
            self.UE.EMM['IMEI'] = ident.get_imei()
            self._log('DBG', 'IMEI {0} reported'.format(self.UE.EMM['IMEI']))
            ret = None
        #
        elif ident_t == 3:
            # IMEISV
            self.UE.EMM['IMEISV'] = ident.get_bcd()
            self._log('DBG', 'IMEISV {0} reported'.format(self.UE.EMM['IMEISV']))
            ret = None
        #
        elif ident_t == 4:
            # TMSI: just trust the UE to report its own TMSI correctly
            self.UE.EMM['TMSI'] = ident.tmsi()
            self._log('DBG', 'TMSI {0} reported'.format(self.UE.EMM['TMSI']))
            ret = None
        #
        else:
            # TMGI or unknown ID type
            self._log('INF', 'ID type {0} reported: {1}'.format(ident_t, repr(ident)))
            ret = None
        #
        return ret
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# EMM Information, 5.4.5
# MME: EMM INFORMATION -> UE
class EMMInformation(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 97)
    Filter = []
    Timer = None
    Kwargs = {
        'NetFullName': None, # bytes
        'NetShortName': None, # bytes
        'TZ': None, # 1-byte bytes, local time-zone
        'TZTime': None, # 7-bytes bytes, time-zone and time
        'DTime': None, # bytes, daylight saving time
        }
    
    def output(self):
        # prepare the NAS msg
        naspdu = EMM_INFORMATION()
        #
        if isinstance(self.Kwargs['NetFullName'], bytes):
            naspdu.NetFullName.V > self.Kwargs['NetFullName']
            naspdu.NetFullName.Trans = False
        #
        if isinstance(self.Kwargs['NetShortName'], bytes):
            naspdu.NetShortName.V > self.Kwargs['NetShortName']
            naspdu.NetShortName.Trans = False
        #
        #
        if isinstance(self.Kwargs['TZ'], bytes):
            naspdu.TZ.V > self.Kwargs['TZ'][0]
            naspdu.TZ.Trans = False
        #
        if isinstance(self.Kwargs['TZTime'], bytes):
            naspdu.TZTime.V > self.Kwargs['TZTime'][:7]
            naspdu.TZTime.Trans = False
        #
        if isinstance(self.Kwargs['DTime'], bytes):
            naspdu.DTime.V > self.Kwargs['DTime']
            naspdu.DTime.Trans = False
        #
        self._trace('DL', naspdu)
        self._end()
        return naspdu


# EMM specific procedures, 5.5, started by the MME

# Detach, 5.5.2.3
# MME : DETACH REQUEST -> UE: DETACH ACCEPT -> MME]
class MMEDetach(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 69)
    Filter = [(7, 70)]
    Timer = 'T3422'
    Kwargs = {
        'DetType': None, # uint < 16, (1, 2 or 3)
        'EMMCause': None # uint
        }
    
    def output(self):
        #
        # change MME EMM state
        self.UE.EMM['state'] = 'EMM-COMMON-PROCEDURE-INITIATED'
        #
        if self.Kwargs['DetType'] is None:
            self.Kwargs['DetType'] = self.UE.DET_TYPE
        #
        # prepare the NAS msg
        Layer3NASEMM._initiator = 'Net'
        naspdu = DETACH_REQUEST(DetType=self.Kwargs['DetType'])
        Layer3NASEMM._initiator = 'ME'
        #
        if self.Kwargs['EMMCause'] is not None:
            naspdu[5].Trans = False
            naspdu[5].V.Pt = chr(self.Kwargs['EMMCause'])
        #
        self._trace('DL', naspdu)
        # start timer and send pdu
        self.init_timer()
        return naspdu
    
    def process(self, naspdu):
        self._trace('UL', naspdu)
        self._log('INF', 'done')
        #
        self._end(state='EMM-DEREGISTERED')
        self.UE.gtp_disable()
        self.UE.init_esm()
        return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()


# EMM connection management procedures, 5.6, started by the MME

# Paging, 5.6.2
# MME: Paging -> ENB: Paging -> UE: [EXTENDED] SERVICE REQUEST
# Filter is not set, the Paging timer is stopped directly from the ServiceRequest procedure
class PagingRequest(UENASSigProc):
    Dom = 'EMM'
    Type = None
    Filter = []
    Timer = 'T3413'
    Kwargs = {
        'UEIdentityIndexValue': None, # BIT STRING (SIZE (10))
        'UEPagingID': None, # s-TMSI (mMEC, m-TMSI) or iMSI
        'DRX': None, # Paging DRX signalled by the UE NAS layer, to be confirmed
        'CNDomain': 'ps', # or 'cs', ENUM
        'TAIList': None
        }
    
    def output(self):
        # prepare the list of arguments for the S1AP msg
        #
        if self.Kwargs['UEIdentityIndexValue'] is None:
            # see TS 36.304, 7.1
            self.Kwargs['UEIdentityIndexValue'] = (int(self.UE.IMSI) % 1024, 10)
        #
        if self.Kwargs['UEPagingID'] is None:
            if self.UE.EMM['TMSI'] is None:
                # paging with IMSI
                self.Kwargs['UEPagingID'] = ('iMSI', str(ID(self.UE.IMSI, 'IMSI')))
            else:
                # paging with MMEC, M-TMSI
                self.Kwargs['UEPagingID'] = ('s-TMSI', {'mMEC': self.MME.MME_MMEC_BUF, 
                                                        'm-TMSI': self.UE.EMM['TMSI']})
        #
        if self.Kwargs['DRX'] is None and self.UE.CAP['DRX'] is not None:
            drx = self.UE.CAP['DRX'][1]()
            # in case the NAS-signalled UE DRX is specified
            if drx in (6, 7, 8, 9):
                self.Kwargs['DRX'] = ('v32', 'v64', 'v128', 'v256')[drx-6]
        #
        if self.Kwargs['TAIList'] is None and self.UE.S1['TAI'] is not None:
            tai = {'pLMNidentity': bytes(self.UE.S1['TAI'][0]),
                   'tAC': pack('!H', self.UE.S1['TAI'][1])}
            self.Kwargs['TAIList'] = [{'id': 47,
                                       'criticality': 'ignore',
                                       'value': ('TAIItem', {'tAI': tai})}]
        #
        self.UE._s1dl_struct = {'Code': 10,
                                'Kwargs': self.Kwargs}
        return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# SMS, 5.6.3, DOWNLINK NAS TRANSPORT
# WNG: name is prefixed with NAS, not to clash with S1 procedure
class NASDownlinkNASTransport(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 98)
    Filter = []
    Timer = None
    Kwargs = {
        'NASContainer': None, # contains the SMS-TP msg
        }

# LPP, 5.6.4, DOWNLINK GENERIC NAS TRANSPORT
class DownlinkGenericNASTransport(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 104)
    Filter = []
    Timer = None
    Kwargs = {
        'ContType': None, # 1: LPP, 2: LCS
        'GenericContainer': None, # contains the LPP / LCS msg
        'AddInfo': None, # ?
        }


#----------------#
# UE-initiated   #
# EMM procedures #
#----------------#

# EMM specific procedures, 5.5, started by the UE

# Attach, 5.5.1
# UE: ATTACH REQUEST -> MME: ATTACH ACCEPT -> UE [: ATTACH COMPLETE -> MME]
# UE: ATTACH REQUEST -> MME: ATTACH REJECT -> UE
# Attach hardcoded behaviour:
# - always reassign a new GUTI
class Attach(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 65)
    Filter = [(7, 67)] # an ATTACH COMPLETE to be sent by the UE, only if EPS bearer is activated
    Timer = 'T3450' # only if EPS bearer is activated
    Kwargs = {
        # for ACCEPT
        'EPSAttRes': None, # 1: EPS only, 2: EPS / IMSI combined
        'T3412': None, # uint < 255
        'TAIList': None, # TAIList()
        'ESMContainer': None, # NAS ESM PDU
        'GUTI': None, # GUTI()
        'LAI': None, # LAI()
        'ID': None, # ID()
        'EMMCause': None, # uint < 255, to 1-byte bytes
        'T3402': None, # uint < 255, to 1-byte bytes
        'T3423': None, # uint < 255, to 1-byte bytes
        'PLMNList': None, # PLMNList(), equivalent PLMN list
        'ECNList': None, # bytes, list of BCD number (TBC)
        'EPSFeatSup': None, # bytes
        'AddUpdRes': None, # uint < 16
        'T3412ext': None, # uint < 255, to 1-byte bytes
        # for REJECT
        'EMMCause': None, # uint < 255
        #'ESMContainer': None, # NAS ESM PDU
        'T3346': None, # bytes
        #'T3402': None, # bytes
        }
    
    def process(self, naspdu):
        #
        if naspdu[1]() == 2:
            # ESM INFO RESPONSE :
            # (ESM PDU will be traced within ESM procedures)
            # update message filter
            try:
                self.Filter.remove( (2, 218) )
            except:
                pass
            self._esm_resp = self.UE._process_naspdu(naspdu)
            # self._esm_resp should contain the ACTIVATE EPS BEARER CTXT
            # which will be wrapped within the ATTACH ACCEPT in self.postprocess()
            return self.postprocess()
        #
        # trace the NAS msg content
        self._trace('UL', naspdu)
        #
        # ATTACH COMPLETE:
        if naspdu[2]() == 67:
            return self._process_complete(naspdu)
        #
        # ATTACH REQUEST:
        # if UE is attaching, it means it considers itself as DEREGISTERED
        self.UE.EMM['state'] = 'EMM-DEREGISTERED'
        #
        # check if the IMSI is allowed
        if self.UE.IMSI not in self.MME.UEConfig:
            rej = ATTACH_REJECT(EMMCause=self.UE.ATT_REJ_ID)
            if self.Kwargs['ESMContainer'] is not None:
                rej[4].Trans = False
                rej[4].V.Pt = self.Kwargs['ESMContainer']
            if self.Kwargs['T3346'] is not None:
                rej[5].Trans = False
                rej[5].V.Pt = self.Kwargs['T3346']
            if self.Kwargs['T3402'] is not None:
                rej[6].Trans = False
                rej[6].V.Pt = self.Kwargs['T3402']
            #
            self._end(state='EMM-DEREGISTERED')
            self._trace('DL', rej)
            return naspdu
        #
        # check Last Visited TAI
        if not naspdu[10].is_transparent():
            tai = naspdu[10].getobj()
            if tai[0].get_mccmnc() != self.UE.S1['TAI'][0].get_mccmnc():
                self._log('WNG', 'invalid UE-reported MCC-MNC in TAI: {0}'.format(repr(tai)))
            elif tai[1]() != self.UE.S1['TAI'][1]:
                self._log('WNG', 'invalid UE-reported TAC in TAI: {0}'.format(repr(tai)))
        #
        # get attach type
        self._epsatttype = naspdu[4]()
        #
        # get capabilities: UENetCap, DRX, MSNetCap, MSCm2, MSCm3, ...
        self.UE.CAP['UENetCap'] = naspdu[6].getobj()
        if not naspdu[11].is_transparent():
            self.UE.CAP['DRX'] = naspdu[11].getobj()
        if not naspdu[12].is_transparent():
            self.UE.CAP['MSNetCap'] = naspdu[12].getobj()
        if not naspdu[15].is_transparent():
            self.UE.CAP['MSCm2'] = naspdu[15].getobj()
        if not naspdu[16].is_transparent():
            self.UE.CAP['MSCm3'] = naspdu[16].getobj()
        if not naspdu[17].is_transparent():
            self.UE.CAP['SuppCodecs'] = naspdu[17].getobj()
        if not naspdu[18].is_transparent():
            self.UE.CAP['AddUpdType'] = naspdu[18].getobj()
        if not naspdu[19].is_transparent():
            self.UE.CAP['VoicePref'] = naspdu[19].getobj()
        if not naspdu[20].is_transparent():
            self.UE.CAP['DevProp'] = naspdu[20].getobj()
        if not naspdu[22].is_transparent():
            self.UE.CAP['MSFeatSup'] = naspdu[22].getobj()
        #
        self._naspdu = naspdu
        self._log('DBG', '{0} requested'.format(repr(naspdu[4])))
        #
        # check if we need to do an Authentication
        if self.UE.nas_need_auth('ATT'):
            proc = self.UE.init_nas_proc(Authentication)
            return proc.output()
        #
        # check if we need to do a Sec Mode Ctrl
        elif self.UE.nas_need_smc('ATT'):
            proc = self.UE.init_nas_proc(SecurityModeControl)
            return proc.output()
        #
        # otherwise, go directly to postprocess
        return self.postprocess()
    
    def postprocess(self, proc=None):
        #
        # if an authentication just happened, we take the new security context into use
        if isinstance(proc, Authentication):
            if self.UE.nas_need_smc('ATT'):
                proc = self.UE.init_nas_proc(SecurityModeControl)
                return proc.output()
        #
        # continuation of the ATTACH procedure after EMM common procedures were run:
        # processing the ESM container
        if not hasattr(self, '_esm_resp'):
            esmpdu = self._naspdu[7].getobj()
            # process the ESM PDU within the ESM state machine
            self._esm_resp = self.UE._process_naspdu(esmpdu)
            if self._esm_resp[3]() == 217:
                # an ESM INFO REQ / RESP roundtrip is required before continuing
                # update the local message filter to catch the ESM INFO RESP within .process()
                self.Filter.append( (2, 218) )
                return self._esm_resp
            # if the ESM INFO is not required by the ESM state machine
            # self._esm_resp will contain the ACTIVATE EPS BEARER CTXT which will be wrapped within the ATTACH ACCEPT
        #
        # set default behaviour
        if self.Kwargs['EPSAttRes'] is None:
            self.Kwargs['EPSAttRes'] = self._epsatttype
        if self.Kwargs['T3412'] is None:
            self.Kwargs['T3412'] = self.UE.T3412
        if self.Kwargs['T3402'] is None:
            self.Kwargs['T3402'] = self.UE.T3402
        if self.Kwargs['T3423'] is None:
            self.Kwargs['T3423'] = self.UE.T3423
        if self.Kwargs['TAIList'] is None:
            self.Kwargs['TAIList'] = self.UE.nas_build_tailist()
        if self.Kwargs['ESMContainer'] is None:
            # process ESM msg through its own state machine
            self.Kwargs['ESMContainer'] = self._esm_resp
        if self.Kwargs['GUTI'] is None:
            # always reassign a GUTI
            self.Kwargs['GUTI'] = self.UE.nas_build_guti()
            self._tmsi = self.Kwargs['GUTI'][6]()
        if self.Kwargs['LAI'] is None:
            # LAI needed when combined IMSI / EPS attach is done
            # we take the 1st TAI from the TAIList
            p_tai = self.Kwargs['TAIList'][0]
            self.Kwargs['LAI'] = LAI(MCCMNC=p_tai.PLMN.get_mccmnc(),
                                     LAC=p_tai.TAC())
        if self.Kwargs['ID'] is None:
            # TMSI needed when combined IMEI / EPS attach is done
            # we take the MTMSI from the GUTI
            self.Kwargs['ID'] = ID(self._tmsi, type='TMSI')
        # TODO: EMMCause
        if self.Kwargs['T3402'] is None:
            self.Kwargs['T3402'] = self.UE.T3402
        if self.Kwargs['T3423'] is None:
            self.Kwargs['T3423'] = self.UE.T3423
        # TODO: PLMNList, ECNList, EPSFeatSup, AddUpdRes
        if self.Kwargs['T3412ext'] is None:
            self.Kwargs['T3412ext'] = self.UE.T3412ext
        #
        attacc = ATTACH_ACCEPT(EPSAttRes=self.Kwargs['EPSAttRes'],
                               T3412=self.Kwargs['T3412'],
                               TAIList=self.Kwargs['TAIList'],
                               ESMContainer=self.Kwargs['ESMContainer'],
                               GUTI=self.Kwargs['GUTI'])
        # combined attach
        if self.Kwargs['EPSAttRes'] == 2:
            attacc[9].Trans = False
            attacc[9].V.Pt = self.Kwargs['LAI']
            attacc[10].Trans = False
            attacc[10].V.Pt = self.Kwargs['ID']
        # TODO: EMMCause, T3402, T3423, PLMNList, ECNList, EPSFeatSup, AddUpdRes, T3412ext
        #
        self._trace('DL', attacc)
        if self._esm_resp[3]() == 193:
            # if the PDN REQ can be honoured with a DEFAULT CTX SETUP
            # the setup of the DRB for the initial default ERAB-ID has been prepared in the DefaultEPSBearerCtxtAct procedure
            # and an ATTACH COMPLETE is to be received from the UE afterwards
            self.init_timer()
        else:
            # otherwise, the Attach procedure ends up here
            self._end(state='EMM-REGISTERED')
            self._log('INF', 'completed, GUTI reallocated, TMSI {0}, PDN connection not setup'.format(hexlify(self._tmsi)))
        return attacc
    
    def _process_complete(self, naspdu):
        #
        # process potential ESM msg
        esmpdu = naspdu[3].getobj()
        esm_resp = self.UE._process_naspdu(esmpdu)
        #assert(esm_resp is None)
        #
        # remove the old TMSI
        if self.UE.EMM['TMSI'] in self.MME.TMSI:
            del self.MME.TMSI[self.UE.EMM['TMSI']]
        # set the new one
        self.MME.TMSI[self._tmsi] = self.UE.IMSI
        self.UE.EMM['TMSI'] = self._tmsi
        self._log('INF', 'completed, GUTI reallocated, TMSI {0}'.format(hexlify(self._tmsi)))
        # attachment type
        if self.Kwargs['EPSAttRes'] == 2:
            self.UE.EMM['combined'] = True
        else:
            self.UE.EMM['combined'] = False
        #
        self._end(state='EMM-REGISTERED')
        return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# Detach, 5.5.2.2
# UE: DETACH REQUEST -> MME [: DETACH ACCEPT -> UE]
class UEDetach(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 69)
    Filter = []
    Timer = None
    Kwargs = {}
    
    def process(self, naspdu):
        # trace the NAS msg content
        self._trace('UL', naspdu)
        #
        # check the type of detach
        dt = naspdu[4]
        #
        self._log('INF', 'type: {0}'.format(repr(dt)))
        self._end(state='EMM-DEREGISTERED')
        self.UE.gtp_disable()
        self.UE.init_esm()
        #
        # release the S1 UE con
        self.UE.s1_release_ctxt(('nas', 'detach'))
        #
        if not dt() & 0x8:
            # UE not switched off, accept detach explicitely
            detacc = DETACH_ACCEPT()
            self._trace('DL', detacc)
            return detacc

# Tracking area update, 5.5.3
# UE: TRACKING AREA UPDATE REQUEST -> MME: TRACKING AREA UPDATE ACCEPT -> UE [: TRACKING AREA UPDATE COMPLETE -> MME]
# UE: TRACKING AREA UPDATE REQUEST -> MME: TRACKING AREA REJECT
# Attach hardcoded behaviour:
# - always reassign a new GUTI
class TrackingAreaUpdate(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 72)
    Filter = [(7, 74)] # a TRACKING AREA UPDATE COMPLETE to be sent by the UE, only if GUTI is reallocated
    Timer = 'T3450' # only if GUTI is reallocated
    Kwargs = {
        # for ACCEPT
        'EPSUpdRes': None, # uint < 16
        'T3412': None, # uint < 255, to 1-byte bytes
        'GUTI': None, # GUTI()
        'TAIList': None, # TAIList()
        'EPSCtxStat': None, # bytes
        'LAI': None, # LAI(), old LAI
        'ID': None, # ID()
        'EMMCause': None, # uint < 255, to 1-byte bytes
        'T3402': None, # uint < 255, to 1-byte bytes
        'T3423': None, # uint < 255, to 1-byte bytes
        'PLMNList': None, # PLMNList(), equivalent PLMN list
        'ECNList': None, # bytes, list of Emergency numbers (BCD-style)
        'EPSFeatSup': None, # bytes
        'AddUpdRes': None, # uint < 16
        'T3412ext': None, # uint < 255, to 1-byte bytes
        # for REJECT
        'EMMCause': None, # uint < 255
        'T3346': None, # bytes
        }
    
    def process(self, naspdu):
        #
        # trace the NAS msg content
        self._trace('UL', naspdu)
        #
        # TAU COMPLETE:
        if naspdu[2]() == 74:
            return self._process_complete(naspdu)
        #
        # check if the IMSI is allowed
        if self.UE.IMSI not in self.MME.UEConfig:
            rej = ATTACH_REJECT(EMMCause=self.UE.ATT_REJ_ID)
            if self.Kwargs['T3346'] is not None:
                rej[5].Trans = False
                rej[5].V.Pt = self.Kwargs['T3346']
            #
            self._end(state='EMM-DEREGISTERED')
            self._trace('DL', rej)
            return naspdu
        #
        # get TAU type
        self._epsupdtype = naspdu[4]()
        #
        # just ignore Old GUTI (set to the current GUTI) and old GUTI type (set to native)
        #naspdu[5], naspdu[24]
        #
        # check TAI
        if not naspdu[12].is_transparent():
            tai = naspdu[12].getobj()
            if tai[0].get_mccmnc() != self.UE.S1['TAI'][0].get_mccmnc():
                self._log('WNG', 'invalid UE-reported MCC-MNC in TAI: {0}'.format(repr(tai)))
            elif tai[1]() != self.UE.S1['TAI'][1]:
                self._log('WNG', 'invalid UE-reported TAC in TAI: {0}'.format(repr(tai)))
        #
        # check for active EPS bearers
        self._epsbrctxt = None
        if not naspdu[15].is_transparent():
            self._epsbrctxt = naspdu[15].getobj()
            if len(self._epsbrctxt) != 2:
                self._log('WNG', 'invalid UE-reported EPS bearer context status: {0}'.format(hexlify(self._epsbrctxt)))
            else:
                epsbrctxt0 = ord(self._epsbrctxt[0])
                epsbrctxt1 = ord(self._epsbrctxt[1])
                for i in range(0, 8):
                    if epsbrctxt0 & (1<<i) and i not in self.UE.ESM['RAB']:
                        self._log('WNG', 'invalid UE-reported EPS bearer {0}'.format(i))
                    elif i in self.UE.ESM['RAB'] and not epsbrctxt0 & (1<<i):
                        self._log('DBG', 'UE-reported EPS bearer context status missing EPS bearer {0}: deleting it'.format(i))
                        del self.UE.ESM['RAB'][i]
                    if epsbrctxt1 & (1<<i) and i+8 not in self.UE.ESM['RAB']:
                        self._log('WNG', 'invalid UE-reported EPS bearer {0}'.format(i+8))
                    elif i+8 in self.UE.ESM['RAB'] and not epsbrctxt1 & (1<<i):
                        self._log('DBG', 'UE-reported EPS bearer context status missing EPS bearer {0}: deleting it'.format(i+8))
                        del self.UE.ESM['RAB'][i+8]
        #
        # update capabilities: UENetCap, DRX, MSNetCap, MSCm2, MSCm3, ...
        if not naspdu[11].is_transparent():
            self.UE.CAP['UENetCap'] = naspdu[11].getobj()
        if not naspdu[13].is_transparent():
            self.UE.CAP['DRX'] = naspdu[13].getobj()
        if not naspdu[16].is_transparent():
            self.UE.CAP['MSNetCap'] = naspdu[16].getobj()
        if not naspdu[19].is_transparent():
            self.UE.CAP['MSCm2'] = naspdu[19].getobj()
        if not naspdu[20].is_transparent():
            self.UE.CAP['MSCm3'] = naspdu[20].getobj()
        if not naspdu[21].is_transparent():
            self.UE.CAP['SuppCodecs'] = naspdu[21].getobj()
        if not naspdu[22].is_transparent():
            self.UE.CAP['AddUpdType'] = naspdu[22].getobj()
        if not naspdu[23].is_transparent():
            self.UE.CAP['VoicePref'] = naspdu[23].getobj()
        if not naspdu[25].is_transparent():
            self.UE.CAP['DevProp'] = naspdu[25].getobj()
        if not naspdu[26].is_transparent():
            self.UE.CAP['MSFeatSup'] = naspdu[26].getobj()
        #
        self._naspdu = naspdu
        self._log('DBG', '{0} requested'.format(repr(naspdu[4])))
        #
        # check if we need to do an Authentication
        if self.UE.nas_need_auth('TAU'):
            proc = self.UE.init_nas_proc(Authentication)
            return proc.output()
        #
        # check if we need to do a Sec Mode Ctrl
        elif self.UE.nas_need_smc('TAU'):
            proc = self.UE.init_nas_proc(SecurityModeControl)
            return proc.output()
        #
        # otherwise, go directly to postprocess
        return self.postprocess()
    
    def postprocess(self, proc=None):
        #
        # if an authentication just happened, we take the new security context into use
        if isinstance(proc, Authentication):
            if self.UE.nas_need_smc('TAU'):
                proc = self.UE.init_nas_proc(SecurityModeControl)
                return proc.output()
        #
        # set default behaviour
        if self.Kwargs['EPSUpdRes'] is None:
            if self._epsupdtype == 3 and self.UE.EMM['combined']:
                self.Kwargs['EPSUpdRes'] = 1
            else:
                # TBC
                self.Kwargs['EPSUpdRes'] = self._epsupdtype
        if self.Kwargs['T3412'] is None:
            self.Kwargs['T3412'] = self.UE.T3412
        if self.Kwargs['GUTI'] is None:
            # always reassign a GUTI
            self.Kwargs['GUTI'] = self.UE.nas_build_guti()
            self._tmsi = self.Kwargs['GUTI'][6]()
        if self.Kwargs['TAIList'] is None:
            self.Kwargs['TAIList'] = self.UE.nas_build_tailist()
        if self._epsbrctxt is not None and self.Kwargs['EPSCtxStat']:
            epsbrctxt = 0
            for rabid in self.UE.ESM['RAB']:
                if rabid in (0, 1, 2, 3, 4, 5, 6, 7):
                    epsbrctxt += 1<<(rabid+8)
                else:
                    epsbrctxt += 1<<rabid
            self.Kwargs['EPSCtxStat'] = pack('!H', epsbrctxt)
        if self.Kwargs['LAI'] is None:
            # LAI needed when combined TA / LA is done
            # we take the 1st TAI from the TAIList
            p_tai = self.Kwargs['TAIList'][0]
            self.Kwargs['LAI'] = LAI(MCCMNC=p_tai.PLMN.get_mccmnc(),
                                     LAC=p_tai.TAC())
        if self.Kwargs['ID'] is None:
            # TMSI needed when combined TA / LA is done
            # we take the MTMSI from the GUTI
            self.Kwargs['ID'] = ID(self._tmsi, type='TMSI')
        # TODO: EMMCause
        if self.Kwargs['T3402'] is None:
            self.Kwargs['T3402'] = self.UE.T3402
        if self.Kwargs['T3423'] is None:
            self.Kwargs['T3423'] = self.UE.T3423
        # TODO: PLMNList, ECNList, EPSFeatSup, AddUpdRes
        if self.Kwargs['T3412ext'] is None:
            self.Kwargs['T3412ext'] = self.UE.T3412ext
        #
        tauacc = TRACKING_AREA_UPDATE_ACCEPT(EPSUpdRes=self.Kwargs['EPSUpdRes'],
                                             T3412=self.Kwargs['T3412'],
                                             GUTI=self.Kwargs['GUTI'],
                                             TAIList=self.Kwargs['TAIList'])
        # combined TA / LA
        if self.Kwargs['EPSUpdRes'] == 1:
            tauacc[9].Trans = False
            tauacc[9].V.Pt = self.Kwargs['LAI']
            tauacc[10].Trans = False
            tauacc[10].V.Pt = self.Kwargs['ID']
        # TODO: EMMCause, T3402, T3423, PLMNList, ECNList, EPSFeatSup, AddUpdRes, T3412ext
        #
        self.init_timer()
        self._trace('DL', tauacc)
        return tauacc
    
    def _process_complete(self, naspdu):
        #
        # remove the old TMSI
        if self.UE.EMM['TMSI'] in self.MME.TMSI:
            del self.MME.TMSI[self.UE.EMM['TMSI']]
        # set the new one
        self.MME.TMSI[self._tmsi] = self.UE.IMSI
        self.UE.EMM['TMSI'] = self._tmsi
        self._log('INF', 'completed, GUTI reallocated, TMSI {0}'.format(hexlify(self._tmsi)))
        # disable possible *freshness* of the security context 
        # (as no RAB context is established during TAU)
        if self.UE.SEC['Fresh']:
            self.UE.SEC['Fresh'] = False 
        #
        self._end()
        return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# EMM connection management procedures, 5.6, started by the UE

# Service request, 5.6.1
# UE: SERVICE REQUEST -> MME [: SERVICE REJECT -> UE]
# UE: EXTENDED SERVICE REQUEST -> MME [: SERVICE REJECT -> UE]
# SERVICE REQUEST has no Type parameter, but only a specific Security Header
# EXTENDED SERVICE REQUEST has Type 76
class ServiceRequest(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 76)
    Filter = []
    Timer = None
    Kwargs = {
        'EMMCause': None, # uint < 255
        'T3442': None, # uint < 255, to 1-byte bytes
        'T3346': None, # bytes
        }
    
    def process(self, naspdu):
        #
        # trace the NAS msg content
        self._trace('UL', naspdu)
        #
        # check if we need to run an Authentication
        if self.UE.nas_need_auth('SERV'):
            proc = self.UE.init_nas_proc(Authentication)
            return proc.output()
        #
        # check if we need to run a Sec Mode Ctrl
        elif self.UE.nas_need_smc('SERV'):
            proc = self.UE.init_nas_proc(SecurityModeControl)
            return proc.output()
        #
        # otherwise, go directly to postprocess
        return self.postprocess()
    
    def postprocess(self, proc=None):
        #
        # if an authentication just happened, we take the new security context into use
        if isinstance(proc, Authentication):
            if self.UE.nas_need_smc('SERV'):
                proc = self.UE.init_nas_proc(SecurityModeControl)
                return proc.output()
        #
        # check if there are ERAB to activate (all should be activated)
        if self.UE.ESM_CTXT_ACT:
            if self.UE.ESM['RAB']:
                self.UE.s1_setup_initial_ctxt(self.UE.ESM['RAB'].keys())
            else:
                self._log('WNG', 'no ERAB to activate')
        self._end()
        #
        # check if there is MME-initiated procedure to run
        if self.UE._proc_mme is not None:
            if isinstance(self.UE._proc_mme, UENASSigProc):
                proc = self.UE.init_nas_proc(self.UE._proc_mme[0])
            elif isinstance(self.UE._proc_mme, (tuple, list)) and len(self.UE._proc_mme) >= 2:
                proc = self.UE.init_nas_proc(self.UE._proc_mme[0], **self.UE._proc_mme[1])
            self.UE._proc_mme = None
            return proc.output()
        else:
            return None
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()


# SMS, 5.6.3, UPLINK NAS TRANSPORT
# WNG: name is prefixed with NAS, not to clash with S1 procedure
class NASUplinkNASTransport(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 99)
    Filter = []
    Timer = None
    Kwargs = {}

# LPP / LCS, 5.6.4, UPLINK GENERIC NAS TRANSPORT
class UplinkGenericNASTransport(UENASSigProc):
    Dom = 'EMM'
    Type = (7, 105)
    Filter = []
    Timer = None
    Kwargs = {}


#----------------#
# MME-initiated  #
# ESM procedures #
#----------------#

# Default context activation, 6.4.1
# This is actually the only MME-initiated ESM procedure supported, yet
# MME: ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST -> UE: ACTIVATE DEFAULT EPS BEARER ACCEPT -> MME
# MME: ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST -> UE: ACTIVATE DEFAULT EPS BEARER REJECT -> MME
class DefaultEPSBearerCtxtAct(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 193)
    Filter = [(2, 194), (2, 195)]
    Timer = 'T3485'
    Kwargs = {
        'EBT': 0, # uint < 16, EPS bearer ID
        'TI': 0, # uint < 255, transaction ID
        'EQoS': None, # bytes, EPS QoS
        'APN': None, # bytes
        'PDNAddr': None, # bytes
        'LTI': None, # bytes, Linked transaction ID
        'QoS': None, # bytes, negotiated QoS
        'LLC_SAPI': None, # 1-byte, something to do with GPRS
        'RadioPrio': None, # uint < 16
        'PFlowID': None, # bytes
        'APN_AMBR': None, # bytes
        'ESMCause': None, # 1-byte
        'ProtConfig': None, # bytes
        'ConType': None, # uint < 16
        }

    
    def output(self):
        #
        # change ESM state
        self.UE.ESM['state'] = 'PROCEDURE-TRANSACTION-PENDING'
        #
        if self.Kwargs['EQoS'] is None:
            self.Kwargs['EQoS'] = '\0'
        if self.Kwargs['APN'] is None:
            self.Kwargs['APN'] = '\0'
        if self.Kwargs['PDNAddr'] is None:
            self.Kwargs['PDNAddr'] = '\x01\0\0\0\0'
        #
        esmpdu = ACTIVATE_DEFAULT_EPS_BEARER_CTX_REQUEST(EBT=self.Kwargs['EBT'],
                                                         TI=self.Kwargs['TI'],
                                                         EQoS=self.Kwargs['EQoS'],
                                                         APN=self.Kwargs['APN'],
                                                         PDNAddr=self.Kwargs['PDNAddr'])
        if self.Kwargs['ProtConfig'] is not None:
            esmpdu[14].Trans = False
            esmpdu[14].V.Pt = self.Kwargs['ProtConfig']
        #
        # TODO: support more options
        #
        # setup the RAB parameters within the UE ESM context
        self.UE.nas_build_rab_default(self.Kwargs['EBT'], self.Kwargs['APN'][1:])
        # prepare the S1AP message to activate the DRB in the eNB
        if self.UE.ESM_CTXT_ACT:
            if self.UE.ESM['active']:
                # another Default EPS Bearer is already active
                self.UE.s1_setup_erab([self.Kwargs['EBT']])
            else:
                # a brand new DRB context is required
                self.UE.s1_setup_initial_ctxt([self.Kwargs['EBT']])
        #
        self._trace('DL', esmpdu)
        self.init_timer()
        return esmpdu
    
    def process(self, esmpdu):
        self._trace('UL', esmpdu)
        #
        # ensures the ERAB-ID reported by the UE is OK
        if esmpdu[0]() != self.Kwargs['EBT']:
            self._log('WNG', 'invalid E-RAB ID: {0}'.format(self.Kwargs['EBT']))
            self._end()
            return None
        if self.Kwargs['EBT'] not in self.UE.ESM['RAB']:
            self._log('WNG', 'E-RAB ID {0} was not set properly in the ESM context'.format(self.Kwargs['EBT']))
            self._end()
            return None
        #
        apn = self.Kwargs['APN'][1:]
        if esmpdu[3]() == 194:
            # EPS bearer activation (in self.UE.ESM['active']) is set by the S1 procedure
            self._log('INF', 'default bearer activated for EPS bearer ID {0}, APN {1}'.format(
                      self.Kwargs['EBT'], apn))
        else:
            # ensures the DRB has not been activated and delete the RAB
            if self.Kwargs['EBT'] not in self.UE.ESM['active']:
                del self.UE.ESM['RAB'][self.Kwargs['EBT']]
                self._log('WNG', 'default bearer rejected for EPS bearer ID {0}, APN {1}'.format(
                          self.Kwargs['EBT'], apn))
            else:
                self._log('ERR', 'default bearer rejected for EPS bearer ID {0}, APN {1}, but E-RAB setup'.format(
                          self.Kwargs['EBT'], apn))
        #
        self._end()
        return None
    
    def _end(self, state=None):
        UENASSigProc._end(self, state='PROCEDURE-TRANSACTION-INACTIVE')
        # delete ESM transaction
        if self.Kwargs['TI'] in self.UE.ESM['trans']:
            del self.UE.ESM['trans'][self.Kwargs['TI']]
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()


# Dedicated context activation, 6.4.2
# MME: ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST -> UE: ACTIVATE DEDICATED EPS BEARER ACCEPT -> MME
# MME: ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST -> UE: ACTIVATE DEDICATED EPS BEARER REJECT -> MME
class DedicatedEPSBearerCtxtAct(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 197)
    Filter = [(2, 198), (2, 199)]
    Timer = 'T3485'
    Kwargs = {
        'TI': 0, # uint < 255, transaction ID (header)
        'Bearer': None, # uint < 16, Linked EPS bearer
        'EQoS': None, # bytes, EPS QoS
        'TFT': None, # bytes
        'TI2': None, # uint < 255, transaction ID (opt arg for A/Gb/Iu mode mobility)
        'QoS': None, # bytes, negotiated QoS
        'LLC_SAPI': None, # 1-byte, something to do with GPRS
        'RadioPrio': None, # uint < 16
        'PFlowID': None, # bytes
        'ProtConfig': None, # bytes
        }

# Context modification, 6.4.3
# MME: MODIFY EPS BEARER CONTEXT REQUEST -> UE: MODIFY EPS BEARER ACCEPT -> MME
# MME: MODIFY EPS BEARER CONTEXT REQUEST -> UE: MODIFY EPS BEARER REJECT -> MME
class EPSBearerCtxtMod(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 201)
    Filter = [(2, 202), (2, 203)]
    Timer = 'T3486'
    Kwargs = {
        'EBT': 5, # uint < 16, EPS bearer ID
        'TI': 0, # uint < 255, transaction ID (header)
        'EQoS': None, # bytes, new EPS QoS
        'TFT': None, # bytes
        'QoS': None, # bytes, new QoS
        'LLC_SAPI': None, # 1-byte, something to do with GPRS
        'RadioPrio': None, # uint < 16
        'PFlowID': None, # bytes
        'APN_AMBR': None, # bytes
        'ProtConfig': None, # bytes
        }

# Context deactivation, 6.4.4
# MME: DEACTIVATE EPS BEARER CONTEXT REQUEST -> UE: DEACTIVATE EPS BEARER ACCEPT -> MME
class EPSBearerCtxtDeact(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 205)
    Filter = [(2, 206)]
    Timer = 'T3495'
    Kwargs = {
        'EBT': 5, # uint < 16, EPS bearer ID
        'TI': 0, # uint < 255, transaction ID (header)
        'ESMCause': None, # uint < 255
        'ProtConfig': None, # # bytes or ProtConfig()
        'T3396': None, # bytes
        }
    
    def output(self):
        #
        # change ESM state
        self.UE.ESM['state'] = 'PROCEDURE-TRANSACTION-PENDING'
        #
        if self.Kwargs['ESMCause'] is None:
            self.Kwargs['ESMCause'] = sef.UE.ESM_BR_DEACT
        #
        esmpdu = DEACTIVATE_EPS_BEARER_CTX_REQUEST(EBT=self.Kwargs['EBT'],
                                                   TI=self.Kwargs['TI'],
                                                   ESMCause=self.Kwargs['ESMCause'])
        # add optional args
        if self.Kwargs['ProtConfig'] is not None:
            esmpdu[5].Trans = False
            esmpdu[5].Pt = self.Kwargs['ProtConfig']
        if self.Kwargs['T3396'] is None and self.UE.T3396 is not None:
            self.Kwargs['T3396'] = self.UE.T3396
        if self.Kwargs['T3396'] is not None:
            esmpdu[6].Trans = False
            esmpdu[6].Pt = self.Kwargs['T3396']
        #
        # prepare the S1AP message to deactivate the DRB in the eNB
        if len(self.UE.ESM['active']) > 1:
            # some Default EPS Bearer will remain active
            self.UE.s1_release_erab([self.Kwargs['EBT']])
        else:
            # the whole DRB can be stopped
            self.UE.s1_release_ctxt([self.Kwargs['EBT']])
        #
        self._trace('DL', esmpdu)
        self.init_timer()
        return esmpdu
    
    def process(self, esmpdu):
        self._trace('UL', esmpdu)
        #
        # ensures ERAB-ID reported by the UE is OK
        if esmpdu[0]() != self.Kwargs['EBT']:
            self._log('WNG', 'invalid E-RAB ID: {0}'.format(self.Kwargs['EBT']))
            self._end()
            return None
        if self.Kwargs['EBT'] not in self.UE.ESM['RAB']:
            self._log('WNG', 'E-RAB ID {0} was not set properly in the ESM context'.format(self.Kwargs['EBT']))
            self._end()
            return None
        #
        # delete the RAB context corresponding to the PDN
        self._log('DBG', 'deactivating ERAB-ID {0}'.format(self.Kwargs['EBT']))
        del self.UE.ESM['RAB'][self.Kwargs['EBT']]
        #
        self._end()
        return None
    
    def _end(self, state=None):
        UENASSigProc._end(self, state='PROCEDURE-TRANSACTION-INACTIVE')
        # delete ESM transaction
        if self.Kwargs['TI'] in self.UE.ESM['trans']:
            del self.UE.ESM['trans'][self.Kwargs['TI']]
    
    def timeout(self):
        UENASSigProc.timeout(self)
        self._end()

# Get ESM information from the UE, 6.6.1
# MME: ESM INFORMATION REQUEST -> UE: ESM INFORMATION RESPONSE -> MME
class ESMInformation(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 217)
    Filter = [(2, 218)]
    Timer = 'T3489'
    Kwargs = {
        'TI': 0, # transaction ID, uint8
        }
    
    def output(self):
        #
        # change ESM state
        self.UE.ESM['state'] = 'PROCEDURE-TRANSACTION-PENDING'
        #
        esmpdu = ESM_INFORMATION_REQUEST(TI=self.Kwargs['TI'])
        #
        self._trace('DL', esmpdu)
        self.init_timer()
        return esmpdu
    
    def process(self, esmpdu):
        self._trace('UL', esmpdu)
        #
        # enrich the transaction parameters according to the transaction ID
        tid = esmpdu[2]()
        if tid not in self.UE.ESM['trans']:
            self._log('WNG', 'unknown transaction ID {0}'.format(tid))
        else:
            trans = self.UE.ESM['trans'][tid]
            # (over)write APN and ProtConfig parameters
            if not esmpdu[4].is_transparent():
                trans['APN'] = esmpdu[4].getobj()[1:]
            if not esmpdu[5].is_transparent():
                # TODO: ensures it's OK to overwrite an existing ProtConfig
                if 'ProtConfigReq' in trans:
                    self._log('DBG', 'overwriting Protocol Configuration Options')
                trans['ProtConfigReq'] = esmpdu[5].getobj()
        #
        self._end()
        return None

# Notify UE of ESM specific situation, 6.6.2
# MME: ESM NOTIFICATION -> UE
class ESMNotification(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 219)
    Filter = []
    Timer = None
    Kwargs = {
        'NotifInd': None, # bytes
        }

#----------------#
# UE-initiated   #
# ESM procedures #
#----------------#

# UE-requested PDN connectivity, 6.5.1
# UE: PDN CONNECTIVITY REQUEST -> MME [: PDN CONNECTIVITY REJECT -> UE]
# if accepted, triggers an DefaultEPSBearerCtxtAct from the MME to the given PDN
class PDNConnectRequest(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 208)
    Filter = []
    Timer = None
    Kwargs = {
        # PDN CONNECTIVITY REJECT
        'ESMCause': None, # uint8
        'ProtConfig': None, # bytes or ProtConfig()
        'T3396': None, # bytes
        }
    
    def process(self, esmpdu):
        #
        self._trace('UL', esmpdu)
        # change ESM state
        self.UE.ESM['state'] = 'PROCEDURE-TRANSACTION-PENDING'
        #
        # get transaction ID and store associated transaction parameters
        self._tid = esmpdu[2]()
        if self._tid in self.UE.ESM['trans']:
            # transaction ID already in use
            return self._reject(cause=35)
        #
        trans = {}
        if esmpdu[5]() != 1:
            self._log('DBG', 'type: {0}'.format(repr(esmpdu[5])))
        # get PDN con type
        trans['PDNType'] = esmpdu[4]()
        # get APN (TLV, optional)
        if not esmpdu[7].is_transparent():
            trans['APN'] = esmpdu[7].getobj()[1:]
        else:
            trans['APN'] = self.UE.ESM_APN_DEF
        # get protocol config (TLV, optional)
        if not esmpdu[8].is_transparent():
            trans['ProtConfigReq'] = esmpdu[8].getobj()
        # get device properties
        if not esmpdu[9].is_transparent():
            trans['DevProp'] = esmpdu[9].getobj()
        # store those parameters in the ESM context
        self.UE.ESM['trans'][self._tid] = trans
        #
        # check if an ESMInformation is required
        if not esmpdu[6].is_transparent():
            proc = self.UE.init_nas_proc(ESMInformation, TI=self._tid)
            return proc.output()
        #
        return self.postprocess()
    
    def postprocess(self, proc=None):
        #
        # if Proc is DefaultEPSBearerCtxtAct, everything OK, just exit
        if isinstance(proc, DefaultEPSBearerCtxtAct):
            self._end(state='PROCEDURE-TRANSACTION-INACTIVE')
            return None
        #
        # if acceptable, start a DefaultEPSBearerCtxtAct
        # otherwise, send a PDN CON REJECT
        trans = self.UE.ESM['trans'][self._tid]
        cause = None
        ctxt = self.UE.nas_build_pdn_default_ctxt(trans['APN'])
        if ctxt is None:
            cause = 27 # unknown APN
        elif trans['PDNType'] != ctxt['IP'][0]:
            cause = 28 # unknown PDN type
        elif 'ProtConfigReq' not in trans:
            cause = 31 # reject, unspecified (no ProtConfig request)
        else:
            ip, pc = self.UE.nas_build_pdn_protconfig(ctxt, trans['ProtConfigReq'])
            if ip is None or pc is None:
                cause = 30 # reject by PDN-GW
            else:
                trans['EBT'] = self.UE.nas_get_new_rabid()
                if trans['EBT'] is None:
                    cause = 65 # max number of bearer reached
        if cause is not None:
            return self._reject(cause)
        #
        trans['ProcConfigResp'] = pc
        trans['ctxt'] = ctxt
        #
        apn = '{0}{1}'.format(chr(len(trans['APN'])), trans['APN'])
        pdn_addr = '{0}{1}'.format(chr(trans['PDNType']), ip)
        eqos = chr(ctxt['QCI'])
        #
        proc = self.UE.init_nas_proc(DefaultEPSBearerCtxtAct,
                                     EBT=trans['EBT'],
                                     TI=self._tid,
                                     EQoS=eqos,
                                     APN=apn,
                                     PDNAddr=pdn_addr,
                                     ProtConfig=pc)
        return proc.output()
        
    def _reject(self, cause=111):
        if self.Kwargs['ESMCause'] is None:
            if cause is None:
                self.Kwargs['ESMCause'] = self.UE.ESM_BR_DEF_REJ
            else:
                self.Kwargs['ESMCause'] = cause
        #
        esmpdu = PDN_CONNECTIVITY_REJECT(TI=self._tid,
                                         ESMCause=self.Kwargs['ESMCause'])
        #
        # add optional args
        if self.Kwargs['ProtConfig'] is not None:
            esmpdu[5].Trans = False
            esmpdu[5].Pt = self.Kwargs['ProtConfig']
        if self.Kwargs['T3396'] is None and self.UE.T3396 is not None:
            self.Kwargs['T3396'] = self.UE.T3396
        if self.Kwargs['T3396'] is not None:
            esmpdu[6].Trans = False
            esmpdu[6].Pt = self.Kwargs['T3396']
        #
        self._end(state='PROCEDURE-TRANSACTION-INACTIVE')
        if self._tid in self.UE.ESM['trans']:
            del self.UE.ESM['trans'][self._tid]
        self._trace('DL', esmpdu)
        return esmpdu
        

# UE-requested PDN disconnect, 6.5.2
# UE: PDN DISCONNECT REQUEST -> MME [: PDN DISCONNECT REJECT -> UE]
# if accepted, triggers an EPSBearerCtxtDeact from the MME
class PDNDisconnectRequest(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 210)
    Filter = []
    Timer = None
    Kwargs = {
        # PDN DISCONNECT REJECT
        'ESMCause': None, # uint8
        'ProtConfig': None, # btyes or ProtConfig()
        }
    
    def process(self, esmpdu):
        #
        self._trace('UL', esmpdu)
        # change ESM state
        self.UE.ESM['state'] = 'PROCEDURE-TRANSACTION-PENDING'
        #
        cause = None
        # get transaction ID and store associated transaction parameters
        self._tid = esmpdu[2]()
        if self._tid in self.UE.ESM['trans']:
            # transaction ID already in use
            return self._reject(cause=35)
        #
        trans = {}
        # get the EPS bearer ID to disconnect
        trans['EBT'] = esmpdu[5]()
        # check if this default bearer exists
        rabid_list = self.UE.ESM['RAB'].keys()
        if trans['EBT'] not in rabid_list:
            # invalid EPS bearer ID
            return self._reject(cause=43)
        # check if another default bearer will remain
        if len(rabid_list) == 1:
            # last PDN disconnection not allowed
            return self._reject(cause=49)
        self.UE.ESM['trans'] = trans
        #
        # TODO: process potential Protocol Configuration parameters
        #
        # start a new ESM procedure EPSBearerCtxtDeact with ESMCause 36 (regular deactivation)
        proc = self.UE.init_nas_proc(EPSBearerCtxtDeact,
                                     EBT=trans['EBT'],
                                     TI=self._tid,
                                     ESMCause=36)
        return proc.output()
    
    def postprocess(self, proc=None):
        # proc should always be EPSBearerCtxtDeact
        self._end(state='PROCEDURE-TRANSACTION-INACTIVE')
        return None
    
    def _reject(self, cause=111):
        if self.Kwargs['ESMCause'] is None:
            if cause is None:
                self.Kwargs['ESMCause'] = self.UE.ESM_BR_DEACT
            else:
                self.Kwargs['ESMCause'] = cause
        #
        esmpdu = PDN_CONNECTIVITY_REJECT(TI=self._tid,
                                         ESMCause=self.Kwargs['ESMCause'])
        #
        # add optional args
        if self.Kwargs['ProtConfig'] is not None:
            esmpdu[5].Trans = False
            esmpdu[5].Pt = self.Kwargs['ProtConfig']
        #
        self._end(state='PROCEDURE-TRANSACTION-INACTIVE')
        self._trace('DL', esmpdu)
        return esmpdu

# UE-requested bearer resource allocation, 6.5.3
# UE: BEARER RESOURCE ALLOCATION REQUEST -> MME [: BEARER RESOURCE ALLOCATION REJECT]
# if accepted, triggers a DedicatedEPSBearerCtxtAct or EPSBearerCtxtMod from the MME
class BearerResAllocRequest(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 212)
    Filter = []
    Timer = None
    Kwargs = {}

# UE-requested bearer resource modification, 6.5.4
# UE: BEARER RESOURCE MODIFICATION REQUEST -> MME [: BEARER RESOURCE MODIFICATION REJECT]
# if accepted, triggers a DedicatedEPSBearerCtxtAct or EPSBearerCtxtMod or EPSBearerCtxtDeact from the MME
class BearerResModifRequest(UENASSigProc):
    Dom = 'ESM'
    Type = (2, 214)
    Filter = []
    Timer = None
    Kwargs = {}

#---------------------------#
# NAS Signalling Procedures #
#---------------------------#

# UE initiated procedures
UESigProcDispatch = {
    65: Attach,
    69: UEDetach,
    72: TrackingAreaUpdate,
    76: ServiceRequest,
    99: NASUplinkNASTransport,
    105: UplinkGenericNASTransport,
    208: PDNConnectRequest,
    210: PDNDisconnectRequest,
    212: BearerResAllocRequest,
    214: BearerResModifRequest,
    }

# MME initiated procedures
MMESigProcDispatch = {
    69: MMEDetach,
    80: GUTIReallocation,
    82: Authentication,
    85: Identification,
    93: SecurityModeControl,
    97: EMMInformation,
    98: NASDownlinkNASTransport,
    104: DownlinkGenericNASTransport,
    193: DefaultEPSBearerCtxtAct,
    197: DedicatedEPSBearerCtxtAct,
    201: EPSBearerCtxtMod,
    205: EPSBearerCtxtDeact,
    217: ESMInformation,
    219: ESMNotification,
    }

# EMM procedures
# GUTI reallocation, authentication, security mode control, identification
EMMCommon_MMEMsgType = [80, 82, 85, 93, 97]
EMMCommon_UEMsgType = [81, 83, 86, 92, 94, 95]
# Attach , detach, tracking area update
EMMSpecific_MMEMsgType = [66, 68, 69, 70, 73, 75]
EMMSpecific_UEMsgType = [65, 67, 69, 70, 72, 74]
# Service request, paging, DL / UL NAS (generic) transport
EMMConMgt_MMEMsgType = [98, 104]
EMMConMgt_UEMsgType = [76, 99, 105]
#
EMM_MMEMsgType = EMMCommon_MMEMsgType + EMMSpecific_MMEMsgType + EMMConMgt_MMEMsgType
EMM_UEMsgType = EMMCommon_UEMsgType + EMMSpecific_UEMsgType + EMMConMgt_UEMsgType

# ESM procedures
# MME-initiated default / dedicated bearer context management
ESMMME_MMEMsgType = [193, 197, 201, 205]
ESMMME_UEMsgType = [194, 195, 198, 199, 202, 203, 206]
# UE-requested ESM procedures
ESMUE_MMEMsgType = [209, 211, 213, 215]
ESMUE_UEMsgType = [208, 210, 212, 214]
# Miscalleneous
ESMMisc_MMEMsgType = [217, 219]
EMMMisc_UEMsgType = [218]
#
ESM_MMEMsgType = ESMMME_MMEMsgType + ESMUE_MMEMsgType + ESMMisc_MMEMsgType
ESM_UEMsgType = ESMMME_UEMsgType + ESMUE_UEMsgType + EMMMisc_UEMsgType
