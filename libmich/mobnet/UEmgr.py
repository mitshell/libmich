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
# * File Name : mobnet/UEmgr.py
# * Created : 2015-07-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# export filtering
#__all__ = ['UEd']

from socket import inet_aton
from collections import deque

from libmich.core.element import Str, Int
from libmich.formats.L3Mobile import parse_L3, L3Call
from libmich.formats.L3Mobile_NAS import Layer3NAS
from libmich.formats.L3Mobile_EMM import *
from libmich.formats.L3Mobile_ESM import *
from libmich.formats.L3Mobile_SMS import CP_DATA, CP_ACK, CP_ERROR
from libmich.formats.L3Mobile_IE import * # GUTI, TAIList, PLMN, UESecCap
from libmich.formats.PPP import *

# for cryptographic operations (MAC / cipher)
from CryptoMobile import CM
# for authentication vector conversion functions
from CryptoMobile.Milenage import *

from .utils import *
from .UES1proc import *
from .UENASproc import *
from .UESMSproc import *
from .ENBmgr import Paging


# UE capability keywords
_Cap_kw = ('UENetCap', 'UESecCap', 'UERadCap', 'MSNetCap', 'MSCm2', 'MSCm3', 
           'DRX', 'SuppCodecs', 'AddUpdType', 'VoicePref', 'DevProp', 'MSFeatSup')


class UEd(SigStack):
    '''
    The UEd instance handles all S1AP / NAS / EMM / ESM procedures related to a specific UE.
    
    attributes:
        IMSI: IMSI of the UE
        MME: reference to the MMEd parent instance
        ENB: eNB global ID of the eNB to which the UE is connected
        
        SEC: NAS security context
        EMM: NAS mobility context
        ESM: NAS session context
        CAP: list all capabilities reported by the UE
        
        Proc: dict of ongoing procedures (UESigProc), indexed by type ('S1', 'EMM', 'ESM')
        Proc_last: procedure code of the last S1 procedure to have sent an S1AP PDU to the eNB
    '''
    #
    # to keep track of all S1 / NAS / SMS procedures and associated PDU
    # WNG: it can consume memory (nothing will be garbage-collected)
    # WNG: this is different from the MMEd.TRACE_* attributes
    TRACE_S1 = True
    TRACE_NAS = True
    TRACE_SMS = True
    #
    #--------------#
    # NAS security #
    # config       #
    #--------------#
    #
    NASSEC_MAC = False # accept / drop received NASPDU with invalid MAC
    NASSEC_ULCNT = False # resynch with UE-provided NAS UL count / drop received NASPDU with invalid NAS UL count
    #
    #------------#
    # EMM config #
    #------------#
    #
    # Attach reject codes
    ATT_REJ_LOC = 13 # reject due to bad location: 13: roaming not allowed in this TA
    ATT_REJ_ID = 22 # reject due to identity issue: 2: IMSI unknown in HLR, 11: PLMN not allowed, 12: TA not allowed, 22: congestion
    # extended attach features
    ATT_EQU_PLMN = None # equivalent PLMNs
    ATT_ECN_LIST = [(0b1, '6669')] # list of (emergency service category, emergency number)
    ATT_EPS_FEAT = 0b00101111 # EPS network feature support (uint8; bit0:IMS VoPS, bit1: EMC BS, bit2: EPC-LCS, bit34: CS-LCS, bit5: ESR PS)
    ATT_ADD_UPD = 0b01 # additional update result (uint4; 0: no info, 1: CSFB not preferred, 2: SMS only, 3: reserved)
    #
    # Detach request codes, when initiated by the MME
    DET_TYPE = 1 # 1:Re-attach required, 2:Re-attach not required, 3:IMSI detach
    #
    # Authentication procedure standard behaviour
    # AUTH_POL: authentication rate policy: 1/X, if 0, never authenticates
    AUTH_POL_ATT = 1
    AUTH_POL_TAU = 1
    AUTH_POL_SERV = 10
    AUTH_AMF = b'\x80\x00' # Authentication Management Field
    # Authentication procedure specific behaviour
    AUTH_ACT = True # enable / disable authentication procedure (if disabled, SMC will fail)
    AUTH_VERIF = True # enable / disable authentication response RES verification
    AUTH_RAND = None # if 16-bytes are set, they are used as RAND challenge
    #
    # SMC procedure standard behaviour
    SMC_IMEI_POL = 1 # policy to request IMEISV in SMC: 0:never, 1:only when not already collected, 2:at each SMC
    SMC_EEA = [0, 1, 2, 3] # encryption algorithm priority: 0:None, 1:SNOW, 2:AES, 3:ZUC
    SMC_EIA = [1, 2, 3] # integrity protection algorithm priority: 0:None (emergency call only), 1:SNOW, 2:AES, 3:ZUC
    # SMC procedure specific behaviour.
    SMC_ACT = True # enable / disable SMC procedure (if disabled, NAS security will fail)
    SMC_KSI = None # if an int (0<=X<=15) is set, it overrides the NASKSI from the SEC context
    #
    # Service Request: if MME-initiated procedures are buffered
    # they are all sent to the UE if set to False, or deleted if set to True
    SERV_DEL_PROCBUF = False
    #
    #------------#
    # ESM config #
    #------------#
    #
    # ESM Bearer ID:
    # Each UP connection flaw is identified by a bearer ID, from 5 to 15.
    # Each bearer ID index refers to the parameters corresponding to a default bearer (including APN, IP@, DNS, ...),
    # or a dedicated bearer (linked to a default one).
    # All established bearers are stored in the ESM context, indexed by 'RAB'.
    #
    # ESM Packet Data Network:
    # This lists the APN available for the UE and associated parameters for setting a default bearer.
    # The '*' is a wildcard that allows the network to accept and echo any APN requested by the UE,
    # with a given set of parameters for setting a default bearer to it.
    ESM_PDN = {
        '*': {
            'IP':[1, '0.0.0.0'], # PDN type (1:IPv4, 2:IPv6, 3:IPv4v6), UE IP@
            'DNS':[None, None], # 2 IP@ for DNS servers
            'QCI': 9, # QoS class id (9: internet browsing), NAS + S1 parameter
            'PriorityLevel': 15, # no priority (S1 parameter)
            'PreemptCap': 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption' (S1 parameter)
            'PreemptVuln': 'not-pre-emptable', # 'pre-emptable' (S1 parameter)
            },
        'corenet': {
            'IP':[1, '0.0.0.0'], # PDN type (1:IPv4, 2:IPv6, 3:IPv4v6), UE IP@
            'DNS':[None, None], # 2 IP@ for DNS servers
            'QCI': 9, # QoS class id (9: internet browsing), NAS + S1 parameter
            'PriorityLevel': 15, # no priority (S1 parameter)
            'PreemptCap': 'shall-not-trigger-pre-emption', # or 'may-trigger-pre-emption' (S1 parameter)
            'PreemptVuln': 'not-pre-emptable', # 'pre-emptable' (S1 parameter)
            },
        }
    #
    # ESM procedures standard behaviour
    ESM_APN_DEF = 'corenet' # default APN, when no APN is explicitely requested by the UE (must be defined in ESM_PDN too)
    ESM_APN_IP = True # assign the IP address for the given APN, even if an IP@ is not requested
    ESM_BR_AGGR_BITRATE_DL = 10000000 # S1 parameter when setting up the DRB (bit/s)
    ESM_BR_AGGR_BITRATE_UL =  5000000 # S1 parameter when setting up the DRB (bit/s)
    ESM_BR_DEF_REJ = 26 # default ESM cause when rejecting default bearer: 26:insufficient resources
    ESM_BR_DEDI_REJ = 60 # default ESM cause when rejecting dedicated bearer: 60:bearer handling not supported
    ESM_BR_DEACT = 36 # default ESM cause when deactivating EPS bearer: 36:regular deactivation
    #
    # ESM procedures specific behaviour
    ESM_CTXT_ACT = True # to setup a DRB context when UE activate context / requests service and has E-RAB configured
    #
    #------------------------#
    # EMM / ESM / SMS timers #
    #------------------------#
    #
    # GUTI realloc / attach accept
    T3450 = 1
    # authent (requires USIM computation) and sec mode ctrl
    T3460 = 2
    # ident
    T3470 = 1
    #
    # TAU cycle (signalled to the UE)
    # GPRS Timer (24.008, 10.5.7.3):
    # bit 6-8: timer unit (0: 2sec, 1: 1mn, 2: 6mn, 7: deactivated)
    # bit 0-5: value
    #T3412 = 0 # keep the UE default value
    #T3412 = 1 # TAU every 2 sec. (how is this possible ?)
    #T3412 = 17 # TAU every 1 mn
    #T3412 = 40 # TAU every 8 mn
    T3412 = 63 # TAU every 31 mn
    #T3412 = 95 # TAU every 186 mn
    #
    # other optional timers signalled to the UE
    # GPRS Timer
    T3346 = None # or bytes, TLV-wrapped GPRS Timer
    T3396 = None # or bytes, TLV-wrapped GPRS Timer
    T3402 = None # or uint8, GPRS Timer
    T3412ext = None # or bytes, TLV-wrapped
    T3423 = None # or uint8
    #
    # paging
    T3413 = 4
    # detach (net-initiated)
    T3422 = 2
    # EPS bearer ctx act (net-initiated), when not packed inside EMM message
    T3485 = 1
    # EPS bearer ctx modif (net-initiated), when not packed inside EMM message
    T3486 = 1
    # ESM information (net-initiated), when not packed inside EMM message
    T3489 = 1
    # EPS bearer ctx deact (net-initiated), when not packed inside EMM message
    T3495 = 1
    #
    # SMS-CP
    TC1star = 4
    
    
    def _log(self, logtype='DBG', msg=''):
        if logtype[:9] in ('TRACE_NAS', 'TRACE_SMS'):
            self.MME._log(logtype, '[UE: {0}]\n{1}'.format(self.IMSI, msg))
        else:
            self.MME._log(logtype, '[UE: {0}] {1}'.format(self.IMSI, msg))
    
    #----------------#
    # initialization #
    # routines       #
    #----------------#
    
    def __init__(self, imsi, mmed):
        # init identity
        self.IMSI = imsi
        # reference to MME
        self.MME = mmed
        # eNB Global ID to which the UE is connected
        self.ENB = None
        #
        self.ESM_PDN = cpdict(self.__class__.ESM_PDN)
        #
        # dict of S1, EMM, ESM procedures
        self.Proc = {}
        # last S1 procedure code run
        self.Proc_last = None
        # list of procedures processed, depends on self.TRACE_S1 and self.TRACE_NAS
        self._proc = []
        # last NAS procedure to output a NAS PDU
        self._proc_out = None
        # stack of waiting MME-initiated NAS procedures, to be run after a UE is paged
        self._proc_mme = deque()
        #
        self.init_cap()
        self.init_s1()
        self.init_sec()
        self.init_emm()
        self.init_esm()
        self.init_sms()
    
    def init_cap(self):
        if not hasattr(self, 'CAP'):
            self.CAP = {}
        for kw in _Cap_kw:
            self.CAP[kw] = None
    
    def init_s1(self):
        if not hasattr(self, 'S1'):
            self.S1 = {}
        self.S1['MME_UE_ID'] = None
        self.S1['ENB_UE_ID'] = None
        self.S1['TAI'] = None
        self.S1['EUTRAN-CGI'] = deque(maxlen=100)
        self.s1_unset()
        # s1dl_struct serves as an indicator to the S1 layer to send back specific S1 DL message
        self._s1dl_struct = None
    
    def init_sec(self):
        if not hasattr(self, 'SEC'):
            self.SEC = {}
            self.SEC['KSI'] = {} # dict of NASKSI value (0..15) -> security-ctx list [nas_ul_cnt, nas_dl_cnt, kasme]
            self.SEC['vec'] = None, # last auth vector used, None or bytes
        self.SEC['POL'] = {'ATT':0, 'TAU':0, 'SERV':0} # authentication policy counters
        self.SEC['active'] = None # int, value of the activated NASKSI 0<=X<=15, if None NAS security is disabled
        self.SEC['EEA'] = None # int, selected encr algo, None or 0<=X<=3
        self.SEC['EIA'] = None # int, selected integr prot algo, None or 0<=X<=3
        self.SEC['Knas_enc'] = None # bytes, cached NAS encr key
        self.SEC['Knas_int'] = None # bytes, cached NAS integr prot key
        self.SEC['SMC'] = False # if True, triggers an SMC (re-selecting auth vec and/or EEA-EIA)
        self.SEC['Fresh'] = False # if True, indicates the UL NAS count has been reset to the START value
    
    def init_emm(self):
        if not hasattr(self, 'EMM'):
            self.EMM = {}
        # EMM states:
        # 'EMM-DEREGISTERED' -> 'EMM-COMMON-PROCEDURE-INITIATED' -> 'EMM-REGISTERED' -> 'EMM-DEREGISTERED-INITIATED'
        self.EMM['state'] = 'EMM-DEREGISTERED'
        self.EMM['TMSI'] = None
        self.EMM['IMEI'] = None
        self.EMM['IMEISV'] = None
        # combined IMSI / EPS attachment
        self.EMM['combined'] = False
        #
        # EMM procedures, 2-stage stack of procedures
        # Auth, SMC, Ident can be run within UE-initiated procedure
        self.Proc['EMM'] = []
    
    def init_esm(self):
        if not hasattr(self, 'ESM'):
            self.ESM = {}
        # ESM states:
        # for each EPS default bearer (1 / APN), this is actually not handled explicitely:
        # 'BEARER-CONTEXT-INACTIVE' -> 'BEARER-CONTEXT-ACTIVE-PENDING' -> 'BEARER-CONTEXT-ACTIVE' -> 'BEARER-CONTEXT-INACTIVE-PENDING'
        #                                                                                            'BEARER-CONTEXT-MODIFY-PENDING'
        # but can be retrieved from the ESM['active'] list
        #
        # when an ESM procedure transaction is running:
        # 'PROCEDURE-TRANSACTION-INACTIVE' <-> 'PROCEDURE-TRANSACTION-PENDING'
        #
        self.ESM['state'] = 'PROCEDURE-TRANSACTION-INACTIVE'
        # for storing established E-RAB, indexed by ERAB-ID (5..15)
        self.ESM['RAB'] = {}
        # for listing E-RAB ID which are activated
        self.ESM['active'] = []
        # for storing ESM transaction parameters, indexed by transaction ID
        self.ESM['trans'] = {}
        #
        # ESM procedures, 2-stage stack of procedures
        # bearer mgt can be run within UE-initiated procedure
        self.Proc['ESM'] = []
    
    def init_ipaddr(self, ip, apn=None):
        if apn is None:
            for apn in self.ESM_PDN:
                self.ESM_PDN[apn]['IP'][1] = ip
        elif apn in self.ESM_PDN:
            self.ESM_PDN[apn]['IP'][1] = ip
    
    def init_sms(self):
        if not hasattr(self, 'SMS'):
            self.SMS = {}
        # SMS-RP buffers, indexed by SMS-CP transaction ID
        self.SMS['trans'] = {}
        #
        # SMS-CP procedures, indexed by SMS-CP transaction ID
        self.Proc['SMS'] = {}
    
    #--------------#
    # printing     #
    # device infos #
    #--------------#
    
    def show_ident(self):
        print('IMSI: {0}'.format(self.IMSI))
        if self.EMM['TMSI']:
            print('TMSI: {0}'.format(hexlify(self.EMM['TMSI'])))
        if self.EMM['IMEI']:
            print('IMEI: {0}'.format(self.EMM['IMEI']))
        if self.EMM['IMEISV']:
            print('IMEISV: {0}'.format(self.EMM['IMEISV']))
    
    def show_cap(self, with_asn1=False):
        if self.CAP['UENetCap']:
            print('UE Network Capability:\n{0}\n'.format(self.CAP['UENetCap'].show()))
        if self.CAP['MSNetCap']:
            print('MS Network Capability:\n{0}\n'.format(self.CAP['MSNetCap'].show()))
        if self.CAP['MSCm2']:
            print('MS Classmark 2:\n{0}\n'.format(self.CAP['MSCm2'].show()))
        if self.CAP['MSCm3']:
            print('MS Classmark 3:\n{0}\n'.format(self.CAP['MSCm3'].show()))
        if self.CAP['DRX']:
            print('Discontinuous Rx:\n{0}\n'.format(self.CAP['DRX'].show()))
        if self.CAP['VoicePref']:
            print('Voice Preference:\n{0}\n'.format(self.CAP['VoicePref'].show()))
        if with_asn1 and self.CAP['UERadCap']:
            if len(self.CAP['UERadCap']) == 1:
                print('UE Radio Capability (undecoded):\n{0}\n'.format(hexlify(self.CAP['UERadCap'][0])))
            else:
                print('UE Radio Capability:\n{0}\n'.format(self.CAP['UERadCap'][1]))
        # TODO: Device Property, Voice Preference, MS Feature Support, Additional Update Type, Supplementary Codecs
    
    #--------------#
    # S1 interface #
    # management   #
    #--------------#
    
    def s1_set(self, enb_gid, mme_ue_id, enb_ue_id):
        self.ENB = self.MME.ENB[enb_gid]
        self.S1['MME_UE_ID'] = mme_ue_id
        self.S1['ENB_UE_ID'] = enb_ue_id
        # S1AP procedures, multiple procedures can run in parallel
        # indexed by S1AP code -> S1AP procedure instance
        self.Proc['S1'] = {}
    
    def s1_unset(self):
        self.ENB = None
        if self.S1['MME_UE_ID'] in self.MME.UE_MME_ID:
            del self.MME.UE_MME_ID[self.S1['MME_UE_ID']]
        self.S1['MME_UE_ID'] = None
        self.S1['ENB_UE_ID'] = None
        self.S1['RRC-Establishment-Cause'] = None
        self.Proc['S1'] = {}
        if self._proc_mme:
            self._log('DBG', '[s1_unset] {0} MME-initiated procedure(s) resetted'.format(len(self._proc_mme)))
        self._proc_mme = deque()
    
    def s1_setup_initial_ctxt(self, rabid_list):
        # 1 or multiple ERAB-ID can be provided
        # prepare the list of ERAB to be setup
        erab_list = []
        for rabid in rabid_list:
            if rabid not in self.ESM['RAB']:
                self._log('WNG', '[s1_initial_ctxt_setup] unknown ERAB-ID: {0}'.format(rabid))
                return
            else:
                erab = self.ESM['RAB'][rabid]
                erab_list.append({'id': 52,
                                  'criticality': 'reject',
                                  'value': ('E-RABToBeSetupItemCtxtSUReq',
                                            {'e-RAB-ID': rabid,
                                             'e-RABlevelQoSParameters': erab['E-RABlevelQoSParameters'],
                                             'transportLayerAddress': (unpack('>I', inet_aton(erab['SGW-TransportLayerAddress']))[0], 32),
                                             'gTP-TEID': pack('>I', erab['SGW-GTP-TEID'])})})
        #
        # prepare the S1AP DL message InitialContextSetup
        # including the AS security context
        if self.SEC['active'] is None:
            self._log('ERR', '[s1_setup_initial_ctxt] security context missing')
            self._s1dl_struct = None
            return
        else:
            sec_ctxt = self.SEC['KSI'][self.SEC['active']] # nas_ul_cnt, nas_dl_cnt, kasme
            if self.SEC['Fresh']:
                ul_cnt = 0
                self.SEC['Fresh'] = False
            else:
                # NAS UL count has been incremented after the NAS UL msg was processed, so we substract 1 here
                ul_cnt = max(0, sec_ctxt[0]-1)
            kenb = conv_A3(sec_ctxt[2], ul_cnt)
            usc = self.CAP['UESecCap']
        self._log('DBG', '[s1_setup_initial_ctxt] AS security context: NAS KSI {0}, NAS UL count {1}, KeNB {2}'.format(
                  self.SEC['active'], ul_cnt, hexlify(kenb)))
        #
        self._s1dl_struct = {'Code': 9,
                             'Kwargs': {'UEAggregateMaximumBitrate': {
                                            'uEaggregateMaximumBitRateDL': self.ESM_BR_AGGR_BITRATE_DL,
                                            'uEaggregateMaximumBitRateUL': self.ESM_BR_AGGR_BITRATE_UL},
                                        'E_RABToBeSetupListCtxtSUReq': erab_list,
                                        'UESecurityCapabilities': {
                                            'encryptionAlgorithms': ((usc[1]()<<15) + (usc[2]()<<14) + (usc[3]()<<13), 16),
                                            'integrityProtectionAlgorithms': ((usc[9]()<<15) + (usc[10]()<<14) + (usc[11]()<<13), 16)},
                                        'SecurityKey': convert_str_bitstr(kenb)}}
        # TODO: it may be required to add the UERadioCapability: self.CAP['UERadCap'][0]
    
    def s1_setup_erab(self, rabid_list):
        # 1 or multiple ERAB-ID can be provided
        # prepare the list of ERAB to be setup
        erab_list = []
        for rabid in rabid_list:
            if rabid not in self.ESM['RAB']:
                self._log('WNG', '[s1_setup_erab] unknown ERAB-ID: {0}'.format(rabid))
                return
            else:
                erab = self.ESM['RAB'][rabid]
                erab_list.append({'id': 17,
                                  'criticality': 'reject',
                                  'value': ('E-RABToBeSetupItemBearerSUReq',
                                            {'e-RAB-ID': rabid,
                                             'e-RABlevelQoSParameters': erab['E-RABlevelQoSParameters'],
                                             'transportLayerAddress': (unpack('>I', inet_aton(erab['SGW-TransportLayerAddress']))[0], 32),
                                             'gTP-TEID': pack('>I', erab['SGW-GTP-TEID'])})})
        #
        # prepare the S1AP DL message E-RABSetupRequest
        self._s1dl_struct = {'Code': 5,
                             'Kwargs': {'UEAggregateMaximumBitrate': {
                                            'uEaggregateMaximumBitRateDL': self.ESM_BR_AGGR_BITRATE_DL,
                                            'uEaggregateMaximumBitRateUL': self.ESM_BR_AGGR_BITRATE_UL},
                                        'E_RABToBeSetupListBearerSUReq': erab_list}}
    
    def s1_release_erab(self, rabid_list):
        # 1 or multiple ERAB-ID can be provided
        # prepare the list of ERAB to be released
        erab_list = []
        for rabid in rabid_list:
            if rabid not in self.ESM['RAB']:
                self._log('WNG', '[s1_release_erab] unknown ERAB-ID: {0}'.format(rabid))
                return
            else:
                erab = self.ESM['RAB'][rabid]
                erab_list.append({'id': 35,
                                  'criticality': 'reject',
                                  'value': ('E-RABItem',
                                            {'e-RAB-ID': rabid,
                                             'cause': ('nas', 'normal-release')})})
        #
        # prepare the S1AP DL message to start an E-RABReleaseCommand
        self._s1dl_struct = {'Code': 7,
                             'Kwargs': {'UEAggregateMaximumBitrate': {
                                           'uEaggregateMaximumBitRateDL': self.ESM_BR_AGGR_BITRATE_DL,
                                           'uEaggregateMaximumBitRateUL': self.ESM_BR_AGGR_BITRATE_UL},
                                        'E_RABList': erab_list}}
        
    def s1_release_ctxt(self, cause=('nas', 'unspecified')):
        # prepare the S1AP DL message to start a UEContextRelease
        self._s1dl_struct = {'Code': 23,
                             'Kwargs': {'Cause': cause}}
    
    def gtp_enable(self, rabid=None):
        if rabid is None:
            # activate all default E-RAB
            for rabid in range(5, 16):
                if rabid in self.ESM['RAB'] and 'IP' in self.ESM['RAB'][rabid]:
                    self.gtp_enable_rab(rabid)
        elif rabid in self.ESM['RAB'] and 'IP' in self.ESM['RAB'][rabid]:
            self.gtp_enable_rab(rabid)
    
    def gtp_enable_rab(self, rabid):
        rab = self.ESM['RAB'][rabid]
        if rabid not in self.ESM['active']:
            self.ESM['active'].append(rabid)
        self._log('DBG', '[gtp_enable_rab] activating GTP tunnel for E-RAB-ID {0}, mobile IP: {1}'.format(
                  rabid, rab['IP'][1]))
        self.MME.GTPd.add_mobile(rab['IP'][1], rab['ENB-TransportLayerAddress'],
                                 rab['SGW-GTP-TEID'], rab['ENB-GTP-TEID'])
    
    def gtp_disable(self, rabid=None):
        if rabid is None:
            # deactivate all default E-RAB
            for rabid in range(5, 16):
                if rabid in self.ESM['RAB'] and 'IP' in self.ESM['RAB'][rabid]:
                    self.gtp_disable_rab(rabid)
        elif rabid in self.ESM['RAB'] and 'IP' in self.ESM['RAB'][rabid]:
            self.gtp_disable_rab(rabid)
    
    def gtp_disable_rab(self, rabid):
        rab = self.ESM['RAB'][rabid]
        if rabid in self.ESM['active']:
            self.ESM['active'].remove(rabid)
        self._log('DBG', '[gtp_disable_rab] deactivating GTP tunnel for E-RAB-ID {0}, mobile IP: {1}'.format(
                  rabid, rab['IP'][1]))
        self.MME.GTPd.rem_mobile(rab['IP'][1])
    
    #------------#
    # S1AP-PDU   #
    # dispatcher #
    #------------#
    
    def process_pdu(self, pdu):
        # PDU can correspond to:
        # 1) a Class 2 eNB-initiated procedure -> process, no response (or send error)
        # 2) a Class 1 eNB-initiated procedure -> process, send response
        # 3) a Class 1 MME-initiated procedure pending -> process response, no response (or send error)
        #
        # InitialUEMessage,
        # UplinkNASTransport,
        # UECapabilityInfoIndication,
        # UEContextReleaseRequest,
        #
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
                self._log('ERR', '[ENB (S1AP): {0}] eNB error ind, Cause: {1}'.format(self.ENB.GID, cause))
                # this must correspond to the last procedure for which an S1AP PDU has been sent
                if self.Proc_last is not None and self.Proc_last in self.Proc['S1']:
                    # if this procedure is still ongoing, disable it
                    proc = self.Proc['S1'][self.Proc_last]
                    self._log('INF', '[ENB (S1AP): {0}] disabling procedure: {1} ({2})'.format(
                              self.ENB.GID, proc.Name, proc.Code))
                    del self.Proc['S1'][self.Proc_last]
                    self.Proc_last = None
            elif procCode in ENBUESigProcDispatch:
                # 2) initiate a procedure and potentially respond to it
                proc = ENBUESigProcDispatch[procCode](self)
                if self.TRACE_S1:
                    self._proc.append(proc)
                if proc in self.Proc['S1']:
                    # an identical procedure is already ongoing
                    self._log('WNG', '[ENB (S1AP): {0}] overwriting procedure: {1} ({2})'.format(
                              self.ENB.GID, proc.Name, proc.Code))
                # this overwrites potential existing S1 procedure of the same type
                self.Proc['S1'][procCode] = proc
                self.Proc_last = proc.Code
                proc.process(pdu)
                return proc.output()
            else:
                # 3) invalid procedure code used by the eNB
                proc = MMEErrorInd(self, Cause=('protocol', 'semantic-error'))
                if self.TRACE_S1:
                    self._proc.append(proc)
                self.Proc_last = proc.Code
                return proc.output()
        #
        # MME-initiated procedure (class 1)
        else:
            if procCode in self.Proc['S1']:
                # 1) the PDU must correspond to an already initiated procedure
                proc = self.Proc['S1'][procCode]
                proc.process(pdu)
                # it can potentially returns Error Indication
                return proc._ret_pdu
            else:
                # 2) otherwise, send an error
                proc = MMEErrorInd(self, Cause=('protocol', 'semantic-error'))
                if self.TRACE_S1:
                    self._proc.append(proc)
                self.Proc_last = proc.Code
                return proc.output()
    
    def init_s1_proc(self, proc, **kwargs):
        #
        # DownlinkNASTransport,
        # InitialContextSetup,
        # UEContextRelease,
        #
        # proc is a class
        if self.ENB is None or self.ENB.SK is None:
            self._log('WNG', 'unable to initiate procedure {0} ({1}): no S1AP connection'\
                      .format(proc.__name__, proc.Code))
            return
        proc = proc(self, **kwargs)
        # now, proc is an instance
        if proc.Code in Class1UESigProc:
            if proc.Code in self.Proc['S1']:
                self._log('WNG', '[ENB (S1AP): {0}] a procedure {1} ({2}) is already ongoing'\
                          .format(self.ENB.GID, proc.Name, proc.Code))
                return
            self.Proc['S1'][proc.Code] = proc
        if self.TRACE_S1:
            self._proc.append(proc)
        self.Proc_last = proc.Code
        return proc
    
    #------------------------#
    # routines to compute    #
    # specific UE-associated #
    # parameters             #
    #------------------------#
    
    def nas_reset_proc(self):
        if self.Proc['EMM']:
            for emm_proc in reversed(self.Proc['EMM']):
                emm_proc._end()
        if self.Proc['ESM']:
            for esm_proc in reversed(self.Proc['ESM']):
                esm_proc._end()
        if self.Proc['SMS']:
            for sms_proc in self.Proc['SMS'].values():
                sms_proc._end()
        if self._proc_mme:
            self._log('DBG', '[nas_reset_proc] {0} MME-initiated procedure(s) resetted'.format(len(self._proc_mme)))
        self._proc_mme = deque()
    
    def nas_build_ueseccap(self):
        # if we have UENetCap (and MSNetCap), we can build UESecCap
        if self.CAP['UENetCap']:
            ueseccap = UESecCap()
            uenetcap = self.CAP['UENetCap']
            if len(uenetcap) >= 4:
                # UENetCap has LTE and UMTS alg
                L = range(0, 32)
                L.remove(24) # 24th element is UCS2 in UENetCap, spare in UESecCap
                for i in L:
                    ueseccap[i].Pt = uenetcap[i]()
                #
                if self.CAP['MSNetCap']:
                    # MSNetCap has GPRS encr alg
                    msnetcap = self.CAP['MSNetCap']
                    for gea in ueseccap[32:]:
                        gea.Trans = False
                    ueseccap[33].Pt = msnetcap[0]() # GEA 1
                    extgeabits = msnetcap.ExtGEABits # GEA 2 to 7
                    for i in range(0, 6):
                        ueseccap[34+i].Pt = extgeabits[i]()
                    self.CAP['UESecCap'] = ueseccap
                else:
                    self.CAP['UESecCap'] = ueseccap[0:32]
            else:
                # UENetCap has LTE alg only
                for i in range(0, 16):
                    ueseccap[i].Pt = uenetcap[i]()
                self.CAP['UESecCap'] = ueseccap[0:16]
        else:
            self._log('ERR', 'unable to set UE security capabilities')
            self.CAP['UESecCap'] = None
    
    def nas_build_tailist(self):
        # build a list with the unique TAI reported by the eNB at the S1 layer for the UE radio session
        # needed for Attach() and TrackingAreaUpdate()
        plmn, tac = self.S1['TAI']
        p_tai = PartialTAIList0(plmn, TAC=tac)
        return TAIList(p_tai)
    
    def nas_build_guti(self):
        # create a GUTI with a new M-TMSI
        return GUTI(MCCMNC=self.MME.MME_PLMN,
                    MMEGroupID=self.MME.MME_GID,
                    MMECode=self.MME.MME_MMEC,
                    MTMSI=self.MME.get_new_tmsi())
    
    def nas_build_pdn_default_ctxt(self, apn=None):
        if apn in (None, ''):
            # return default APN
            return self.ESM_PDN[self.ESM_APN_DEF]
        elif apn in self.ESM_PDN:
            # return the default bearer for the APN requested
            return self.ESM_PDN[apn]
        elif len(apn) and '*' in self.ESM_PDN:
            # echo the requested APN
            self.ESM_PDN[apn] = cpdict(self.ESM_PDN['*'])
            return self.ESM_PDN[apn]
        else:
            return None
    
    def nas_build_pdn_protconfig(self, ctxt, req):
        # ctxt is the PDN ctxt returned by build_pdn_default_ctxt() for a given APN
        # req is the ProtConfig request from the UE
        ip, resp, dns_req = None, ProtConfig(), True
        if req[2]() != 0:
            # we only expect PPP with IP PDP
            self._log('WNG', 'PDN config protocol unsupported: {0}'.format(repr(req[2])))
            return None, None
        for pid in req[3:]:
            pid_id = pid[0]()
            #
            if pid_id == 3:
                # request DNS IPv6@
                pass
            #
            elif pid_id == 5:
                # TODO
                # support for network requested bearer control indicator
                pass
            #
            elif pid_id == 10:
                # request IP@ signalled within ESM PDU
                try:
                    ip = inet_aton(ctxt['IP'][1])
                except:
                    self._log('ERR', '[nas_build_pdn_protconfig] invalid UE IP format')
            #
            elif pid_id == 13:
                # TODO
                # request DNS IPv4@, this is actually sent within the IPCP payload
                pass
            #
            elif pid_id == 16:
                # TODO
                # IPv4 Link MTU
                pass
            #
            elif pid_id == 32801:
                # IPCP: how many DNS@, ...
                req_ncp = pid[2].getobj()
                if req_ncp[0]() != 1:
                    # we only expect Configure-Request
                    self._log('WNG', 'PDN config for IPCIP, NCP code unsupported: {0}'.format(repr(req_ncp[0])))
                    return None, None
                req_ipcp = req_ncp[3].getobj()
                resp_ipcp, ncp_code = [], 2
                for ipcp in req_ipcp:
                    if ipcp[0]() == 129 and dns_req:
                        # 1st DNS@
                        try:
                            resp_ipcp.append( IPCP(Type=129, Data=inet_aton(ctxt['DNS'][0])) )
                        except:
                            self._log('ERR', '[nas_build_pdn_protconfig] invalid DNS IP format')
                    elif ipcp[0]() == 131 and dns_req:
                        # 2nd DNS@
                        try:
                            resp_ipcp.append( IPCP(Type=131, Data=inet_aton(ctxt['DNS'][1])) )
                        except:
                            self._log('ERR', '[nas_build_pdn_protconfig] invalid DNS IP format')
                    else:
                        self._log('WNG', 'PDN config NCP IPCP type unsupported: {0}'.format(repr(ipcp[0])))
                        ncp_code = 3
                # NCP code: 2: config-ack, 3: config-nack, 4: config-reject, ...
                resp_ncp = NCP(Code=ncp_code, Identifier=req_ncp[1]())
                resp_ncp[3].Pt = resp_ipcp
                resp.append( ProtID(ID=32801, content=resp_ncp) )
            #
            elif pid_id == 49187:
                # PAP pwd auth
                req_ncp = pid[2].getobj()
                if req_ncp[0]() == 1:
                    # PAP Authenticate-Request
                    pap_data = req_ncp[3]()
                    # this id / pwd parsing is done the dirty way
                    try:
                        pap_id = pap_data[1:1+ord(pap_data[0])]
                        pap_pwd = pap_data[2+ord(pap_data[0]):]
                    except:
                        pap_id, pap_pwd = '', '' 
                    self._log('DBG', 'PDN config, PAP id / pwd: {0} / {1}'.format(pap_id, pap_pwd))
                    resp_ncp = NCP(Code=2, Identifier=req_ncp[1](), Data='\0')
                    resp.append( ProtID(ID=49187, content=resp_ncp) )
                else:
                    self._log('WNG', 'PDN config for PAP, NCP code unsupported: {0}'.format(repr(req_ncp[0])))
                    #return None, None
            #
            elif pid_id == 49699:
                # CHAP pwd auth: there must be 2 NCP request (1 with CHAP chall, 1 with CHAP resp)
                req_ncp = pid[2].getobj()
                chap_val = [None, None, None] # id, chall, resp
                if req_ncp[0]() == 1:
                    # CHAP Challenge
                    chap_data = req_ncp[3]()
                    try:
                        chap_val[1] = chap_data[1:1+ord(chap_data[0])]
                        chap_val[0] = chap_data[2+ord(chap_data[0])]
                    except:
                        pass
                elif req_ncp[0]() == 2:
                    # CHAP Response
                    chap_data = req_ncp[3]()
                    try:
                        chap_val[2] = chap_data[1:1+ord(chap_data[0])]
                        if chap_val[0] is None:
                            chap_val[0] = chap_data[2+ord(chap_data[0])]
                    except:
                        pass
                    self._log('DBG', 'PDN config, CHAP id / chall / resp: {0} / {1} / {2}'.format(*chap_data))
                    resp_ncp = NCP(Code=3, Identifier=req_ncp[1](), Data='')
                    resp.append( ProtID(ID=49699, content=resp_ncp) )
                else:
                    self._log('WNG', 'PDN config for CHAP, NCP code unsupported: {0}'.format(repr(req_ncp[0])))
                    #return None, None
            #
            else:
                self._log('WNG', 'PDN config protocol ID unsupported: {0}'.format(repr(pid[0])))
                return None, None
        #
        if ip is None and self.ESM_APN_IP:
            # request IP@ signalled within ESM PDU
            try:
                ip = inet_aton(ctxt['IP'][1])
            except:
                self._log('ERR', '[nas_build_pdn_protconfig] invalid UE IP format')
        #
        return ip, resp
    
    def nas_get_new_rabid(self):
        # provide the next available RAB-ID
        for rabid in range(5, 16):
            if rabid not in self.ESM['RAB']:
                return rabid
        return None
    
    def nas_build_rab_default(self, rabid, apn):
        if apn not in self.ESM_PDN:
            self._log('WNG', '[nas_build_rab_default] unknown APN: {0}'.format(apn))
            return
        if rabid in self.ESM['RAB']:
            self._log('WNG', '[nas_build_rab_default] ERAB-ID already in use: {0}'.format(rabid))
            return
        #
        # get the reference to the PDN config
        pdn_config = self.ESM_PDN[apn]
        # set the default RAB parameters
        self.ESM['RAB'][rabid] = {
            'APN': apn,
            'IP': pdn_config['IP'],
            'DNS': pdn_config['DNS'],
            'E-RABlevelQoSParameters': {'qCI': pdn_config['QCI'],
                                        'allocationRetentionPriority': {
                                            'priorityLevel': pdn_config['PriorityLevel'],
                                            'pre-emptionCapability': pdn_config['PreemptCap'],
                                            'pre-emptionVulnerability': pdn_config['PreemptVuln']}},
            'SGW-TransportLayerAddress': self.MME.get_sgw_addr(),
            'ENB-TransportLayerAddress': None, # will be updated after the eNB setup the ERAB
            'SGW-GTP-TEID': self.MME.get_new_teid(),
            'ENB-GTP-TEID': None, # will be updated after the eNB setup the ERAB
            }
    
    def nas_need_auth(self, proc=None):
        if not self.AUTH_ACT:
            return False
        elif not self.SEC['KSI']:
            # if no sec ctxt exists, auth required
            self._log('DBG', '[need_auth] no security context exists: auth required')
            if proc in self.SEC['POL']:
                self.SEC['POL'][proc] += 1
            return True
        elif proc is None:
            # if procedure is none of Attach, TAU, ServReq
            return False
        elif proc == 'ATT':
            # Attach
            self.SEC['POL']['ATT'] += 1
            if self.AUTH_POL_ATT == 0 or self.SEC['POL']['ATT'] % self.AUTH_POL_ATT:
                return False
            else:
                return True
        elif proc == 'TAU':
            # TAU
            self.SEC['POL']['TAU'] += 1
            if self.AUTH_POL_TAU == 0 or self.SEC['POL']['TAU'] % self.AUTH_POL_TAU:
                return False
            else:
                return True
        elif proc == 'SERV':
            # ServReq
            self.SEC['POL']['SERV'] += 1
            if self.AUTH_POL_SERV == 0 or self.SEC['POL']['SERV'] % self.AUTH_POL_SERV:
                return False
            else:
                return True
    
    def nas_need_smc(self, proc=None):
        if not self.SMC_ACT:
            return False
        # for some procedures, SMC is just mandated (initial UE msg comes in clear)
        if proc in ('ATT', 'TAU'):
            return True
        # just follow one of the 2 triggers:
        # - SMC, which is used to force an SMC to happen
        # - Fresh, which indicates a new fresh NAS sec ctxt is available
        # see 33.401, 7.2.5.2.3
        fresh = self.SEC['Fresh']
        if not self.ESM_CTXT_ACT and self.SEC['Fresh']:
            # no DRB is going to be enabled, so we can disable the key freshness here
            # instead of within s1_setup_initial_ctxt()
            self.SEC['Fresh'] = False
        return self.SEC['SMC'] or fresh
    
    #----------#
    # NAS-PDU  #
    # security #
    #----------#
    
    def nas_process_sec(self, sec_naspdu):
        self._log('TRACE_SEC_UL', sec_naspdu.show())
        # apply the current security context to the NASPDU to process
        #
        # get the Security Header
        sh = sec_naspdu[0]()
        #
        # 1) ensure we have an active KSI
        if self.SEC['active'] is None or self.SEC['active'] not in self.SEC['KSI']:
            # if no active / valid KSI
            return self.nas_process_sec_unknown(sec_naspdu)
        #
        # 2) select the established security context
        ksi = self.SEC['active']
        ul, dl, kasme = self.SEC['KSI'][ksi]
        eea, eia = self.SEC['EEA'], self.SEC['EIA']
        if eea not in (0, 1, 2, 3) or eia not in (0, 1, 2, 3):
            # if no sec algo established
            self._log('ERR', 'invalid EEA / EIA reference in self.SEC[\'EEA\'] / .SEC[\'EIA\']')
            return self.nas_process_sec_unknown(sec_naspdu)
        #
        # 3) verify integrity protection
        if eia != 0: 
            if self.SEC['Knas_int'] is None:
                self.SEC['Knas_int'] = conv_A7(kasme, 2, eia)[16:32]
            sec_naspdu.EIA = getattr(CM, 'EIA{0}'.format(eia))
            verif_mac = sec_naspdu.verify_mac(self.SEC['Knas_int'], 0)
        else:
            verif_mac = True
        if not verif_mac:
            if self.NASSEC_MAC:
                self._log('ERR', 'NASSEC: MAC verification failed; dropping NASPDU')
                return None
            else:
                self._log('WNG', 'NASSEC: MAC verification failed')
        # get the NAS UL count status
        verif_cnt = True if sec_naspdu[3]() == (ul & 0xFF) else False
        if not verif_cnt:
            if self.NASSEC_ULCNT:
                self._log('ERR', 'NASSEC: invalid NAS UL count {0}, expected {1}; dropping NASPDU'.format(sec_naspdu[3](), ul&0xFF))
                return None
            else:
                self._log('WNG', 'NASSEC: resynching NAS UL count')
                self.SEC['KSI'][ksi][0] = sec_naspdu[3]() + (self.SEC['KSI'][ksi][0] & 0xFFFFFF00)
        # increment NAS UL count
        self.SEC['KSI'][ksi][0] += 1
        #
        # 4) decipher
        if eea > 0:
            if self.SEC['Knas_enc'] is None:
                self.SEC['Knas_enc'] = conv_A7(kasme, 1, eea)[16:32]
            sec_naspdu.EEA = getattr(CM, 'EEA{0}'.format(eea))
            naspdu = parse_L3(sec_naspdu.get_deciphered(self.SEC['Knas_enc'], 0))
        else:
            naspdu = parse_L3(sec_naspdu.get_deciphered())
        #
        return naspdu
    
    def nas_process_sec_unknown(self, sec_naspdu):
        # if no active / valid KSI, or selected EEA / EIA
        # be opportunistic: guess it's not ciphered or using EEA0
        self._log('WNG', 'mobile using an unknown security context')
        try:
            # remove NAS security header and reinterpret NASPDU
            naspdu = parse_L3(sec_naspdu.get_deciphered())
        except:
            self._log('ERR', 'unable to decipher NASPDU')
            return None
        if naspdu[0]() == 0 and naspdu[1]() in (2, 7):
            return naspdu
        else:
            self._log('ERR', 'unable to decipher NASPDU')
            return None
    
    def nas_process_servreq(self, sec_naspdu):
        # handle the security of this NAS special message
        ue_ksi = sec_naspdu[2]()
        if ue_ksi in self.SEC['KSI']:
            # if the UE NASKSI is known, we get it active
            self.SEC['active'] = ue_ksi
            ul, dl, kasme = self.SEC['KSI'][ue_ksi]
            eea, eia = self.SEC['EEA'], self.SEC['EIA']
        else:
            # need to establish a brand new security context (Auth + SMC)
            self._log('WNG', 'NASSEC: unknown security context used for the SERVICE REQUEST, cleaning local KSI')
            self.SEC['KSI'] = {}
            return self._nas_process_servreq(sec_naspdu)
        #
        # get the MAC verification status
        if eia is not None and 0 < eia < 4:
            if self.SEC['Knas_int'] is None:
                self.SEC['Knas_int'] = conv_A7(kasme, 2, eia)[16:32]
            # SERVICE REQUEST MAC is only 2 LSBytes, count is on 5 bits
            # get integrity protection algo instance
            sec_naspdu.EIA = getattr(CM, 'EIA{0}'.format(eia))
            verif_mac = sec_naspdu.verify_mac(self.SEC['Knas_int'], 0)
        else:
            verif_mac = True
        # get the NAS UL count status
        verif_cnt = True if sec_naspdu[3]() == (ul & 0x1F) else False
        #
        if not verif_mac:
            if self.NASSEC_MAC:
                self._log('ERR', 'NASSEC: MAC verification failed; dropping NASPDU')
                return None
            else:
                self._log('WNG', 'NASSEC: MAC verification failed')
        if not verif_cnt:
            if self.NASSEC_ULCNT:
                self._log('ERR', 'NASSEC: invalid NAS UL count {0}, expected {1}; dropping NASPDU'.format(sec_naspdu[3](), ul&0x1F))
                return None
            else:
                self._log('WNG', 'NASSEC: invalid NAS UL count {0}, resynching with it'.format(sec_naspdu[3]()))
                self.SEC['KSI'][ue_ksi][0] = sec_naspdu[3]() + (self.SEC['KSI'][ue_ksi][0] & 0xFFFFFFE0)
        #
        # increment NAS UL count
        self.SEC['KSI'][ue_ksi][0] += 1
        return self._nas_process_servreq(sec_naspdu)
    
    def _nas_process_servreq(self, sec_naspdu):
        if self.Proc['EMM']:
            # an EMM procedure is already ongoing
            if self.Proc['EMM'][-1].Name == 'PagingRequest':
                # in case a PagingRequest was made, remove it from the procedure stack
                self.Proc['EMM'][-1]._end()
            else:
                self._log('WNG', '[process_servreq] EMM procedure {0} already ongoing, sending STATUS 101'.format(
                          self.Proc['EMM'][-1].Name))
                return EMM_STATUS(EMMCause=101)
        # start the NAS procedure
        proc = ServiceRequest(self)
        self.Proc['EMM'] = [proc]
        if self.TRACE_NAS:
            self._proc.append(proc)
        return proc.process(sec_naspdu)
    
    def nas_output_sec(self, naspdu):
        # Few procedures might return multiple NAS-PDU from a single uplink message (e.g. SMS)
        # -> this specific message dispatch is handled here
        if isinstance(naspdu, list):
            retpdu = []
            for np in naspdu:
                retpdu.append( self._nas_output_sec(np) )
            return retpdu
        else:
            return self._nas_output_sec(naspdu)
    
    def _nas_output_sec(self, naspdu):
        # apply the current security context to the NASPDU to output
        #
        # 0) if NAS security not activated, just void SH
        if self.SEC['active'] is None:
            # ensure SH is null
            if hasattr(naspdu, 'SH'):
                naspdu[0].Pt = 0
            return naspdu
        #
        # 1) prepare a new NAS message with security header
        sec_naspdu = Layer3NAS(with_security=True)
        #
        # 2) check for naspdu type: security mode command
        if isinstance(naspdu, SECURITY_MODE_COMMAND):
            # if security mode command, 
            # integrity protection only + new security context
            sec_naspdu[0].Pt = 3
        else:
            # integrity + ciphering
            sec_naspdu[0].Pt = 2
        #
        # 3) select appropriate NAS master key and counters
        try:
            ul, dl, kasme = self.SEC['KSI'][self.SEC['active']]
        except KeyError:
            self._log('ERR', 'invalid KSI set in self.SEC[\'active\']')
            return None
        #
        # 4) set the NAS DL counter (only 8 LSB)
        sn_dl = dl & 0xFF
        sec_naspdu[3].Pt = sn_dl
        #
        # 5) select integrity / ciphering alg and derive Knas if needed
        eea, eia = self.SEC['EEA'], self.SEC['EIA']
        if eea not in (0, 1, 2, 3) or eia not in (0, 1, 2, 3):
            self._log('ERR', 'invalid EEA / EIA reference in self.SEC[\'EEA\'] / .SEC[\'EIA\']')
            return None
        #
        naspdu_buf = bytes(naspdu)
        # 6a) if EEA0 or no ciphering applied, no need to derive NAS encryption key
        if eea == 0 or sec_naspdu[0]() in (1, 3):
            sec_naspdu.append( Str('_enc', Pt=naspdu_buf, Repr='hex') )
            if eia == 0:
                # for unauthenticated emergency session (EIA0)
                sec_naspdu[2].Pt = '\0\0\0\0'
                # increment NAS DL count
                self.SEC['KSI'][self.SEC['active']][1] += 1
                return sec_naspdu
        #
        # 6b) ciphering (not applied to SMC)
        if 0 < eea < 4 and naspdu.Type() != 93:
            if self.SEC['Knas_enc'] is None:
                self.SEC['Knas_enc'] = conv_A7(kasme, 1, eea)[16:32]
            # get encryption algo instance
            EEA = getattr(CM, 'EEA{0}'.format(eea))
            # cipher the NASPDU
            ciph = EEA(self.SEC['Knas_enc'], sn_dl, 0, 1, naspdu_buf)
            sec_naspdu.EEA = EEA
            sec_naspdu.append( Str('_enc', Pt=ciph, Repr='hex') )
        #
        # 7) integrity protection
        if 0 < eia < 4:
            if self.SEC['Knas_int'] is None:
                self.SEC['Knas_int'] = conv_A7(kasme, 2, eia)[16:32]
            # get integrity protection algo instance
            EIA = getattr(CM, 'EIA{0}'.format(eia))
            sec_naspdu.EIA = EIA
            sec_naspdu.compute_mac(self.SEC['Knas_int'], 1)
        #
        # 8) increment NAS DL count
        self.SEC['KSI'][self.SEC['active']][1] += 1
        #
        self._log('TRACE_SEC_DL', sec_naspdu.show())
        return sec_naspdu
    
    #------------#
    # NAS-PDU    #
    # dispatcher #
    #------------#
    
    def process_naspdu(self, naspdu_buf):
        '''
        process the whole NAS PDU, as received within the S1AP PDU
        return a NAS PDU (according to any ongoing NAS procedure) or None
        '''
        #
        s0 = ord(naspdu_buf[0])
        sh, pd = s0>>4, s0&0xF
        ret_naspdu = None
        #
        if sh == 0:
            # clear text NAS PDU
            naspdu = parse_L3(naspdu_buf)
            ret_naspdu = self._process_naspdu(naspdu)
        #
        elif pd == 7 and sh in (1, 2, 3, 4):
            # security-protected NAS PDU
            naspdu_sec = Layer3NAS()
            naspdu_sec.map(naspdu_buf)
            naspdu = self.nas_process_sec(naspdu_sec)
            ret_naspdu = self._process_naspdu(naspdu)
        #
        elif sh == 12:
            # NAS service request
            naspdu = SERVICE_REQUEST()
            naspdu.map(naspdu_buf)
            ret_naspdu = self.nas_process_servreq(naspdu)
        #
        else:
            self._log('ERR', 'invalid Security Header / Protocol Discriminator: {0} / {1}'.format(sh, pd))
        #
        if ret_naspdu:
            return self.nas_output_sec(ret_naspdu)
    
    def _process_naspdu(self, naspdu):
        #
        # check the Protocol Discriminator and Type
        pd, ty = naspdu.PD(), naspdu.Type()
        #
        # 0) check for invalid or DetachRequest messages
        if pd not in (2, 7):
            self._log('TRACE_NAS_UL', naspdu.show())
            self._log('WNG', '[process_naspdu] invalid NAS message (PD {0}), sending STATUS 111'.format(pd, ty))
            # Cause 111: Protocol error, unspecified
            stat = EMM_STATUS(EMMCause=111)
            self._log('TRACE_NAS_DL', stat.show())
            return stat
        elif (pd == 7 and ty not in EMM_UEMsgType) or (pd == 2 and ty not in ESM_UEMsgType):
            self._log('TRACE_NAS_UL', naspdu.show())
            self._log('WNG', '[process_naspdu] invalid NAS message (PD {0}, Type {1}), sending STATUS 97'.format(pd, ty))
            # Cause 97: type non existent or not implemented
            if pd == 2:
                stat = ESM_STATUS(EBT=naspdu[0](), TI=naspdu[2](), ESMCause=97)
            else:
                stat = EMM_STATUS(EMMCause=97)
            self._log('TRACE_NAS_DL', stat.show())
            return stat
        elif (pd, ty) == (7, 69):
            # Detach requested by the UE, always prioritized over any other procedures
            proc = UEDetach(self)
            if self.TRACE_NAS:
                self._proc.append(proc)
            # the UEDetach procedure will clean up GTP tunnels, ESM contexts and all ongoing NAS procedures
            return proc.process(naspdu)
        #
        # 1) check against any possible ongoing EMM procedure
        if self.Proc['EMM']:
            if (pd, ty) == (7, 96):
                # EMM STATUS: disable the procedure
                proc = self.Proc['EMM'].pop()
                proc._trace('UL', naspdu)
                proc._end()
                self._log('WNG', '[process_naspdu] EMM STATUS with cause: {0}, disabling {1}'.format(
                          repr(naspdu[3]), proc.Name))
                return None
            elif (pd, ty) in self.Proc['EMM'][-1].Filter:
                proc = self.Proc['EMM'][-1]
                # if the procedure ends, it will remove itself from the self.Proc list
                ret_naspdu = proc.process(naspdu)
                # if the procedure was an MME-initiated, within a UE-initiated one,
                # we need to go back to this last one
                if ret_naspdu is None and self.Proc['EMM']:
                    proc_ue = self.Proc['EMM'][-1]
                    ret_naspdu = proc_ue.postprocess(proc)
                return ret_naspdu
            elif pd == 7:
                # unexpected EMM message
                self._log('TRACE_NAS_UL', naspdu.show())
                self._log('WNG', '[process_naspdu] unexpected EMM message (Type {0}), sending STATUS 98'.format(ty))
                # Cause 98: Message type not compatible with the protocol state
                stat = EMM_STATUS(EMMCause=98)
                self._log('TRACE_NAS_DL', stat.show())
                return stat
        #
        # 2) check against any possible ongoing ESM procedure
        # TODO: actually, it should be possible to handle multiple ESM transaction in parallel (multiplexed)
        # and to demultiplex everything with the EPS Bearer Type (EBT) / ESM Transaction ID (TI)
        if self.Proc['ESM']:
            if (pd, ty) == (2, 232):
                # ESM STATUS: disable the procedure
                proc = self.Proc['ESM'].pop()
                proc._trace('UL', naspdu)
                proc._end()
                self._log('WNG', '[process_naspdu] ESM STATUS with cause: {0}, disabling {1}'.format(
                          repr(naspdu[3]), proc.Name))
                return None
            elif (pd, ty) in self.Proc['ESM'][-1].Filter:
                proc = self.Proc['ESM'][-1]
                ret_naspdu = proc.process(naspdu)
                if ret_naspdu is None and self.Proc['ESM']:
                    proc_ue = self.Proc['ESM'][-1]
                    ret_naspdu = proc_ue.postprocess(proc)
                return ret_naspdu
            elif pd == 2:
                # unexpected ESM message
                self._log('TRACE_NAS_UL', naspdu.show())
                self._log('WNG', '[process_naspdu] unexpected ESM message (Type {0}), sending STATUS 98'.format(ty))
                # Cause 98: Message type not compatible with the protocol state
                stat = ESM_STATUS(EBT=naspdu[0](), TI=naspdu[2](), EMMCause=98)
                self._log('TRACE_NAS_DL', stat.show())
                return stat
        #
        # 3) check for starting a new NAS procedure
        if ty in UESigProcDispatch:
            proc = UESigProcDispatch[ty](self)
            if self.TRACE_NAS:
                self._proc.append(proc)
            if pd == 7:
                self.Proc['EMM'] = [proc]
            elif pd == 2:
                self.Proc['ESM'] = [proc]
            return proc.process(naspdu)
        #
        # 4) out of procedure EMM / ESM STATUS
        elif (pd, ty) == (7, 96):
            self._log('TRACE_NAS_UL', naspdu.show())
            self._log('WNG', '[process_naspdu] EMM STATUS with cause: {0}'.format(repr(naspdu[3])))
        elif (pd, ty) == (2, 232):
            self._log('TRACE_NAS_UL', naspdu.show())
            self._log('WNG', '[process_naspdu] ESM STATUS with cause: {0}'.format(repr(naspdu[3])))        
        #
        # 5) EMM / ESM message out of any procedure
        else:
            self._log('TRACE_NAS_UL', naspdu.show())
            self._log('WNG', '[process_naspdu] unexpected NAS message (PD {0}, Type {1}), sending STATUS 98'.format(pd, ty))
            # Cause 98: Message type not compatible with the protocol state
            stat = EMM_STATUS(EMMCause=98)
            self._log('TRACE_NAS_DL', stat.show())
            return stat
    
    def init_nas_proc(self, proc, **kwargs):
        proc = proc(self, **kwargs)
        self.Proc[proc.Dom].append(proc)
        if self.TRACE_NAS:
            self._proc.append(proc)
        return proc
    
    #----------------#
    # MME-initiated  #
    # NAS procedures #
    #----------------#
    
    def release_ctxt(self, cause=('nas', 'unspecified')):
        if self.ENB is None:
            self._log('INF', '[release] UE not connected')
        proc_s1 = self.init_s1_proc(UEContextRelease, Cause=cause)
        for pdu in proc_s1.output():
            self.MME.send_enb(self.ENB.SK, pdu, uerel=True)        
    
    def page(self):
        # ensures the UE is not already connected
        if self.ENB is not None:
            self._log('INF', '[page] UE already connected')
            return
        # ensures a PagingRequest is not already ongoing
        if self.Proc['EMM'] and self.Proc['EMM'][-1].Name == 'PagingRequest':
            self._log('DBG', '[page] PagingRequest already ongoing')
            return
        # get all eNB serving the TAC on which the UE is registered
        # and send the Paging command to each of it
        tac = self.S1['TAI'][1]
        if tac not in self.MME.TA:
            self._log('INF', '[page] unable to page, no eNB serving the UE TAC {0}'.format(tac))
            return
        proc_nas = self.init_nas_proc(PagingRequest)
        # .output() generates self._s1dl_struct for the S1AP Paging command, but returns nothing (no NAS msg)
        proc_nas.output()
        # if paging with IMSI, no timer is started, procedure just ends
        if self.EMM['TMSI'] is not None:
            proc_nas.init_timer()
        else:
            proc_nas._end()
        for enb_gid in self.MME.TA[tac]:
            enb = self.MME.ENB[enb_gid]
            # sending Paging to the enb
            enb.init_proc(Paging, **self._s1dl_struct['Kwargs'])
        self._s1dl_struct = None
    
    def _run(self, proc, **kwargs):
        # this is to run an MME-initiated procedure, possibly paging the UE first
        if self.ENB is not None:
            # UE already connected
            # 1) empty any possible buffered procedures
            if self._proc_mme:
                if self.SERV_DEL_PROCBUF:
                    self._log('INF', '[_run] deleting {0} buffered NAS procedures'.format(len(self._proc_mme)))
                    self._proc_mme = deque()
                else:
                    self._log('DBG', '[_run] firing {0} buffered NAS procedures'.format(len(self._proc_mme)))
                    while self._proc_mme:
                        proc_nas, kwargs = self._proc_mme.popleft()
                        self.__run_single(proc_nas, **kwargs)
            # 2) run the requested procedure
            self.__run_single(proc, **kwargs)
        else:
            # UE not connected, buffer the procedure and page it
            self._proc_mme.append( (proc, kwargs) )
            self.page()
    
    def __run_single(self, proc, **kwargs):
        proc_nas = self.init_nas_proc(proc, **kwargs)
        proc_s1 = self.init_s1_proc(DownlinkNASTransport, NAS_PDU=self.nas_output_sec(proc_nas.output()))
        for pdu in proc_s1.output():
            self.MME.send_enb(self.ENB.SK, pdu, uerel=True)
    
    
    #------------#
    # SMS-CP PDU #
    # dispatcher #
    #------------#
    
    def process_smscp(self, cpstr):
        '''
        process the SMS-CP PDU, as received within the NAS Container within the Uplink NAS transport
        return an SMS-CP PDU (according to any ongoing SMS-CP procedure) or None
        '''
        # WNG: at this stage, cpstr is a str (bytes)
        # check the Protocol Discriminator and SMS-CP Type
        if len(cpstr) < 2:
            self._log('WNG', '[process_smscp] SMS-CP message too short: {0}'.format(hexlify(cpstr)))
            return None
        if len(cpstr) > 1:
            cpstr_0 = ord(cpstr[0])
            ti, tio = cpstr_0>>7, (cpstr_0>>4)&0x7
            pd, ty = cpstr_0&0xF, ord(cpstr[1])
        #
        # 0) check for invalid messages
        if pd != 9 or ty not in (1, 4, 16):
            #self._log('TRACE_SMS_UL', hexlify(cpstr))
            self._log('WNG', '[process_smscp] invalid SMS-CP message, sending CP-ERROR 97: {0}'.format(hexlify(cpstr)))
            # CP-ERROR, cause 97, message type non existent
            cperr = CP_ERROR(TI=(1, 0)[ti], TIO=tio, CPCause=97)
            self._log('TRACE_SMS_DL', cperr.show())
            return bytes(cperr)
        #
        # 1) check for MO CP procedure
        if ty == 1:
            cppdu = CP_DATA()
            cppdu.map(cpstr)
            if tio in self.Proc['SMS']:
                # SMS transaction already running for this slot
                self._log('TRACE_SMS_UL', cppdu.show())
                self._log('WNG', '[process_smsp] SMS-CP transaction ID already in use, sending STATUS 81')
                cperr = CP_ERROR(TI=(1, 0)[ti], TIO=tio, CPCause=81)
                self._log('TRACE_SMS_DL', cperr.show())
                return bytes(cperr)
            else:
                # start a new SMS transaction
                proc = SmsCpMo(self)
                self.Proc['SMS'][tio] = proc
                if self.TRACE_SMS:
                    self._proc.append(proc)
                return map_bytes( proc.process(cppdu) )
        #
        # 2) check for CP-ACK / CP-ERROR from UE
        elif ty == 4:
            cppdu = CP_ACK()
        else:
            cppdu = CP_ERROR()
        cppdu.map(cpstr)
        #
        if tio not in self.Proc['SMS']:
            # SMS transaction unknown
            self._log('TRACE_SMS_UL', cppdu.show())
            self._log('WNG', '[process_smsp] SMS-CP unknown transaction ID, sending STATUS 81')
            cperr = CP_ERROR(TI=(1, 0)[ti], TIO=tio, CPCause=81)
            self._log('TRACE_SMS_DL', cperr.show())
            return bytes(cperr)
        else:
            proc = self.Proc['SMS'][tio]
            return map_bytes( proc.process(cppdu) )
    
    def init_sms_proc(self, proc, **kwargs):
        if 'TIO' not in kwargs:
            # get any available TIO slot
            kwargs['TIO'] = -1
            for tio in range(0, 8):
                if tio not in self.Proc['SMS']:
                    kwargs['TIO'] = tio
                    break
            if kwargs['TIO'] == -1:
                self._log('ERR', '[init_sms_proc] no SMS-CP TIO available: unable to start procedure')
                return None
        proc = proc(self, **kwargs)
        self.Proc['SMS'][kwargs['TIO']] = proc
        if self.TRACE_SMS:
            self._proc.append(proc)
        return proc
    
    #----------------#
    # MME-initiated  #
    # SMS procedures #
    #----------------#
    
    def _run_smscpmt(self, **kwargs):
        proc_cp = self.init_sms_proc(SmsCpMt, **kwargs)
        proc_nas = self._run(NASDownlinkNASTransport, NASContainer=proc_cp.output())
