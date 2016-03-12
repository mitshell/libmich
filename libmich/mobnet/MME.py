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
# * File Name : mobnet/MME.py
# * Created : 2015-02-18
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# export filtering
#__all__ = ['MMEd', 'S1APSigStack', 'NASSigStack', 'GLOBAL', 'ASN1Obj', 'PER']

# System imports
import sys
import traceback
from select import select
from random import SystemRandom
#
try:
    from sctp import *
except ImportError as err:
    print('pysctp library is required for MME')
    raise(err)
#
from libmich.utils.repr import *
# 3GPP protocol formats imports
from libmich.formats.L3Mobile_IE import PLMN
from libmich.formats.L3Mobile import parse_L3
#
# 3GPP signalling imports
from .utils import *
from .ENBmgr import *
from .UEmgr import *

# S1AP UL PDU UE-related: offset of the NAS message
S1AP_NAS_OFFSET = {
    12: 1, # InitialUEMessage
    13: 2, # UplinkNASTransport
    16: 2, # NASNonDeliveryInd
    }


# MME server
class MMEd(object):
    #
    #-------------------------#
    # debug and tracing level #
    #-------------------------#
    #
    # verbosity level: list of log types to display when calling self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    # for logging SCTP socket send() / recv() content
    TRACE_SK = True
    # for logging ASN.1 PDU decoded / encoded
    TRACE_ASN1 = True
    # for logging NAS security headers decoded / encoded
    TRACE_SEC = True
    # for logging NAS PDU decoded / encoded
    TRACE_NAS = True
    # for logging SMS-CP PDU decoded / encoded
    TRACE_SMS = True
    #
    #---------------------#
    # MME server settings #
    #---------------------#
    #
    # those parameters are configured during self.init_server(ip, port)
    # IP version
    #SERVER_IPVERS = 4
    # IP address to listen to
    #SERVER_IP = ''
    # SCTP port to listen to
    #SERVER_PORT = 36412
    #
    # SCTP socket recv() buffer length
    SERVER_BUFLEN = 2048
    # SCTP server maximum client (S1AP instance -> eNodeB)
    SERVER_MAXCLI = 16
    #
    # MME scheduler resolution:
    # This is the resolution (in second) for the MME to check the list of registered UE,
    # and check for NAS procedures in timeout.
    # This is also applied as a timeout on the main select() loop.
    SCHED_RES = 0.1
    # In case we want to disable cleaning NAS stacks on timeout, set to False
    SCHED_UE_TO = True
    #
    #------------------------#
    # LTE Services referrers #
    #------------------------#
    # These are references to services handlers
    # setup at MMEd initialization
    #
    # Authentication Centre handler
    AUCd = None
    # GPRS tunneling protocol handler
    GTPd = None
    # SMS center handler
    SMSd = None
    # LTE Positionning handler
    LPPd = None
    #
    #-----------------#
    # UE and ENB dict #
    #-----------------#
    # These are tables referencing allowed (and connected) UEs and eNBs
    # setup at MME initialization through config file
    #
    # UE references UEd instances, indexed by IMSI (str)
    #UE = {}
    # UE config for storing IP addresses (at least): imsi: {'IP':@IP}
    #UEConfig = {}
    # when an unknown UE gets connected, a default IP address is configured for it
    UE_UNKNOWN_IP = '192.168.100.250'
    #
    # ENB references ENBd instances, indexed by eNB Global ID (tuple: PLMNIdentity (str), eNB-ID (hex-str))
    #ENB = {}
    # ENB config for whitelisting all eNB Global ID allowed
    # if empty, any eNodeB which advertises our MME PLMN in its Global ID will be allwoed
    #ENBConfig = {}
    #
    #-------------------------#
    # MME specific parameters #
    #-------------------------#
    # Parameters used for S1 link setup
    ConfigS1 = {
    'MMEname': 'MichTelecomMME', # optional
    'ServedGUMMEIs': [
        {'servedPLMNs': [bytes(PLMN('00101'))],
         'servedGroupIDs': ['\x00\x01'],
         'servedMMECs': ['\x01']}
        ], # mandatory, at least 1
    'RelativeMMECapacity': 20, # mandatory, 0 < X < 255
    'MMERelaySupportIndicator': None, # optional
    'CriticalDiagnostics': None, # optional, 'true' otherwise
    }
    # those indexes are used to build the MME main GUMMEI and {PLMN, GID, MMEC}
    _ind_gummei = 0
    _ind_plmn = 0
    _ind_gid = 0
    _ind_mmec = 0
    #
    # after instantiation, the following MME identifiers are available:
    #MME_GUMMEI, MME_PLMN_BUF, MME_PLMN, MME_GID_BUF, MME_GID, MME_MMEC_BUF, MME_MMEC
    
    def _log(self, logtype='DBG', msg=''):
        #
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        # specials: 'TRACE_SK', 'TRACE_ASN1', 'TRACE_SEC', 'TRACE_NAS', 'TRACE_SMS'
        #
        if logtype[:6] == 'TRACE_':
            tracetype = logtype[6:]
            if tracetype[:2] == 'SK' and self.TRACE_SK:
                log('[{0}] [MME: {1}] {2}'.format(logtype, self.MME_GUMMEI, hexlify(msg)))
            elif (tracetype[:4] == 'ASN1' and self.TRACE_ASN1) \
              or (tracetype[:3] == 'SEC' and self.TRACE_SEC) \
              or (tracetype[:3] == 'NAS' and self.TRACE_NAS) \
              or (tracetype[:3] == 'SMS' and self.TRACE_SMS) :
                hdr, cont = msg.split('\n', 1)
                log('[{0}] [MME: {1}] {2}\n{3}{4}{5}'.format(logtype, self.MME_GUMMEI, hdr, TRA_COLOR_START, cont, TRA_COLOR_END))
        elif logtype in self.DEBUG:
            log('[{0}] [MME: {1}] {2}'.format(logtype, self.MME_GUMMEI, msg))
    
    #--------------------#
    # MME initialization #
    #--------------------#
    
    def __init__(self, config={'server':('127.0.1.100', 36412)}):
        #
        # config: dict with keys:
        #   'server', 'ue', 'enb'
        # server: network IP / port tuple 
        #   (IP (str), sctp_port (int))
        # ue: dict with keys:
        #   '$imsi':(gtp_ip (str), ...)
        # enb: tuple of enb_global_id
        #   ($enb_global_id (tuple(str, int)), ...)
        #
        # create un uncorrelated copy of the class Config dict
        self.ConfigS1 = cpdict(self.__class__.ConfigS1)
        #
        # initialize MME GUMMEI (required for ._log())
        self.init_idents()
        #
        # initialize MME config
        if 'server' in config:
            self.init_server(config['server'][0], config['server'][1])
        #
        self.UE = {}
        self.UEConfig = {}
        # for joining UE though their network identities (IP@, phone num for SMS)
        self.IP_IMSI = {}
        self.Num_IMSI = {}
        if 'ue' in config:
            for imsi in config['ue']:
                self.init_ue(imsi, **config['ue'][imsi])
        self._log('DBG', 'UE IMSI configured: {0}'.format(self.UEConfig.keys()))
        # for all MME UE S1AP ID (mme_ue_id: imsi)
        self.UE_MME_ID = {}
        self._ue_mme_id = 0
        self._ue_delayed = {}
        # for all randomly attributed TMSI
        self.TMSI = {}
        #
        self.ENB = {}
        self.ENBConfig = {}
        if 'enb' in config:
            for enb_gid in config['enb']:
                self.init_enb(enb_gid, **config['enb'][enb_id])
        self._log('DBG', 'eNodeB Global ID configured: {0}'.format(self.ENB.keys()))
        # for all SCTP sockets established for each eNB (sk:enb_gid)
        self.ENBSk = {}
        # for all Tracking Areas handled by attached eNB (ta:[enb_gid, ...])
        self.TA = {}
        # for keeping a cache of all randomly attributed downlink TEID
        self._TEID = []
        #
        # S1AP PDU message ASN.1 PER aligned encoder / decoder 
        self._S1AP_PDU = GLOBAL.TYPE['S1AP-PDU']
        #
        # random generator for TMSI
        self._rand = SystemRandom()
        #
        self._running = False
        self._bg = threadit(self.start)
    
    def init_idents(self, ind_gummei=None, ind_plmn=None, ind_gid=None, ind_mmec=None):
        #
        # initializing indexes for the MMEd instance
        if ind_gummei is not None and ind_gummei != self._ind_gummei:
            self._ind_gummei = ind_gummei
            self._log('WNG', 'changing MME GUMMEI index')
        if ind_plmn is not None and ind_plmn != self._ind_plmn:
            self._ind_plmn = ind_plmn
            self._log('WNG', 'changing MME PLMN index')
        if ind_gid is not None and ind_gid != self._ind_gid:
            self._ind_gid = ind_gid
            self._log('WNG', 'changing MME  index')
        if ind_mmec is not None and ind_mmec != self._ind_mmec:
            self._ind_mmec = ind_mmec
            self._log('WNG', 'changing MME  index')
        #
        # selecting the right identifier indexed and setting the right value for the MMEd instance
        if self._ind_gummei >= len(self.ConfigS1['ServedGUMMEIs']):
            gummei = self.ConfigS1['ServedGUMMEIs'][0]
            self._log('WNG', 'invalid MME GUMMEI index')
        else:
            gummei = self.ConfigS1['ServedGUMMEIs'][self._ind_gummei]
        #
        if self._ind_plmn >= len(gummei['servedPLMNs']):
            self.MME_PLMN_BUF = gummei['servedPLMNs'][0]
            self._log('WNG', 'invalid MME PLMN index')
        else:
            self.MME_PLMN_BUF = gummei['servedPLMNs'][self._ind_plmn]
        plmn = PLMN()
        plmn.map(self.MME_PLMN_BUF)
        self.MME_PLMN = plmn.get_mccmnc()
        #
        if self._ind_gid >= len(gummei['servedGroupIDs']):
            self.MME_GID_BUF = gummei['servedGroupIDs'][0]
            self._log('WNG', 'invalid MME Group ID index')
        else:
            self.MME_GID_BUF = gummei['servedGroupIDs'][self._ind_gid]
        self.MME_GID = unpack('!H', self.MME_GID_BUF)[0]
        #
        if self._ind_mmec >= len(gummei['servedMMECs']):
            self.MME_MMEC_BUF = gummei['servedMMECs'][0]
            self._log('WNG', 'invalid MME Group ID index')
        else:
            self.MME_MMEC_BUF = gummei['servedMMECs'][self._ind_mmec]
        self.MME_MMEC = ord(self.MME_MMEC_BUF)
        #
        self.MME_GUMMEI = '{0}.{1}.{2}.{3}'.format(plmn.get_mcc(),
                                                   plmn.get_mnc(),
                                                   hexlify(self.MME_GID_BUF),
                                                   hexlify(self.MME_MMEC_BUF))
    
    def init_server(self, ip=None, port=None):
        '''
        Initialize the SCTP server of the MME.
        The server socket is made available through the *_sk* attribute.
        
        Kwargs:
            ip (str): IP address (V4 or V6 or wildcard), default to ''
            port (int): SCTP port, default to 36412
        
        Returns:
            None
        
        Raises:
            MMEErr
        '''
        # default settings are set as class attributes
        #
        # IP addr
        if ip.count('.') == 3:
            self.SERVER_IPVERS = 4
            self.SERVER_IP = ip
        elif ip.count(':') > 0:
            self.SERVER_IPVERS = 6
            self.SERVER_IP = ip
        #
        # SCTP port
        if 0 < port < 65536:
            self.SERVER_PORT = port
        #
        # TODO: support SCTP multihoming / multi-addresses
        self.SERVER_ADDR = (self.SERVER_IP, self.SERVER_PORT)
        #
        # start SCTP server
        try:
            if self.SERVER_IPVERS == 6:
                self._sk = sctpsocket_tcp(socket.AF_INET6)
            else:
                self._sk = sctpsocket_tcp(socket.AF_INET)
            # S1AP uses SCTP adaptation layer 18
            self._sk.set_adaptation(18)
        except:
            raise(MMEErr('cannot create SCTP socket'))
        try:
            self._sk.bind(self.SERVER_ADDR)
        except:
            raise(MMEErr('cannot bind SCTP socket on address {0}'.format(self.SERVER_ADDR)))
        #
        self._log('DBG', 'SCTP server started on address {0}'.format(self.SERVER_ADDR))
    
    def init_ue(self, imsi, **kwargs):
        # kwargs keys: 'IP'
        self.UEConfig[imsi] = {}
        if 'IP' in kwargs:
            self.UEConfig[imsi]['IP'] = kwargs['IP']
            self.IP_IMSI[kwargs['IP']] = imsi
        else:
            self.UEConfig[imsi]['IP'] = None
            self._log('WNG', 'missing GTP IP address for IMSI {0}'.format(imsi))
        if 'Num' in kwargs:
            self.UEConfig[imsi]['Num'] = kwargs['Num']
            self.Num_IMSI[kwargs['Num']] = imsi
        else:
            self.UEConfig[imsi]['Num'] = None
            self._log('WNG', 'missing phone number for IMSI {0}'.format(imsi))
    
    def init_enb(self, enb_gid, **kwargs):
        # kwargs keys: None, yet
        self.ENBConfig[enb_gid] = {}
    
    #-----------#
    # randomly  #
    # generated #
    # tokens    #
    #-----------#
    
    def get_new_ue_mme_id(self):
        self._ue_mme_id += 1
        if self._ue_mme_id >= 4294967295:
            self._ue_mme_id = 1
        return self._ue_mme_id
    
    def get_new_tmsi(self):
        # TMSI is provided as type: bytes
        v = pack('!I', self._rand.randint(0, 4294967295))
        while v in self.TMSI:
            # this is not efficient, but should not happen that often !
            v = pack('!I', self._rand.randint(0, 4294967295))
        return v
    
    def get_new_teid(self):
        # TEID is provided as type: int
        v = self._rand.randint(0, 4294967295)
        while v in self._TEID:
            v = self._rand.randint(0, 4294967295)
        return v
    
    def get_sgw_addr(self):
        # return the GTPd internal IP for S1AP transportLayerAddress
        return self.GTPd.INT_IP
    
    #---------------------#
    # SCTP server runtime #
    #---------------------#
    #
    # The self.start() method with the main loop can be launched in a background thread
    # It's then possible to stop it with the .stop() method
    #
    def start(self):
        try:
            self._sk.listen(self.SERVER_MAXCLI)
        except:
            self.init_server()
            self._sk.listen(self.SERVER_MAXCLI)
        #
        self._running = True
        self._log('INF', 'SCTP server listening on address {0}'.format(self.SERVER_ADDR))
        #
        # main MME infinite loop using the socket select() call:
        # the loop gets new SCTP stream,
        # gets new SCTP messages for existing SCTP stream,
        # and eventually timeouts running procedures in case no messages are received
        T_lto = time()
        while self._running:
            sk_ready = []
            try:
                sk_ready = select([self._sk] + self.ENBSk.keys(),
                                  [],
                                  [],
                                  self.SCHED_RES)[0]
            except Exception as err:
                self._log('ERR', 'select() failed with Exception: {0}'.format(err))
                self._running = False
            #
            for sk in sk_ready:
                if sk is self._sk:
                    # read from server socket for a new STCP stream (S1SetupRequest)
                    self.handle_stream_new()
                else:
                    # read from established eNB SCTP socket for new message 
                    # (whatever S1AP PDU)
                    self.handle_stream_msg(sk)
            #
            # clean-up potential signalling procedures in timeout
            if self.SCHED_UE_TO:
                if not len(sk_ready) or time() - T_lto > self.SCHED_RES:
                    # select() timeout or more than SCHED_RES since last timeout
                    self.handle_ue_timeout()
                    T_lto = time()
        #
        # server stopped
        self._log('INF', 'SCTP server stopped')
    
    def stop(self):
        # TODO: check when to cleanup ENBd and UEd instances
        #
        # stop the socket server
        if self._running:
            self._running = False
            sleep(self.SCHED_RES)
            for enb_gid in self.ENB:
                self.del_enb(enb_gid)
            # close the main SCTP listener
            self._sk.close()
    
    
    def add_enb(self, enb_gid):
        if enb_gid not in self.ENB:
            return
        enb = self.ENB[enb_gid]
        # update the list of Tracking Area supported by the MME
        if 'SupportedTAs' in enb.Config:
            for ta in enb.Config['SupportedTAs']:
                if ta['tAC'] not in self.TA:
                    self.TA[ta['tAC']] = set([enb_gid])
                else:
                    self.TA[ta['tAC']].add(enb_gid)
        # add the eNB sk to the socket list of the MME
        if enb.SK not in self.ENBSk:
            self.ENBSk[enb.SK] = enb_gid
    
    def del_enb(self, enb_gid):
        if enb_gid not in self.ENB:
            return
        enb = self.ENB[enb_gid]
        # close the SCTP socket
        sk = enb.SK
        if sk is not None:
            sk.close()
        enb.set_sk(None)
        # remove the eNB from the TA list of the MME
        if 'SupportedTAs' in enb.Config:
            for ta in enb.Config['SupportedTAs']:
                if ta['tAC'] in self.TA:
                    try:
                        self.TA[ta['tAC']].remove(enb_gid)
                    except:
                        pass
        # remove the eNB sk from the socket list of the MME
        if sk in self.ENBSk:
            del self.ENBSk[sk]
        # remove S1 info from UE previously attached to this eNB
        for ue in self.UE.values():
            if ue.ENB is not None and ue.ENB.GID == enb_gid:
                ue.s1_unset()
    
    #----------------------#
    # S1AP streams handler #
    #----------------------#
    
    def handle_stream_recv(self, sk):
        # remind the eNB behind the socket
        if sk in self.ENBSk:
            enb_gid = self.ENBSk[sk]
        else:
            enb_gid = ''
        # read the STCP message content
        buf = bytes()
        buf = sk.recv(self.SERVER_BUFLEN)
        if not buf and enb_gid:
            # this is actually an eNB closing its STCP stream
            self.del_enb(enb_gid)
            self._log('DBG', '[eNB: {0}] S1AP stream closed by eNB'.format(enb_gid))
            return
        self._log('TRACE_SK_UL', buf)
        #
        try:
            self._S1AP_PDU.decode(buf)
        except:
            self.send_enb_err(sk, cause=('protocol', 'transfer-syntax-error'))
            self._log('WNG', '[eNB: {0}] closing S1AP stream, S1AP PDU decoding error: {0}'.format(enb_gid, hexlify(buf)))
            self.del_enb(enb_gid)
            return
        #
        self._log('TRACE_ASN1_UL', '[eNB: {0}]\n{1}'.format(enb_gid, self._S1AP_PDU._msg.show()))
        # return the S1AP PDU content values
        return self._S1AP_PDU()
    
    def handle_stream_new(self):
        sk, addr = self._sk.accept()
        self._log('DBG', 'new S1AP stream client from address {0}'.format(addr))
        #
        # get the S1AP PDU content values
        pdu = self.handle_stream_recv(sk)
        if pdu is None:
            sk.close()
            return
        #
        # Any new S1AP stream must start with a proper S1Setup procedure
        # TS 36.413, 8.7.3.1
        if pdu[0] == 'initiatingMessage' and pdu[1]['procedureCode'] == 17:
            self.handle_s1setup(sk, pdu)
        #
        else:
            self.send_enb_err(sk, cause=('protocol', 'message-not-compatible-with-receiver-state'))
            self._log('WNG', 'new S1AP stream without S1Setup (type {0}, code {1}), closing S1AP stream'.format(
                      pdu[0], pdu[1]['procedureCode']))
            sk.close()
    
    def handle_s1setup(self, sk, pdu):
        # get protocolIEs' values
        protIEs = pdu[1]['value'][1]['protocolIEs']
        # get the eNB Global ID
        plmn_id, enb_id = None, None
        for protIE in protIEs:
            if protIE['id'] == 59:
                enb_id_bitstr = protIE['value'][1]['eNB-ID'][1]
                plmn_id_octstr = protIE['value'][1]['pLMNidentity']
                # convert to readable values:
                # 1) enb id
                if enb_id_bitstr[1] == 20:
                    # macroENB-ID
                    enb_id = '%.5x' % enb_id_bitstr[0]
                elif enb_id_bitstr[1] == 28:
                    # homeENB-ID
                    enb_id = '%.7x' % enb_id_bitstr[0]
                # 2) plmn id
                plmn_id = PLMN()
                plmn_id.map(plmn_id_octstr)
                plmn_id = plmn_id.get_mccmnc()
        #
        if plmn_id and enb_id:
            enb_gid = (plmn_id, enb_id)
            # create / reset the eNB handler instance
            ret = self.create_enb_handler(enb_gid, sk)
            if not ret:
                # eNB not allowed
                self.send_enb_err(sk, cause=('misc', 'unknown-PLMN'))
                self._log('WNG', '[eNB: {0}] eNB not allowed, closing S1AP stream'.format(enb_gid))
                sk.close()
                return
            #
            self._log('INF', '[eNB: {0}] S1AP stream established'.format(enb_gid))
            # process the PDU in the context of the eNB handler
            #'''
            try:
                ret_pdu = self.ENB[enb_gid].process_pdu(pdu)
            except Exception as err:
                self._exc = sys.exc_info()
                self._log('ERR', 'something went wrong in the ENBmgr code: {0}'.format(err))
                print('ERROR: something went wrong in the ENBmgr code:\n{0}'.format(err))
                traceback.print_tb(self._exc[2])
            else:
                self.add_enb(enb_gid)
                for pdu in ret_pdu:
                    self.send_enb(sk, pdu)
    
    def create_enb_handler(self, enb_gid, sk):
        if len(self.ENBConfig):
            if enb_gid in self.ENBConfig:
                self._create_enb_handler(enb_gid, sk)
                return True
        # enb_gid = (plmn_id, enb_id)
        elif enb_gid[0] == self.MME_PLMN:
            self._create_enb_handler(enb_gid, sk)
            return True
        return False
    
    def _create_enb_handler(self, enb_gid, sk):
        if enb_gid in self.ENB:
            # eNB already attached the MME in the past
            self.ENB[enb_gid].reset()
            self.ENB[enb_gid].set_sk(sk)
        else:
            # new eNB
            self.ENB[enb_gid] = ENBd(enb_gid, self)
            self.ENB[enb_gid].set_sk(sk)
    
    def handle_stream_msg(self, sk):
        # get the S1AP PDU content values
        pdu = self.handle_stream_recv(sk)
        if pdu is None:
            return
        enb_gid = self.ENBSk[sk]
        #
        # check for ErrorInd related to a UE
        mme_ue_id, enb_ue_id = get_ue_s1ap_id(pdu)
        if pdu[1]['procedureCode'] == 15 and mme_ue_id in self.UE_MME_ID:
            imsi = self.UE_MME_ID[mme_ue_id]
            ue = self.UE[imsi]
            ret_pdu = ue.process(pdu)
            if ret_pdu:
                for pdu in ret_pdu:
                    self.send_enb(sk, pdu)
        #
        # check if it is an eNB-related PDU
        elif pdu[1]['procedureCode'] in S1APENBProcCodes:
            enb = self.ENB[enb_gid]
            #'''
            try:
                ret_pdu = enb.process_pdu(pdu)
            except Exception as err:
                self._exc = sys.exc_info()
                self._log('ERR', 'something went wrong in the ENBmgr code: {0}'.format(err))
                print('ERROR: something went wrong in the ENBmgr code:\n{0}'.format(err))
                traceback.print_tb(self._exc[2])
            else:
                if ret_pdu:
                    for pdu in ret_pdu:
                        self.send_enb(sk, pdu)
        #
        # check if it is a UE-related PDU
        elif pdu[1]['procedureCode'] in S1APUEProcCodes and enb_ue_id is not None:
            # decode potential NAS-PDU
            #self.ue_decode_nas(pdu)
            # check if it is a UE newly attaching to the eNB
            if mme_ue_id is None:
                # get a new MME UE ID
                mme_ue_id = self.get_new_ue_mme_id()
                # try to retrieve the IMSI for the UE
                imsi = self.ue_get_imsi(pdu)
                # if not possible, start a special procedure to request the IMSI 
                # and delay the processing of the pdu
                if imsi is None:
                    self._ue_delayed[mme_ue_id] = pdu
                    self.send_enb(sk, self.ue_request_ident(enb_gid, mme_ue_id, enb_ue_id, ident_type=1))
                # otherwise, just setup the UE handler in the MME registries
                # and pass it the S1AP PDU to process
                else:
                    self.handle_ue_stream_msg(sk, enb_gid, imsi, pdu, initial=True, ue_id=(mme_ue_id, enb_ue_id))
            #
            elif mme_ue_id in self._ue_delayed:
                # we should get an EPS IDENTITY RESPONSE with IMSI here
                imsi = self.ue_retrieve_imsi(pdu, enb_gid)
                if imsi:
                    # setup the UE handler in the MME registries
                    # and pass it the delayed S1AP PDU to process
                    self.handle_ue_stream_msg(sk, enb_gid, imsi, self._ue_delayed[mme_ue_id], initial=True, ue_id=(mme_ue_id, enb_ue_id))
                del self._ue_delayed[mme_ue_id]
            #
            elif mme_ue_id in self.UE_MME_ID:
                imsi = self.UE_MME_ID[mme_ue_id]
                self.handle_ue_stream_msg(sk, enb_gid, imsi, pdu)
            #
            else:
                # unknown S1AP MME UE ID: error
                self.send_enb_err(sk, cause=('radioNetwork', 'unknown-mme-ue-s1ap-id'))
                self._log('WNG', '[eNB: {0}] unknown MME-UE-S1AP-ID {1}'.format(enb_gid, mme_ue_id))
                return
        #
        else:
            # invalid S1AP message
            self.send_enb_err(sk, cause=('protocol', 'semantic-error'))
            self._log('WNG', '[eNB: {0}] unknown S1AP procedureCode {1}'.format(enb_gid, pdu[1]['procedureCode']))
    
    def handle_ue_stream_msg(self, sk, enb_gid, imsi, pdu, initial=False,  ue_id=None):
        ue = self.ue_get_handler(imsi)
        if initial:
            # InitialUEMessage
            self.UE_MME_ID[ue_id[0]] = imsi
            ue.s1_set(enb_gid, ue_id[0], ue_id[1])
        #'''
        try:
            ret_pdu = ue.process_pdu(pdu)
        except Exception as err:
            self._exc = sys.exc_info()
            self._log('ERR', 'something went wrong in the UEmgr code: {0}'.format(err))
            print('ERROR: something went wrong in the UEmgr code:\n{0}'.format(err))
            traceback.print_tb(self._exc[2])
        else:
            if ret_pdu:
                for pdu in ret_pdu:
                    self.send_enb(sk, pdu)
    
    def send_enb(self, sk, pdu):
        # remind the eNB behind the socket
        if sk in self.ENBSk:
            enb_gid = self.ENBSk[sk]
        else:
            enb_gid = ''
        # send the encoded S1AP-PDU to the eNB
        try:
            self._S1AP_PDU.encode(pdu)
        except Exception as err:
            self._log('ERR', '[eNB: {0}] S1AP PDU encoding error: {1}'.format(enb_gid, err))
            self._S1AP_ENC_ERR = pdu
        else:
            self._log('TRACE_ASN1_DL', '[eNB: {0}]\n{1}'.format(enb_gid, self._S1AP_PDU._msg.show()))
            # send the buffer over the SCTP socket
            buf = bytes(self._S1AP_PDU)
            try:
                sk.send(buf)
            except Exception as err:
                self._log('ERR', '[eNB: {0}] unable to send SCTP message, exception: {1}'.format(enb_gid, err))
            else:
                self._log('TRACE_SK_DL', buf)
    
    #--------------------#
    # eNB errors handler #
    #--------------------#
    
    def send_enb_err(self, sk, cause=None, diag=None):
        # send an S1AP Error Indication, not related to any UE,
        # when required early in the MME server process
        # Cause and CriticalityDiagnostics may be provided
        protIEs = []
        if cause is not None:
            protIEs.append({'value': ('Cause', cause),
                            'id': 2,
                            'criticality': 'ignore'})
        if diag is not None:
            protIEs.append({'value': ('CriticalityDiagnostics', diag),
                            'id': 58,
                            'criticality': 'ignore'})
        pdu_val = ('initiatingMessage',
                   {'procedureCode': 15,
                    'value': ('ErrorIndication', {'protocolIEs':protIEs}),
                    'criticality': 'ignore'})
        self.send_enb(sk, pdu_val)
    
    #-------------#
    # UE routines #
    #-------------#
    
    def ue_decode_nas(self, pdu):
        if pdu[1]['procedureCode'] not in S1AP_NAS_OFFSET:
            return
        nas_ie = pdu[1]['value'][1]['protocolIEs'][S1AP_NAS_OFFSET[pdu[1]['procedureCode']]]
        if nas_ie['value'][0] == 'NAS-PDU':
            # OCTET STRING, to be parsed
            nas_ie['value'] = ('NAS-PDU', parse_L3(nas_ie['value'][1]))
    
    def ue_get_imsi(self, pdu):
        # collect S-TMSI and NAS-PDU in the S1AP PDU
        pIEs = pdu[1]['value'][1]['protocolIEs']
        for pIE in pIEs:
            if pIE['id'] == 26:
                # NAS-PDU
                nas = parse_L3(pIE['value'][1])
                tmsi = get_tmsi(nas)
                if tmsi is not None:
                    if tmsi in self.TMSI:
                        return self.TMSI[tmsi]
                else:
                    imsi = get_imsi(nas)
                    if imsi is not None:
                        return imsi
            elif pIE['id'] == 96:
                # S-TMSI, nly m-TMSI is processed, mMEC is ignored
                tmsi = pIE['value'][1]['m-TMSI']
                if tmsi in self.TMSI:
                    return self.TMSI[tmsi]
        return None
    
    def ue_request_ident(self, enb_gid, mme_ue_id, enb_ue_id, ident_type=1):
        # send a NAS-PDU with IMSI request
        naspdu = EPS_IDENTITY_REQUEST(IDType=ident_type)
        pIEs = [{'value': ('MME-UE-S1AP-ID', mme_ue_id),
                 'criticality': 'ignore',
                 'id': 0},
                {'value': ('ENB-UE-S1AP-ID', enb_ue_id),
                 'criticality': 'reject',
                 'id': 8},
                {'value': ('NAS-PDU', bytes(naspdu)),
                 'criticality': 'reject',
                 'id': 26}]
        #
        self._log('TRACE_NAS_DL', '[eNB: {0}] [UE: ]\n{1}'.format(enb_gid, naspdu.show()))
        #
        return ('initiatingMessage',
                {'procedureCode': 11,
                 'value': ('DownlinkNASTransport', {'protocolIEs':pIEs}),
                 'criticality': 'ignore'})
    
    def ue_retrieve_imsi(self, pdu, enb_gid):
        # retrieve the IMSI from the NAS-PDU response
        if pdu[1]['procedureCode'] not in S1AP_NAS_OFFSET:
            return
        nas_ie = pdu[1]['value'][1]['protocolIEs'][S1AP_NAS_OFFSET[pdu[1]['procedureCode']]]
        if nas_ie['value'][0] == 'NAS-PDU':
            naspdu = parse_L3(nas_ie['value'][1])
            self._log('TRACE_NAS_UL', '[eNB {0}] [UE: ]\n{1}'.format(enb_gid, naspdu.show()))
            try:
                ident = naspdu.ID.getobj()
            except:
                pass
            else:
                return ident.get_imsi()
        return None
    
    def ue_get_handler(self, imsi):
        if imsi in self.UE and self.UE[imsi] is not None:
            return self.UE[imsi]
        else:
            ue = UEd(imsi, self)
            if imsi in self.UEConfig:
                ue.init_ipaddr(self.UEConfig[imsi]['IP'])
            else:
                ue.init_ipaddr(self.UE_UNKNOWN_IP)
            self.UE[imsi] = ue
            return ue
    
    def handle_ue_timeout(self):
        T = time()
        for imsi in self.UE:
            ue = self.UE[imsi]
            if ue is not None:
                if ue.Proc['EMM']:
                    for emm_proc in reversed(ue.Proc['EMM']):
                        if hasattr(emm_proc, 'TimerStop') and T > emm_proc.TimerStop:
                            emm_proc.timeout()
                if ue.Proc['ESM']:
                    for esm_proc in reversed(ue.Proc['ESM']):
                        if hasattr(esm_proc, 'TimerStop') and T > esm_proc.TimerStop:
                            esm_proc.timeout()
                if ue.Proc['SMS']:
                    for sms_proc in ue.Proc['SMS'].values():
                        if hasattr(sms_proc, 'TimerStop') and T > sms_proc.TimerStop:
                            sms_proc.timeout()
