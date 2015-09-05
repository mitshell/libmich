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
# * File Name : mobnet/utils.py
# * Created : 2015-02-18
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from time import sleep, time
from datetime import datetime
from threading import Thread
from binascii import hexlify, unhexlify
from struct import pack, unpack
#
from libmich.formats.L3Mobile_IE import ID, GUTI, PLMN, LAI
#
# ASN.1 imports and PER codec config
from libmich.asn1.utils import _make_GLOBAL
from libmich.asn1.processor import PER, ASN1, load_module, GLOBAL
ASN1Obj = ASN1.ASN1Obj
ASN1Obj._DEBUG = 0
ASN1Obj._SAFE = True
#ASN1Obj._SAFE = False
ASN1Obj._RAISE_SILENTLY = False
ASN1Obj._RET_STRUCT = False
ASN1Obj.CODEC = PER
PER.VARIANT = 'A'
PER._SAFE = True
#PER._SAFE = False
PER._ENUM_BUILD_DICT = False
#
# S1AP ASN.1 db in GLOBAL, RRCLTE ASN.1 db in GLOBAL_RRCLTE, RRC3G ASN.1 db in GLOBAL_RRC3G
try:
    load_module('S1AP')
    GLOBAL_RRCLTE = _make_GLOBAL()
    load_module('RRCLTE', GLOBAL_RRCLTE)
    GLOBAL_RRC3G = _make_GLOBAL()
    load_module('RRC3G', GLOBAL_RRC3G)
except Exception as err:
    print('unable to load ASN.1 modules (S1AP, RRCLTE, RRC3G), exception: {0}'.format(err))
    print('you need to compile them before running corenet')

# dedicated error
class MMEErr(Exception):
    pass

# Signalling stack handler (e.g. for UEd and ENBd)
class SigStack(object):
    pass

# Signalling procedure handler (e.g. for UES1SigProc, UENASSigProc and ENBProc)
class SigProc(object):
    pass

class UESigProc(SigProc):
    pass

# S1AP procedure codes: eNB related or UE related
# unimplemented: 39 (PrivateMessage), 48 (UERadioCapMatch), 49 (PWSRestartInd)
S1APENBProcCodes = [10, 14, 15, 17, 29, 30, 34, 35, 36, 37, 38, 40, 41, 43, 46, 47]
S1APUEProcCodes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 31, 32, 33, 42, 44, 45]

# thread launcher
def threadit(f, *args, **kwargs):
    th = Thread(target=f, args=args, kwargs=kwargs)
    th.start()
    return th

# coloured logs
TRA_COLOR_START = '\x1b[94m'
TRA_COLOR_END = '\x1b[0m'

# logging facility
def log(msg='', withdate=True):
    #print('[%s] %s' % (datetime.now(), msg))
    if withdate:
        open('/tmp/corenet.log', 'a').write('[{0}] {1}\n'.format(datetime.now(), msg))
    else:
        open('/tmp/corenet.log', 'a').write(msg)

# recursive copy routines (dict / list - friendly)
def cpdict(d):
    ret = {}
    for k in d:
        if isinstance(d[k], dict):
            ret[k] = cpdict(d[k])
        elif isinstance(d[k], list):
            ret[k] = cplist(d[k])
        else:
            ret[k] = d[k]
    return ret

def cplist(l):
    ret = []
    for e in l:
        if isinstance(e, dict):
            ret.append(cpdict(e))
        elif isinstance(e, list):
            ret.append(cplist(e))
        else:
            ret.append(e)
    return ret

# MAC@ converter
def mac_aton(mac='00:00:00:00:00:00'):
    return unhexlify(mac.replace(':', ''))

# stateless routines
def get_ue_s1ap_id(s1appdu):
    mme_ue_id, enb_ue_id = None, None
    #
    # 3 possible config:
    # no identifiers
    # only ENB-UE-S1AP-ID (when a new UE is attaching the eNB), 1st protocolIE
    # both MME then ENB-UE-S1AP-ID, 1st and 2nd protocolIE
    pIEs = s1appdu[1]['value'][1]['protocolIEs']
    if pIEs[0]['id'] == 0:
        mme_ue_id = pIEs[0]['value'][1]
        if pIEs[1]['id'] == 8:
            enb_ue_id = pIEs[1]['value'][1]
        #else:
        #    assert()
    #
    elif pIEs[0]['id'] == 8:
        enb_ue_id = pIEs[0]['value'][1]
    #
    return mme_ue_id, enb_ue_id

def get_tmsi(naspdu):
    ident = None
    #
    # from basic ID (EPS_IDENTIFY)
    if hasattr(naspdu, 'ID'):
        ident = naspdu.ID.getobj()
    #
    # from EPS ID (ATTACH / DETACH)
    elif hasattr(naspdu, 'EPS_ID'):
        ident = naspdu.EPS_ID.getobj()
    #
    # from GUTI (TAU)
    elif hasattr(naspdu, 'GUTI'):
        ident = naspdu.GUTI.getobj()
    #
    if isinstance(ident, ID):
        if hasattr(ident, 'tmsi'):
            return ident.tmsi()
    elif isinstance(ident, GUTI):
        return ident.MTMSI()
    else:
        return None

def get_imsi(naspdu):
    ident = None
    #
    # from basic ID (EPS_IDENTIFY)
    if hasattr(naspdu, 'ID'):
        ident = naspdu.ID.getobj()
    
    # from EPS ID (ATTACH / DETACH)
    elif hasattr(naspdu, 'EPS_ID'):
        ident = naspdu.EPS_ID.getobj()
    #
    if isinstance(ident, ID):
        return ident.get_imsi()
    else:
        return None

def convert_str_bitstr(s=''):
    h = hexlify(s)
    return (int(h, 16), len(h)*4)

def convert_tai(tai):
    plmn = PLMN()
    plmn.map(tai['pLMNidentity'])
    return (plmn, unpack('>H', tai['tAC'])[0])

def convert_eutran_cgi(eutran_cgi):
    plmn = PLMN()
    plmn.map(eutran_cgi['pLMNidentity'])
    return (plmn, '%.7x' % eutran_cgi['cell-ID'][0])

def decode_UERadioCapability(buf=''):
    per_v = PER.VARIANT
    PER.VARIANT = 'U'
    try:
        GLOBAL_RRCLTE.TYPE['UERadioAccessCapabilityInformation'].decode(buf)
    except:
        PER.VARIANT = per_v
        return None
    UERadCap = GLOBAL_RRCLTE.TYPE['UERadioAccessCapabilityInformation']()
    if UERadCap['criticalExtensions'][0] != 'c1':
        PER.VARIANT = per_v
        return UERadCap
    if UERadCap['criticalExtensions'][1][0] != 'ueRadioAccessCapabilityInformation-r8':
        PER.VARIANT = per_v
        return UERadCap
    if 'ue-RadioAccessCapabilityInfo' not in UERadCap['criticalExtensions'][1][1]:
        PER.VARIANT = per_v
        return UERadCap
    if UERadCap['criticalExtensions'][1][1]['ue-RadioAccessCapabilityInfo'][0] != 'UECapabilityInformation':
        PER.VARIANT = per_v
        return UERadCap
    #
    uecapinfo = UERadCap['criticalExtensions'][1][1]['ue-RadioAccessCapabilityInfo'][1]
    #uecapinfo['rrc-TransactionIdentifier']
    if uecapinfo['criticalExtensions'][0] != 'c1':
        PER.VARIANT = per_v
        return UERadCap
    if uecapinfo['criticalExtensions'][1][0] != 'ueCapabilityInformation-r8':
        PER.VARIANT = per_v
        return UERadCap
    if 'ue-CapabilityRAT-ContainerList' not in uecapinfo['criticalExtensions'][1][1]:
        PER.VARIANT = per_v
        return UERadCap
    #
    for rat in uecapinfo['criticalExtensions'][1][1]['ue-CapabilityRAT-ContainerList']:
        if rat['rat-Type'] == 'eutra':
            try:
                GLOBAL_RRCLTE.TYPE['UE-EUTRA-Capability'].decode(rat['ueCapabilityRAT-Container'])
            except:
                pass
            else:
                rat['ueCapabilityRAT-Container'] = GLOBAL_RRCLTE.TYPE['UE-EUTRA-Capability']()
        elif rat['rat-Type'] == 'utra':
            try:
                GLOBAL_RRC3G.TYPE['InterRATHandoverInfo'].decode(rat['ueCapabilityRAT-Container'])
            except:
                pass
            else:
                rat['ueCapabilityRAT-Container'] = GLOBAL_RRC3G.TYPE['InterRATHandoverInfo']()
        elif rat['rat-Type'] == 'geran-cs':
            # MSCm2 || MSCm3
            pass
        elif rat['rat-Type'] == 'geran-ps':
            # MSRACap
            pass
        elif rat['rat-Type'] == 'cdma2000-1XRTT':
            pass
    #
    PER.VARIANT = per_v
    return UERadCap
