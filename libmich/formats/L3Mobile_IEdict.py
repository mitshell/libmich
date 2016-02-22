# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.2
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
# * File Name : formats/L3Mobile_IEdict.py
# * Created : 2015-09-01 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# exporting
#__all__ = []

from libmich.core.IANA_dict import IANA_dict

###
# TS 24.008, 12.10.0 specification
# MM, GPRS MM short IE (Information Element)
###

# 24.008, 10.5.1.2, Ciphering Key Sequence Number unavailibility
CKSN_dict = {7:'No key is available (from MS) / reserved (from network)'}

# 24.008, 10.5.1.15, MS network feature support
MSFeatSup_dict = {
    0:'extended periodic timers not supported',
    1:'extended periodic timers supported'
    }

# 24.008, 10.5.3.3, CM Service type
CMService_dict = {
    1:'Mobile originating call / packet mode connection',
    2:'Emergency call',
    4:'SMS',
    8:'Supplementary service',
    9:'Voice group call',
    10:'Voice broadcast call',
    11:'Location service'
    }

# 24.008, 10.5.3.4, Identity type
IDType_dict = {
    0:'private',
    1:'IMSI',
    2:'IMEI',
    3:'IMEISV',
    4:'TMSI',
    5:'private'
    }

# 24.008, 10.5.3.5, Location updating type
LUType_dict = {
    0:'Normal location updating',
    1:'Periodic updating',
    2:'IMSI attach',
    3:'Reserved',
    8:'Normal location updating - request pending',
    9:'Periodic updating - request pending',
    10:'IMSI attach - request pending',
    11:'Reserved - request pending'
    }

# 24.008, 10.5.3.14, Additional update parameters
AddUpdType_dict = {
    0:'no info',
    1:'CSMT',
    2:'CSMO',
    3:'CSMT+CSMO'
    }

# 24.008, 10.5.5.1, Attach result
AttachRes_dict = {
    1 : 'GPRS Attach',
    3 : 'Combined GPRS / IMSI attach'
    }
AttachResFOP_dict = {
    0 : 'Follow-on proceed',
    1 : 'No follow-on proceed'
    }

# 24.008, 10.5.5.2, Attach type
AttachTypeFOR_dict = {
    0 : 'No follow-on request pending',
    1 : 'follow-on request pending'
    }
AttachType_dict = {
    0 : 'GPRS Attach',
    1 : 'GPRS Attach',
    2 : 'Not used (only in old release)',
    3 : 'Combined GPRS / IMSI attach',
    4 : 'Emergency attach',
    5 : 'GPRS Attach',
    6 : 'GPRS Attach',
    7 : 'GPRS Attach'
    }

# 24.008, 10.5.5.3, Ciphering algorithm
CiphAlg_dict = {
    0 : 'ciphering not used',
    1 : 'GEA/1',
    2 : 'GEA/2',
    3 : 'GEA/3',
    4 : 'GEA/4',
    5 : 'GEA/5',
    6 : 'GEA/6',
    7 : 'GEA/7'
    }

# 24.008, 10.5.5.4, TMSI status
TMSIStatus_dict = {
    0 : 'No valid TMSI available',
    1 : 'valid TMSI available'
    }

# 24.008, 10.5.5.5, Detach type
DetachTypeNet_dict = {
    1:'Re-attach required',
    2:'Re-attach not required',
    3:'IMSI detach (after VLR failure)'
    }
DetachTypeMS_dict = {
    1:'GPRS detach',
    2:'IMSI detach',
    3:'Combined GPRS/IMSI detach',
    9:'Power switched off; GPRS detach',
    10:'Power switched off; IMSI detach',
    11:'Power switched off; combined GPRS/IMSI detach'
    }

# 24.008, 10.5.5.7, Force to stand-by
ForceStdby_dict = {
    0 : 'Force to standby not indicated',
    1 : 'Force to standby indicated'
    }

# 24.008, 10.5.5.17, Update result
UpdateRes_dict = {
    0 : 'RA updated',
    1 : 'Combined RA/LA updated',
    4 : 'RA updated and ISR activated',
    5 : 'Combined RA/LA updated and ISR activated'
    }

# 24.008, 10.5.5.18, Update type
UpdateType_dict = {
    0 : 'RA updating',
    1 : 'Combined RA/LA updating',
    2 : 'Combined RA/LA updating with IMSI attach',
    3 : 'Periodic updating'
    }

# 24.008, 10.5.5.20, Service type
ServiceType_dict = {
    0 : 'Signalling',
    1 : 'Data',
    2 : 'Paging response',
    3 : 'MBMS multicast service reception',
    4 : 'MBMS broadcast service reception'
    }

# 24.008, 10.5.6.9, LLC SAPI
LLCSAPI_dict = {
    0 : 'LLC SAPI not assigned',
    }

# 24.008, 10.5.6.17, GPRS SM request type
RequestType_dict = {
    1 : 'Initial request',
    2 : 'Handover',
    3 : 'Unused. Interpreted as initial request',
    4 : 'Emergency',
    }

# 24.008, 10.5.7.8, Device properties
DevProp_dict = {
    0:'MS not configured for NAS signalling low priority',
    1:'MS configured for NAS signalling low priority'
    }

###
# TS 23.401, 12.10.0 specification
# EMM short IE (Information Element)
###

# 23.401, 9.9.3.5, CSFB response
CSFBResp_dict = {
    0 : 'CS fallback rejected by the UE',
    1 : 'CS fallback accepted by the UE'
    }

# 23.401, 9.9.3.7, Detach type (MS initiated / Net initiated)
MEDetType_dict = {
    0 : 'Combined EPS/IMSI detach',
    1 : 'EPS detach',
    2 : 'IMSI detach',
    3 : 'Combined EPS/IMSI detach',
    4 : 'Combined EPS/IMSI detach',
    5 : 'Combined EPS/IMSI detach',
    6 : 'reserved',
    7 : 'reserved',    
    8 : 'Combined EPS/IMSI detach; UE switch off',
    9 : 'EPS detach; UE switch off',
    10 : 'IMSI detach; UE switch off',
    11 : 'Combined EPS/IMSI detach; UE switch off',
    12 : 'Combined EPS/IMSI detach; UE switch off',
    13 : 'Combined EPS/IMSI detach; UE switch off',
    14 : 'reserved; UE switch off',
    15 : 'reserved; UE switch off'
    }
NetDetType_dict = {
    1 : 'Re-attach required',
    2 : 'Re-attach not required',
    3 : 'IMSI detach',
    4 : 'Re-attach not required',
    5 : 'Re-attach not required',
    6 : 'reserved',
    7 : 'reserved'
    }

# 23.401, 9.9.3.10, EPS attach response
EPSAttRes_dict = {
    1 : 'EPS only',
    2 : 'combined EPS / IMSI attach'
    }

# 23.401, 9.9.3.11, EPS attach type
EPSAttType_dict = {
    1 : 'EPS Attach',
    2 : 'combined EPS / IMSI attach',
    6 : 'EPS emergency attach',
    7 : 'reserved'
    }

# 23.401, 9.9.3.13, EPS tracking area result
EPSUpdRes_dict = {
    0 : 'TA updated',
    1 : 'Combined TA / LA updated',
    4 : 'TA updated and ISR activated',
    5 : 'Combined TA / LA updated and ISR activated'
    }

# 23.401, 9.9.3.14, EPS tracking area update type
EPSUpdType_dict = {
    0 : 'TA updated',
    1 : 'Combined TA / LA updating',
    2 : 'Combined TA / LA updating with IMSI attach',
    3 : 'periodic updating',
    4 : 'unused (TA updating)',
    5 : 'unused (TA updating)',
    8 : 'TA updated; bearer establishment requested',
    9 : 'Combined TA / LA updating; bearer establishment requested',
    10 : 'Combined TA / LA updating with IMSI attach; '\
         'bearer establishment requested',
    11 : 'periodic updating; bearer establishment requested',
    12 : 'unused (TA updating); bearer establishment requested',
    13 : 'unused (TA updating); bearer establishment requested'
    }

# 23.401, 9.9.3.25A, Paging identity
PagingID_dict = {
    0 : 'IMSI',
    1 : 'TMSI'
    }

# section 9.9.3.27, EPS service type
ServType_dict = {
    0 : 'Mobile originating CS fallback or 1xCS fallback',
    1 : 'Mobile terminating CS fallback or 1xCS fallback',
    2 : 'Mobile originating CS fallback emergency call or 1xCS fallback ' \
        'emergency call',
    3 : 'Unused; mobile originating CS fallback or 1xCS fallback',
    4 : 'Unused; mobile originating CS fallback or 1xCS fallback',
    8 : 'Packet services via S1',
    9 : 'Unused; packet services via S1',
    10 : 'Unused; packet services via S1',
    11 : 'Unused; packet services via S1'
    }

# 23.401, 9.9.3.42
GeneContType_dict = {
    0 : 'reserved',
    1 : 'LTE Positioning Protocol (LPP)',
    2 : 'Location Services (LCS)'
    }

# 23.401, 9.9.3.45, GUTI type
GUTIType_dict = {
    0 : 'Native GUTI',
    1 : 'Mapped GUTI'
    }

# 24.301, 9.9.4.5, ESM information transfer flag
ESMTransFlag_dict = {
    0 : 'Security protected ESM information transfer not required',
    1 : 'Security protected ESM information transfer required',
    }

# 23.401, 9.9.4.10, PDN type
PDNType_dict = {
    1 : 'IPv4',
    2 : 'IPv6',
    3 : 'IPv4v6',
    }

