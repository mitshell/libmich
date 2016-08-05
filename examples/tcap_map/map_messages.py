#!/usr/local/bin/python
# -*- coding: utf-8 -*-

# SS7 messages
# Created by Martin Kacer, H21 lab, 2016
# All the content and resources have been provided in the hope that it will be useful.
# Author do not take responsibility for any misapplication of it.


# To generate reference pcap with dummy Ethernet, IP, SCTP layer:
#  - just run the script

import os
import libmich
from libmich.asn1.processor import BER, ASN1, load_module, GLOBAL
from libmich.asn1.processor import *

# ****** GLOBALS *******
global_pcap_output = True                       # offline generate pcap file using text2pcap

# M3UA INAT0
m3ua_opc = '00000001'
m3ua_dpc = '00000002'
m3ua_si = '03'  # SCCP
m3ua_ni = '00'  # international network
m3ua_mp = '00'
m3ua_sls = '0b'

# SCCP
sccp_called_ai = '12'
sccp_called_gt =  '000000000000'
sccp_calling_ai = '12'
sccp_calling_gt = '111111111111'

# MAP
map_imsi = '\x11\x11\x11\x11\x11\x11\x11\xf1'
map_msisdn = '\x11\x11\x11\x11\x11\x11\xf1'
map_imei = '\x11\x11\x11\x11\x11\x11\x11\x11'
map_msrn = '\x11\x11\x11\x11\x11\x11\xf1'

# ***** FUNCTIONS ******
def to_pcap_file(filename, output_pcap_file):
    cmd = "cat " + filename + "| text2pcap -S 2905,2905,0 - " + output_pcap_file 
    os.system(cmd)

def hex_to_txt(hexstring, output_file):
    cmd = "echo \"" + hexstring + "\" | xxd -r -p  | od -Ax -tx1 >>" + output_file       
    os.system(cmd)
    
def encode_tcap_user_info(destinationReference, originationReference): 
    i = 0
    tcap_user_info = 'be$028$1060704000001010101a0$2a0$3$4$5$6$7'
    
    if originationReference != None and originationReference != '':
        tcap_user_info = tcap_user_info.replace('$7', originationReference)
        i += len(originationReference)/2
        tcap_user_info = tcap_user_info.replace('$6', '81' + format(len(originationReference)/2, '02x'))
        i += 2
    else:
        tcap_user_info = tcap_user_info.replace('$7', '')
        tcap_user_info = tcap_user_info.replace('$6', '')
    
    if destinationReference != None and destinationReference != '':
        tcap_user_info = tcap_user_info.replace('$5', destinationReference)
        i += len(destinationReference)/2
        tcap_user_info = tcap_user_info.replace('$4', '80' + format(len(destinationReference)/2, '02x'))
        i += 2
    else:
        tcap_user_info = tcap_user_info.replace('$5', '')
        tcap_user_info = tcap_user_info.replace('$4', '')
    
    tcap_user_info = tcap_user_info.replace('$3', format(i, '02x'))
    i += 2
    tcap_user_info = tcap_user_info.replace('$2', format(i, '02x'))
    i += 11
    tcap_user_info = tcap_user_info.replace('$1', format(i, '02x'))
    i += 2
    tcap_user_info = tcap_user_info.replace('$0', format(i, '02x'))
    
    return tcap_user_info

# ***** MAPv1 inline compilation ******

####### MAPv1 sendParameters
maxAddressLength = inline('''maxAddressLength  INTEGER ::= 20''')

AddressString = inline('''AddressString ::= OCTET STRING (SIZE (1..maxAddressLength))''')

maxISDN_AddressLength = inline('''maxISDN-AddressLength  INTEGER ::= 9''')

ISDN_AddressString = inline('''ISDN-AddressString ::= 
                        AddressString (SIZE (1..maxISDN-AddressLength))''')

TBCD_STRING = inline('''TBCD-STRING ::= OCTET STRING''')

IMSI = inline('''IMSI ::= [APPLICATION 2] IMPLICIT TBCD-STRING (SIZE (3..8))''')

SubscriberIdentity = inline('''SubscriberIdentity ::= CHOICE {
        imsi                    [0] IMPLICIT IMSI,
        msisdn          [1] IMPLICIT ISDN-AddressString
        }''')

RequestParameter = inline('''RequestParameter        ::= ENUMERATED {
        requestIMSI (0),
        requestAuthenticationSet (1),
        requestSubscriberData (2),
        requestKi (4)}''')

RequestParameterList = inline('''RequestParameterList    ::= SEQUENCE SIZE (1..2) OF
                                        RequestParameter''')

SendParametersArg = inline('''SendParametersArg       ::= SEQUENCE {
        subscriberId SubscriberIdentity,
        requestParameterList RequestParameterList}''')

#print GLOBAL.TYPE['SendParametersArg'].__dict__

####### MAPv1 processUnstructuredSS-Data
maxSignalInfoLength = inline('''maxSignalInfoLength  INTEGER ::= 200''')

SS_UserData = inline('''SS-UserData ::= IA5String (SIZE (1.. maxSignalInfoLength))''')

####### MAPv1 performHandover
GlobalCellId = inline('''GlobalCellId ::= OCTET STRING (SIZE (5..7))''')

ProtocolId = inline('''ProtocolId ::= ENUMERATED {
        gsm-0408 (1),
        gsm-0806 (2),
        gsm-BSSMAP (3),
        ets-300102-1 (4)}''')

maxSignalInfoLength = inline('''maxSignalInfoLength INTEGER ::= 200''')

SignalInfo = inline('''SignalInfo ::= OCTET STRING (SIZE (1..maxSignalInfoLength))''')

ExternalSignalInfo = inline('''ExternalSignalInfo ::= SEQUENCE {
        protocolId ProtocolId,
        signalInfo SignalInfo,
        ...}''')

PrepareHO_Arg = inline('''PrepareHO-Arg ::= SEQUENCE {
        targetCellId GlobalCellId OPTIONAL,
        ho-NumberNotRequired NULL OPTIONAL,
        bss-APDU ExternalSignalInfo OPTIONAL,
        ...}''')

###### MAPv1 performSubsequentHandover
PerformSubsequentHO_Arg = inline('''PerformSubsequentHO-Arg ::= SEQUENCE {
        targetCellId OCTET STRING (SIZE (5..7)),
        servingCellId OCTET STRING (SIZE (5..7)),
        targetMSC-Number OCTET STRING (SIZE (1..9)),
        classmarkInfo [10] IMPLICIT OCTET STRING (SIZE (1..2)) OPTIONAL}''')

###### MAPv1 provideSIWFSNumber
maxNumOfPrivateExtensions = inline('''maxNumOfPrivateExtensions INTEGER ::= 10''')

MAP_EXTENSION = inline('''MAP-EXTENSION  ::= CLASS {
        &ExtensionType                          OPTIONAL,
        &extensionId    OBJECT IDENTIFIER }''')

ExtensionSet = inline('''ExtensionSet            MAP-EXTENSION ::=
            {...
             -- ExtensionSet is the set of all defined private extensions
        }''')

PrivateExtension = inline('''PrivateExtension ::= SEQUENCE {
        extId           MAP-EXTENSION.&extensionId
                                ({ExtensionSet}),
        extType         MAP-EXTENSION.&ExtensionType
                                ({ExtensionSet}{@extId})        OPTIONAL}''')

PrivateExtensionList = inline('''PrivateExtensionList ::= SEQUENCE SIZE (1..maxNumOfPrivateExtensions) OF
                                PrivateExtension''')

PCS_Extensions = inline('''PCS-Extensions ::= SEQUENCE {
        ...}''')

ExtensionContainer = inline('''ExtensionContainer ::= SEQUENCE {
        privateExtensionList    [0]PrivateExtensionList OPTIONAL, 
        pcs-Extensions  [1]PCS-Extensions       OPTIONAL,
        ...}''')

CallDirection = inline('''CallDirection ::= OCTET STRING (SIZE (1))''')

ProvideSIWFSNumberArg = inline('''ProvideSIWFSNumberArg ::= SEQUENCE {
        gsm-BearerCapability    [0] ExternalSignalInfo,
        isdn-BearerCapability   [1] ExternalSignalInfo,
        call-Direction                  [2] CallDirection,
        b-Subscriber-Address    [3] ISDN-AddressString,
        chosenChannel                   [4] ExternalSignalInfo,
        lowerLayerCompatibility [5] ExternalSignalInfo OPTIONAL,
        highLayerCompatibility  [6] ExternalSignalInfo OPTIONAL,
        extensionContainer              [7] ExtensionContainer OPTIONAL,
        ...}''')

###### sIWFSSignallingModify
SIWFSSignallingModifyArg = inline('''SIWFSSignallingModifyArg ::= SEQUENCE {
        channelType                     [0] ExternalSignalInfo OPTIONAL,
        chosenChannel           [1] ExternalSignalInfo OPTIONAL,
        extensionContainer      [2] ExtensionContainer OPTIONAL,
        ...}''')

###### noteInternalHandover
NoteInternalHO_Arg = inline('''NoteInternalHO-Arg ::= SEQUENCE {
        handoverType ENUMERATED {
            interBSS        (0),
            intraBSS        (1)},
        targetCellId [1] IMPLICIT OCTET STRING (SIZE (5..7)) OPTIONAL,
        channelId [2] IMPLICIT SEQUENCE {
        protocolId ENUMERATED {
            gsm-0408        (1),
            gsm-0806        (2),
            gsm-BSSMAP      (3),
            ets-300102-1    (4)},
        signalInfo OCTET STRING (SIZE (1..200)),
        ... } OPTIONAL}''')

###### alertServiceCentreWithoutResult
AlertServiceCentreArg = inline('''AlertServiceCentreArg ::= SEQUENCE {
        msisdn        OCTET STRING (SIZE (1..9)),
        serviceCentreAddress OCTET STRING (SIZE (1..20)),
        ... }''')

###### traceSubscriberActivity
TraceReference = inline('''TraceReference ::= OCTET STRING (SIZE (1..2))''')

TraceType = inline('''TraceType ::= INTEGER (0..255)''')

CallReference = inline('''CallReference ::= OCTET STRING (SIZE (1..3))''')

TraceSubscriberActivityArg = inline('''TraceSubscriberActivityArg ::= SEQUENCE {
        imsi                [0] IMSI OPTIONAL,
        traceReference      [1] TraceReference,
        traceType           [2] TraceType,
        omc-Id              [3] AddressString OPTIONAL,
        callReference       [4] CallReference OPTIONAL}''')

###### beginSubscriberActivity
BeginSubscriberActivityArg = inline('''BeginSubscriberActivityArg ::= SEQUENCE {
        imsi            IMSI,
        originatingEntityNumber ISDN-AddressString,
        msisdn                  [PRIVATE 28] AddressString OPTIONAL,
        ... }''')

# ******* main ********
if (global_pcap_output):
    file = 'tmp.txt'
    f = open(file,'w')


load_module('MAP')
ASN1.ASN1Obj.CODEC = BER
BER._ENUM_BUILD_TYPE = True
#print GLOBAL.TYPE
#print GLOBAL.TYPE['SendRoutingInfoArg'].__dict__
#print "=================="

#pdu = GLOBAL.TYPE['SendAuthenticationInfoArg']
#buf = '3014800811111111111111f102010505008100830101'.decode('hex')
#pdu.decode(buf)

#pdu.set_val({'numberOfRequestedVectors': 5, 'imsi': '\x11\x11\x11\x11\x11\x11\x11\xf1', 'requestingNodeType': 'sgsn'})
#pdu.encode()
#print pdu.show()
#print str(pdu).encode('hex')

#pdu = GLOBAL.TYPE['AnyTimeInterrogationArg']
#print pdu.__dict__
#buf = '301da00a800811111111111111f1a1068000810083008307111111111111f1'.decode('hex')
#pdu.decode(buf)
#print pdu()


tcap_tid = 0
for tcap_oc in range(0, 255):
    
    # TCAP
    tcap_start = '62$04804$16b$928$a060700118605010101' + 'a0$b60$8' +              'a10906070400000100$5$6$7' + '6c$2a1$30201010201$4'
    tcap_padding_len = 0
    #tcap_start = '62$04804$16b$928$a060700118605010101' + 'a0$b60$8' + '80020780' + 'a10906070400000100$5$6$7' + '6c$2a1$30201010201$4'      
    #tcap_padding_len = 4
    
    # MAP defaults
    sccp_orig_ssn = 8
    sccp_dest_ssn = 8
    tcap_ac = 1
    tcap_map_ver = 2
    tcap_user_info = ''
    gsm = ''
       
    if (tcap_oc == 2):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 1
        pdu = GLOBAL.TYPE['UpdateLocationArg']
        pdu.set_val({'vlr-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'msc-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'vlr-Capability': {'supportedCamelPhases': (1, 1)}, 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 3):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 2
        pdu = GLOBAL.TYPE['CancelLocationArg']
        pdu.set_val({'cancellationType': 'updateProcedure', 'identity': ('imsi', map_imsi)})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 4):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 3
        pdu = GLOBAL.TYPE['ProvideRoamingNumberArg']
        pdu.set_val({'msisdn': map_msisdn, 'msc-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'gsm-BearerCapability': {'protocolId': 'gsm-0408', 'signalInfo': '\x04\x01\xa0'}, 'imsi': map_imsi, 'gmsc-Address': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 5):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 147
        tcap_ac = 22
        pdu = GLOBAL.TYPE['NoteSubscriberDataModifiedArg']
        pdu.set_val({'imsi': map_imsi, 'msisdn': map_msisdn})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 6):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 6
        pdu = GLOBAL.TYPE['ResumeCallHandlingArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 7):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 16
        pdu = GLOBAL.TYPE['InsertSubscriberDataArg']
        pdu.set_val({'vlrCamelSubscriptionInfo': {'o-CSI': {'camelCapabilityHandling': 2, 'o-BcsmCamelTDPDataList': [{'gsmSCF-Address': '\x11\x11\x11\x11\x11\x11\xf1', 'defaultCallHandling': 'continueCall', 'serviceKey': 2, 'o-BcsmTriggerDetectionPoint': 'collectedInfo'}]}}, 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 8):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 149
        tcap_ac = 16
        pdu = GLOBAL.TYPE['DeleteSubscriberDataArg']
        pdu.set_val({'imsi': map_imsi, 'gprsSubscriptionDataWithdraw': ('allGPRSData', None)})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 9):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 14
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['SendParametersArg']
        pdu.set_val({'subscriberId': ('imsi', map_imsi), 'requestParameterList': ['requestSubscriberData']})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 10):
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['RegisterSS-Arg']
        pdu.set_val({'ss-Code' : '\x00', 'forwardedToSubaddress' : '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 11): # eraseSS
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['SS-ForBS-Code']
        pdu.set_val({'ss-Code' : '\x21'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 12): # activateSS
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['SS-ForBS-Code']
        pdu.set_val({'ss-Code' : '\x21'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 13): # deactivateSS
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['SS-ForBS-Code']
        pdu.set_val({'ss-Code' : '\x21'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 14): # interrogateSS
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['SS-ForBS-Code']
        pdu.set_val({'ss-Code' : '\x21'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 15):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['AuthenticationFailureReportArg']
        pdu.set_val({'vlr-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'rand': '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'accessType': 'locationUpdating', 'failureCause': 'wrongUserResponse', 're-attempt': False, 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 17): # registerPassword
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        pdu = GLOBAL.TYPE['SS-Code']
        pdu.set_val('\x21')
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 18): # getPassword
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('96' + map_imsi.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 18
        pdu = GLOBAL.TYPE['GuidanceInfo']
        pdu.set_val('enterPW')
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 19): # processUnstructuredSS-Data
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['SS-UserData']
        pdu.set_val('*#123#')
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 20):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 44
        pdu = GLOBAL.TYPE['ReleaseResourcesArg']
        pdu.set_val({'msrn': map_msrn})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 21):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 41
        pdu = GLOBAL.TYPE['MT-ForwardSM-VGCS-Arg']
        pdu.set_val({'asciCallReference': '\x00\x00\x00\x00\x00\x00\x00\x00', 'sm-RP-OA': ('serviceCentreAddressOA', '\x11\x11\x11\x11\x11\x11\xf1'), 'sm-RP-UI': '@\x0b\x91\x11\x11\x11\x11\x11\xf1\x00\x08Q\x01\x02qr\x01\x80\x1a\x05\x00\x03\xa8\x02\x02\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 22):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 6
        tcap_ac = 5
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['SendRoutingInfoArg']
        pdu.set_val({'msisdn': map_msisdn, 'interrogationType': 'basicCall', 'gmsc-OrGsmSCF-Address': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 23):
        sccp_orig_ssn = 149
        sccp_dest_ssn = 6
        tcap_ac = 32
        pdu = GLOBAL.TYPE['UpdateGprsLocationArg']
        pdu.set_val({'sgsn-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'sgsn-Capability': {'homogeneousSupportOfIMSVoiceOverPSSessions': False, 'gprsEnhancementsSupportIndicator': None, 't-adsDataRetrieval': None}, 'sgsn-Address': '\x04\x00\x00\x00\x00', 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 24):
        sccp_orig_ssn = 149
        sccp_dest_ssn = 6
        tcap_ac = 33
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['SendRoutingInfoForGprsArg']
        pdu.set_val({'ggsn-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'ggsn-Address': '\x04\x00\x00\x00\x00', 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 25):
        sccp_orig_ssn = 150
        sccp_dest_ssn = 6
        tcap_ac = 34
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['FailureReportArg']
        pdu.set_val({'imsi': map_imsi, 'ggsn-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 26):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 150
        tcap_ac = 35
        pdu = GLOBAL.TYPE['NoteMsPresentForGprsArg']
        pdu.set_val({'imsi': map_imsi, 'sgsn-Address': '\x04\x00\x00\x00\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 28):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['PrepareHO-Arg']
        pdu.set_val({'targetCellId': '\x00\x00\x00\x00\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 29):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['SendEndSignal-Arg']
        pdu.set_val({'an-APDU': {'accessNetworkProtocolId': 'ts3G-48006', 'signalInfo': '\x00\x00\x00\x00\x00'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 30):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['PerformSubsequentHO-Arg']
        pdu.set_val({'targetCellId': '\x00\x00\x00\x00\x00', 'servingCellId': '\x00\x00\x00\x00\x00', 'targetMSC-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 31):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 148
        tcap_ac = 12
        pdu = GLOBAL.TYPE['PerformSubsequentHO-Arg']
        pdu.set_val({'targetCellId': '\x00\x00\x00\x00\x00', 'servingCellId': '\x00\x00\x00\x00\x00', 'targetMSC-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 32):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 148
        tcap_ac = 12
        pdu = GLOBAL.TYPE['SIWFSSignallingModifyArg']
        pdu.set_val({'channelType': {'protocolId': 'gsm-0806', 'signalInfo': '\x00\x00\x00\x00\x00'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 33):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['ProcessAccessSignalling-Arg']
        pdu.set_val({'an-APDU': {'accessNetworkProtocolId': 'ts3G-48006', 'signalInfo': '\x00\x00\x00\x00\x00'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 34):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['ForwardAccessSignalling-Arg']
        pdu.set_val({'an-APDU': {'accessNetworkProtocolId': 'ts3G-48006', 'signalInfo': '\x00\x00\x00\x00\x00'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 35):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['NoteInternalHO-Arg']
        pdu.set_val({'handoverType': 'intraBSS', 'targetCellId': '\x00\x00\x00\x00\x00', 'channelId': {'protocolId': 'gsm-BSSMAP', 'signalInfo': '\x00\x00\x00\x00\x00'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 36):
        sccp_orig_ssn = 248
        sccp_dest_ssn = 7
        tcap_ac = 47
        pdu = GLOBAL.TYPE['CancelVcsgLocationArg']
        pdu.set_val({'identity': ('imsi', map_imsi)})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 37):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 10
        pdu = GLOBAL.TYPE['ResetArg']
        pdu.set_val({'sendingNodenumber': ('hlr-Number', '\x11\x11\x11\x11\x11\x11\xf1'), 'hlr-List': ['\x11\x11\x11']})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 39):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 31
        pdu = GLOBAL.TYPE['PrepareGroupCallArg']
        pdu.set_val({'teleservice': '\x00', 'asciCallReference': '\x00', 'codec-Info': '\x00\x00\x00\x00\x00', 'cipheringAlgorithm': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 40):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 31
        pdu = GLOBAL.TYPE['SendGroupCallEndSignalArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 41):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 31
        pdu = GLOBAL.TYPE['ProcessGroupCallSignallingArg']
        pdu.set_val({})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 42):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 31
        pdu = GLOBAL.TYPE['ForwardGroupCallSignallingArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 43):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 9
        tcap_ac = 13
        pdu = GLOBAL.TYPE['CheckIMEI-Arg']
        pdu.set_val({'imei': map_imei, 'requestedEquipmentInfo': (255, 2)})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 44):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 25
        pdu = GLOBAL.TYPE['MT-ForwardSM-Arg']
        pdu.set_val({'sm-RP-OA': ('serviceCentreAddressOA', '\x11\x11\x11\x11\x11\x11\xf1'), 'sm-RP-DA': ('imsi', map_imsi), 'sm-RP-UI': '\x40\x0b\x91\x11\x11\x11\x11\x11\xf1\x00\x08Q\x01\x02qr\x01\x80\x1a\x05\x00\x03\xa8\x02\x02\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 45):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 6
        tcap_ac = 20
        pdu = GLOBAL.TYPE['RoutingInfoForSM-Arg']
        pdu.set_val({'msisdn': map_msisdn, 'sm-RP-PRI': False, 'serviceCentreAddress': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 46):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 21
        pdu = GLOBAL.TYPE['MO-ForwardSM-Arg']
        # TODO SMS layer encoding
        pdu.set_val({'sm-RP-DA': ('serviceCentreAddressDA', '\x11\x11\x11\x11\x11\x11\xf1'), 'sm-RP-OA': ('msisdn', map_msisdn), 'sm-RP-UI': '\x21\x2a\x0b\x91\x11\x11\x11\x11\x11\xf1\x00\x08\x1a\x05\x00\x03\xa8\x02\x02\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 47):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 6
        tcap_ac = 20
        pdu = GLOBAL.TYPE['ReportSM-DeliveryStatusArg']
        pdu.set_val({'msisdn': map_msisdn, 'sm-DeliveryOutcome': 'absentSubscriber', 'serviceCentreAddress': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 48): # noteSubscriberPresent
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 24
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['IMSI']
        pdu.set_val(map_imsi)
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 49): # alertServiceCentreWithoutResult
        sccp_orig_ssn = 6
        sccp_dest_ssn = 8
        tcap_ac = 23
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['AlertServiceCentreArg']
        pdu.set_val({'msisdn': map_msisdn, 'serviceCentreAddress': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 50):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 17
        pdu = GLOBAL.TYPE['ActivateTraceModeArg']
        pdu.set_val({'imsi': map_imsi, 'traceReference': '\x00', 'traceType': 0})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 51):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 17
        pdu = GLOBAL.TYPE['DeactivateTraceModeArg']
        pdu.set_val({'imsi': map_imsi, 'traceReference': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 52):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 8
        tcap_ac = 11
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['TraceSubscriberActivityArg']
        pdu.set_val({'imsi': map_imsi, 'traceReference': '\x00', 'traceType': 0})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    if (tcap_oc == 53):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 248
        tcap_ac = 46
        pdu = GLOBAL.TYPE['UpdateVcsgLocationArg']
        pdu.set_val({'vlr-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'sgsn-Number': '\x11\x11\x11\x11\x11\x11\xf1', 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    if (tcap_oc == 54):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 18
        tcap_map_ver = 1
        pdu = GLOBAL.TYPE['BeginSubscriberActivityArg']
        pdu.set_val({'imsi': map_imsi, 'originatingEntityNumber': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 55):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 7
        tcap_ac = 15
        pdu = GLOBAL.TYPE['SendIdentificationArg']
        pdu.set_val({'tmsi': '\x11\x11\x11\x11'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 56):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 14
        pdu = GLOBAL.TYPE['SendAuthenticationInfoArg']
        pdu.set_val({'numberOfRequestedVectors': 5, 'imsi': map_imsi, 'requestingNodeType': 'sgsn'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 57):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 1
        pdu = GLOBAL.TYPE['RestoreDataArg']
        pdu.set_val({'vlr-Capability': {'supportedCamelPhases': (1, 1)}, 'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 58): # sendIMSI
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 26
        pdu = GLOBAL.TYPE['ISDN-AddressString']
        pdu.set_val('\x11\x11\x11\x11\x11\x11\xf1')
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 59): # processUnstructuredSS-Request
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 19
        pdu = GLOBAL.TYPE['USSD-Arg']
        pdu.set_val({'ussd-DataCodingScheme': '\x0f', 'ussd-String': '\xaa\x51\x4c\x36\x1b\x01'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 60): # unstructuredSS-Request
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 19
        pdu = GLOBAL.TYPE['USSD-Arg']
        pdu.set_val({'ussd-DataCodingScheme': '\x0f', 'ussd-String': '\xaa\x51\x4c\x36\x1b\x01'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 61): # unstructuredSS-Request
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '')
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 19
        pdu = GLOBAL.TYPE['USSD-Arg']
        pdu.set_val({'ussd-DataCodingScheme': '\x0f', 'ussd-String': '\xaa\x51\x4c\x36\x1b\x01'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 62):
        sccp_orig_ssn = 147
        sccp_dest_ssn = 6
        tcap_ac = 43
        pdu = GLOBAL.TYPE['AnyTimeSubscriptionInterrogationArg']
        pdu.set_val({'subscriberIdentity': ('imsi', map_imsi), 'requestedSubscriptionInfo': {'msisdn-BS-List': None}, 'gsmSCF-Address': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 63):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 8
        tcap_ac = 20
        pdu = GLOBAL.TYPE['InformServiceCentreArg']
        pdu.set_val({'storedMSISDN': map_msisdn})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 64):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 8
        tcap_ac = 23
        pdu = GLOBAL.TYPE['AlertServiceCentreArg']
        pdu.set_val({'msisdn': map_msisdn, 'serviceCentreAddress': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 65):
        sccp_orig_ssn = 147
        sccp_dest_ssn = 6
        tcap_ac = 43
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['AnyTimeModificationArg']
        pdu.set_val({'subscriberIdentity': ('imsi', map_imsi), 'gsmSCF-Address': '\x11\x11\x11\x11\x11\x11\xf1', 'modificationRequestFor-ODB-data': {'odb-data': {'odb-GeneralData': (0x0000ff00, 32)}}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 66):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 24
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['ReadyForSM-Arg']
        pdu.set_val({'imsi': map_imsi, 'alertReason': 'ms-Present'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 67):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 4
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['PurgeMS-Arg']
        pdu.set_val({'imsi': map_imsi, 'vlr-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 68):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['PrepareHO-Arg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 69):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 11
        pdu = GLOBAL.TYPE['PrepareSubsequentHO-Arg']
        pdu.set_val({'targetMSC-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 70):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 28
        pdu = GLOBAL.TYPE['ProvideSubscriberInfoArg']
        pdu.set_val({'imsi': map_imsi, 'requestedInfo': {'locationInformation': None, 'currentLocation': None}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 71):
        sccp_orig_ssn = 147
        sccp_dest_ssn = 6
        tcap_ac = 29
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['AnyTimeInterrogationArg']
        pdu.set_val({'subscriberIdentity': ('imsi', map_imsi), 'requestedInfo': {'locationInformation': None, 'currentLocation': None}, 'gsmSCF-Address': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 72):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 147
        tcap_ac = 36
        pdu = GLOBAL.TYPE['SS-InvocationNotificationArg']
        pdu.set_val({'imsi': map_imsi, 'msisdn': map_msisdn, 'ss-Event': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 73):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 7
        pdu = GLOBAL.TYPE['SetReportingStateArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 74):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 7
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['StatusReportArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 75):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 7
        tcap_ac = 7
        pdu = GLOBAL.TYPE['RemoteUserFreeArg']
        pdu.set_val({'imsi': map_imsi, 'callInfo': {'protocolId': 'gsm-BSSMAP', 'signalInfo': '\x00\x00\x00\x00'}, 'ccbs-Feature': {}, 'translatedB-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 76):
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 8
        pdu = GLOBAL.TYPE['RegisterCC-EntryArg']
        pdu.set_val({'ss-Code': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 77):
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 7
        sccp_dest_ssn = 6
        tcap_ac = 8
        pdu = GLOBAL.TYPE['EraseCC-EntryArg']
        pdu.set_val({'ss-Code': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 83):
        sccp_orig_ssn = 145
        sccp_dest_ssn = 8
        tcap_ac = 38
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['ProvideSubscriberLocation-Arg']
        pdu.set_val({'locationType': {'locationEstimateType': 'currentOrLastKnownLocation'}, 'mlc-Number': '\x11\x11\x11\x11\x11\x11\xf1'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 84):
        # MAP Dialog
        tcap_user_info = encode_tcap_user_info('81' + map_msisdn.encode('hex'), '81' + map_msisdn.encode('hex'))
        sccp_orig_ssn = 8
        sccp_dest_ssn = 8
        tcap_ac = 45
        pdu = GLOBAL.TYPE['SendGroupCallInfoArg']
        pdu.set_val({'requestedInfo': 'imsiAndAdditionalInfoAndAdditionalSubscription', 'groupId': '\x00\x00\x00\x00', 'teleservice': '\x00'})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 85):
        sccp_orig_ssn = 145
        sccp_dest_ssn = 6
        tcap_ac = 37
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['RoutingInfoForLCS-Arg']
        pdu.set_val({'mlcNumber': '\x11\x11\x11\x11\x11\x11\xf1', 'targetMS': ('imsi', map_imsi)})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 86):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 145
        tcap_ac = 38
        pdu = GLOBAL.TYPE['SubscriberLocationReport-Arg']
        pdu.set_val({'imsi': map_imsi, 'lcs-Event': 'emergencyCallOrigination', 'lcs-ClientID': {'lcsClientType': 'emergencyServices'}, 'lcsLocationInfo': {'networkNode-Number': '\x11\x11\x11\x11\x11\x11\xf1'}})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 87):
        sccp_orig_ssn = 8
        sccp_dest_ssn = 6
        tcap_ac = 4
        tcap_map_ver = 3
        pdu = GLOBAL.TYPE['IST-AlertArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 88):
        sccp_orig_ssn = 6
        sccp_dest_ssn = 8
        tcap_ac = 9
        tcap_map_ver = 2
        pdu = GLOBAL.TYPE['IST-CommandArg']
        pdu.set_val({'imsi': map_imsi})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    elif (tcap_oc == 89):
        sccp_orig_ssn = 7
        sccp_dest_ssn = 147
        tcap_ac = 42
        pdu = GLOBAL.TYPE['NoteMM-EventArg']
        pdu.set_val({'serviceKey': 0, 'eventMet': '\x03', 'imsi': map_imsi, 'msisdn': map_msisdn})
        pdu.encode()
        gsm = str(pdu).encode('hex')
        #pdu.decode(gsm.decode('hex'))
    
    # TCAP
    tcap_start = tcap_start.replace('$8', format(11 + tcap_padding_len + len(tcap_user_info)/2, '02x'))
    tcap_start = tcap_start.replace('$b', format(13 + tcap_padding_len + len(tcap_user_info)/2, '02x'))
    tcap_start = tcap_start.replace('$9', format(24 + 2 + tcap_padding_len + len(tcap_user_info)/2, '02x'))
    tcap_start = tcap_start.replace('$a', format(24 + tcap_padding_len + len(tcap_user_info)/2, '02x'))
    
    tcap_start = tcap_start.replace('$1', format(tcap_tid, '08x'))
    tcap_start = tcap_start.replace('$4', format(tcap_oc, '02x'))
    tcap_start = tcap_start.replace('$5', format(tcap_ac, '02x'))
    tcap_start = tcap_start.replace('$6', format(tcap_map_ver, '02x'))
    tcap_start = tcap_start.replace('$7', tcap_user_info)

    tcap_len = 8;
    tcap_len += len(gsm)/2
    tcap_start = tcap_start.replace('$0', format(len(tcap_start + gsm)/2 - 2, '02x'))
    tcap_start = tcap_start.replace('$2', format(tcap_len, '02x'))
    tcap_start = tcap_start.replace('$3', format(tcap_len - 2, '02x'))

    # SCCP
    sccp_start = '0980030e190b$2$3001104$40b$5$6001104$7$1'
    sccp_start = sccp_start.replace('$1', format(len(tcap_start + gsm)/2, '02x'))
    sccp_start = sccp_start.replace('$2', sccp_called_ai)
    sccp_start = sccp_start.replace('$3', format(sccp_dest_ssn, '02x'))
    sccp_start = sccp_start.replace('$4', sccp_called_gt)
    sccp_start = sccp_start.replace('$5', sccp_calling_ai)
    sccp_start = sccp_start.replace('$6', format(sccp_orig_ssn, '02x'))
    sccp_start = sccp_start.replace('$7', sccp_calling_gt)
    #sccp_end = '52fcc4'
    
    # M3UA
    m3ua_start = '010001010000$10210$2$3$4$5$6$7$8'
    m3ua_start = m3ua_start.replace('$1', format(len(sccp_start + tcap_start + gsm)/2 + 20 + 10 + 4, '04x'))
    m3ua_start = m3ua_start.replace('$2', format(len(sccp_start + tcap_start + gsm)/2 + 12 + 4, '04x'))
    m3ua_start = m3ua_start.replace('$3', m3ua_opc)
    m3ua_start = m3ua_start.replace('$4', m3ua_dpc)
    m3ua_start = m3ua_start.replace('$5', m3ua_si)
    m3ua_start = m3ua_start.replace('$6', m3ua_ni)
    m3ua_start = m3ua_start.replace('$7', m3ua_mp)
    m3ua_start = m3ua_start.replace('$8', m3ua_sls)
    #m3ua_end = '00321a'   

    # ALL LAYERS
    packet = m3ua_start + sccp_start + tcap_start + gsm #+ sccp_end + m3ua_end
    
    if (global_pcap_output):
        hex_to_txt(packet, file)
        
    tcap_tid += 1
          
   
if (global_pcap_output):
    f.close()
    to_pcap_file('tmp.txt', 'map_messages.pcap')
