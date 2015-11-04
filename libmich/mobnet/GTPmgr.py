# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.3.0
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
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
# * File Name : mobnet/GTPmgr.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

'''
HOWTO:

1) in order to use this GTP tunnels handler, the following parameters need to be configured:

-> some internal parameters
ARPd.GGSN_ETH_IF = 'eth0', ethernet interface toward external networks (e.g. Internet)
APRd.GGSN_MAC_ADDR = '08:00:00:01:02:03', MAC address of the ethernet interface toward external networks
APRd.GGSN_IP_ADDR = '192.168.1.100', IP address set to the ethernet interface toward external networks
GTPUd.EXT_IF = 'eth0', same as ARPd.GGSN_ETH_IF
GTPUd.GGSN_MAC_ADDR = '08:00:00:01:02:03', same as ARPd.GGSN_MAC_ADDR

-> some external network parameters (toward e.g. Internet)
APRd.SUBNET_PREFIX = '192.168.1', subnet prefix of the LAN to which the ethernet interface to external network is connected
APRd.ROUTER_MAC_ADDR = 'f4:00:00:01:02:03', the LAN router (1st IP hop) MAC address
APRd.ROUTER_IP_ADDR = '192.168.1.1', the LAN router (1st IP hop) IP address

-> some internal network parameters (toward RNC / eNodeB)
GTPUd.INT_IP = '10.1.1.1', IP address exposed on the RAN side
GTPUd.INT_PORT = 2152, GTPU UDP port to be used by RAN equipments

-> some mobiles parameters
APRd.IP_POOL = ('192.168.1.201', '192.168.1.202'), the pool of IP addresses to be used by our set of mobiles
GTPUd.BLACKHOLING = True, False or 'ext', to filter out all the mobile trafic, no trafic at all, or IP packets to external network only
GTPUd.WL_ACTIVE = True or False, to allow specific IP packets to be forwarded to the external network, bypassing the BLACKHOLING directive
GTPUd.WL_PORTS = [('UDP', 53), ('UDP', 123)], to specify to list of IP protocol / port to allow in case WL_ACTIVE is True
GTPUd.DPI = True or False, to store packet statistics (protocol / port / DNS requests, see the class DPI) in GTPUd.stats 

2) To use the GTPUd, you need to be root or have the capability to start raw sockets:

-> launch the demon, and add_mobile() / rem_mobile() to add or remove GTPU tunnel endpoint.
>>> gsn = GTPUd()

-> to start forwarding IP packets between the external interface and the GTP tunnel
if you want to let the GTPUd manage the attribution of TEID_to_rnc (GTPUd.GTP_TEID_EXT = False)
>>> teid_to_rnc = gsn.add_mobile(mobile_IP='192.168.1.201', rnc_IP='10.2.1.1', TEID_from_rnc=0x1)
if you want to manage TEID_to_rnc by yourself and just mush its value to GTPUd (GTPUd.GTP_TEID_EXT = True)
>>> add_mobile(self, mobile_IP='192.168.1.201', rnc_IP='10.1.1.2', TEID_from_rnc=0x1, TEID_to_rnc=0x2)

-> to stop forwading IP packets
>>> gsn.rem_mobile(mobile_IP='192.168.1.201')

-> modules that act on GTPU packets can be added to the GTPUd instance, they must be put in the MOD attribute
An example module TCPSYNACK is provided, it answers to TCP SYN packets sent by the mobile
>>> gsn.MOD.append( TCPSYNACK )

3) That's all !
'''
# filtering exports
__all__ = ['GTPUd', 'ARPd', 'DPI', 'DNSRESP', 'TCPSYNACK']

import os
#import signal
from select import select
from random import randint, _urandom
#
if os.name != 'nt':
    from fcntl import ioctl
    from socket import socket, timeout, error, \
        ntohs, htons, inet_aton, inet_ntoa, \
        AF_PACKET, SOCK_RAW, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
else:
    print('[ERR] GTPmgr : you\'re not on *nix system. It\'s not going to work:\n' \
          'You need PF_PACKET socket')

from libmich.formats.GTP import *
from libmich.formats.IP import *
from libmich.core.element import Block
from .utils import *
#
# debug level
DBG = 1

# for getting all kind of ether packets
ETH_P_ALL = 3

#------------------------------------------------------------------------------#
# GTP-U handler works with Linux PF_PACKET RAW socket on the Internet side
# and with standard GTP-U 3GPP protocol on the RNC / eNB side
# RNC / eNB <=== IP/UDP/GTPU/IP_mobile ===> GTPU_handler
#                GTPU_handler <=== RawEthernet/IP_mobile ===> Internet
#
# This way, the complete IP interface of a mobile is exposed through 
# this Gi interface.
# It requires the GTPmgr to resolve ARP request on behalf of mobiles 
# that it handles: this is the role of ARPd
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# setting / unsetting ethernet IF in promiscuous mode                          #
#------------------------------------------------------------------------------#
# copied from scapy
# actually, it seems not to work as expected 
# -> launching wireshark in promiscuous mode on the IF will do the job otherwise

def set_promisc(sk):
    from fcntl import ioctl
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    SIOCGIFINDEX = 0x8933
    #
    iff = sk.getsockname()[0]
    ifreq = ioctl(sk, SIOCGIFINDEX, pack("16s16x", iff))
    ifind = int(unpack("I", ifreq[16:20])[0])
    sk.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
                  pack("IHH8s", ifind, PACKET_MR_PROMISC, 0, ""))

def unset_promisc(sk):
    from fcntl import ioctl
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_DROP_MEMBERSHIP = 2
    PACKET_MR_PROMISC = 1
    SOL_PACKET = 263
    SIOCGIFINDEX = 0x8933
    #
    iff = sk.getsockname()[0]
    ifreq = ioctl(sk, SIOCGIFINDEX, pack("16s16x", iff))
    ifind = int(unpack("I", ifreq[16:20])[0])
    sk.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, 
                  pack("IHH8s", ifind, PACKET_MR_PROMISC, 0, ""))

#------------------------------------------------------------------------------#
# ARPd                                                                         #
#------------------------------------------------------------------------------#
# It resolves MAC addresses for requested IP addresses
# and listens for incoming ARP requests to answer them with a given MAC address.
#
# when we handle mobiles' IP interfaces over the Gi GGSN interface:
#
# A] for outgoing packets:
# 1) for any IP outside of our network, e.g. 192.168.1.0/24:
# we will provide the ROUTER_MAC_ADDR directly at the GGSN level
# 2) for local IP address in our subnet:
# we will resolve the MAC address thanks to ARP request / response
#
# B] for incoming packets:
# we must answer the router's or local hosts' ARP requests
# before being able to receive IP packets to be transferred to the mobiles
#
# ARPd is going to:
# maintain the ARP_RESOLV_TABLE
# listen on the ethernet interface for:
# - incoming ARP requests, and answer it for IP from our IP_POOL
# - incoming ARP responses (due to the daemon sending ARP requests)
# - incoming IP packets (thx to promiscous mode) to update the ARP_RESOLV_TABLE
#   with new MAC addresses
# send ARP request when needed to be able then to forward IP packet from mobile
#
class ARPd(object):
    '''
    ARP resolver
    resolve Ethernet / IP address correspondence on behalf of connected UE
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # recv() buffer length
    BUFLEN = 2048
    # select() timeout and wait period
    SELECT_TO = 0.1
    SELECT_SLEEP = 0.05
    #
    # all Gi interface parameters
    # Our GGSN ethernet parameters (IF, MAC and IP addresses)
    # (and also the MAC address to be used for any mobiles through our GGSN)
    GGSN_ETH_IF = 'eth0'
    GGSN_MAC_ADDR = '08:00:00:01:02:03'
    GGSN_IP_ADDR = '192.168.1.100'
    #
    # the pool of IP address to be used by our mobiles
    IP_POOL = ('192.168.1.201', '192.168.1.202')
    #
    # network parameters:
    # subnet prefix 
    # WNG: we only handle IPv4 /24 subnet
    SUBNET_PREFIX = '192.168.1'
    # and 1st IP router (MAC and IP addresses)
    # this is to resolve directly any IP outside our subnet
    ROUTER_MAC_ADDR = 'f4:00:00:01:02:03'
    ROUTER_IP_ADDR = '192.168.1.1'
    
    def __init__(self):
        #
        self.GGSN_MAC_BUF = mac_aton(self.GGSN_MAC_ADDR)
        self.GGSN_IP_BUF = inet_aton(self.GGSN_IP_ADDR)
        self.SUBNET_PREFIX = self.SUBNET_PREFIX.split('.')[:3]
        self.ROUTER_MAC_BUF = mac_aton(self.ROUTER_MAC_ADDR)
        self.ROUTER_IP_BUF = inet_aton(self.ROUTER_IP_ADDR)
        #
        # init RAW ethernet socket for ARP
        self.sk_arp = socket(AF_PACKET, SOCK_RAW, ntohs(0x0806))
        self.sk_arp.settimeout(0.1)
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_arp.bind((self.GGSN_ETH_IF, 0x0806))
        #self.sk_arp.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # init RAW ethernet socket for IPv4
        self.sk_ip = socket(AF_PACKET, SOCK_RAW, ntohs(0x0800))
        self.sk_ip.settimeout(0.1)
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 0)
        self.sk_ip.bind((self.GGSN_ETH_IF, 0x0800))
        #self.sk_ip.setsockopt(SOL_PACKET, SO_RCVBUF, 2**24)
        #
        # ARP resolution table
        self.ARP_RESOLV_TABLE = {
            self.ROUTER_IP_ADDR : self.ROUTER_MAC_BUF,
            self.GGSN_IP_ADDR : self.GGSN_MAC_BUF,
            }
        for ip in self.IP_POOL:
            self.ARP_RESOLV_TABLE[ip] = self.GGSN_MAC_BUF
        #
        # interrupt handler
        #def sigint_handler(signum, frame):
        #    if self.DEBUG > 1:
        #        self._log('INF', 'CTRL+C caught')
        #    self.stop()
        #signal.signal(signal.SIGINT, sigint_handler)
        #
        # starting main listening loop in background
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('INF', 'ARP resolver started')
        #
        # .resolve(ip) method is available for ARP resolution by GTPUd
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[{0}] [ARPd] {1}'.format(logtype, msg))
    
    def stop(self):
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                self.sk_arp.close()
                self.sk_ip.close()
            except Exception as err:
                self._log('ERR', 'socket error: {0}'.format(err))
    
    def listen(self):
        # select() until we receive arp or ip packet
        while self._listening:
            r = []
            r = select([self.sk_arp, self.sk_ip], [], [], self.SELECT_TO)[0]
            for sk in r:
                buf = bytes()
                try:
                    buf = sk.recvfrom(self.BUFLEN)[0]
                except Exception as err:
                    self._log('ERR', 'external network error (recvfrom): {0}'\
                              .format(err))
                # dipatch ARP request / IP response
                if sk is self.sk_arp \
                and len(buf) >= 42 and buf[12:14] == '\x08\x06':
                    self._process_arpbuf(buf)
                elif sk is self.sk_ip \
                and len(buf) >= 34 and buf[12:14] == '\x08\x00':
                    self._process_ipbuf(buf)
            # if select() timeouts, take a little rest
            if len(r) == 0:
                sleep(self.SELECT_SLEEP)
        #
        self._log('INF', 'ARP resolver stopped')
    
    def _process_arpbuf(self, buf=bytes()):
        # this is an ARP request or response:
        arpop = ord(buf[21:22])
        # 1) check if it requests for one of our IP
        if arpop == 1:
            ipreq = inet_ntoa(buf[38:42])
            if ipreq in self.IP_POOL:
                # reply to it with our MAC ADDR
                try:
                    self.sk_arp.sendto(
                     '{0}{1}\x08\x06\0\x01\x08\0\x06\x04\0\x02{2}{3}{4}{5}'\
                     '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'.format(
                      buf[6:12], self.GGSN_MAC_BUF, # Ethernet hdr
                      self.GGSN_MAC_BUF, buf[38:42], # ARP sender
                      buf[6:12], buf[28:32]), # ARP target 
                     (self.GGSN_ETH_IF, 0x0806))
                except Exception as err:
                    self._log('ERR', 'external network error (sendto) on ARP '\
                              'response: {0}'.format(err))
                else:
                    self._log('DBG', 'ARP response sent for IP: {0}'.format(
                              ipreq))
        # 2) check if it responses something useful for us
        elif arpop == 2:
            ipres = inet_ntoa(buf[28:32])
            if ipres.split('.')[:3] == self.SUBNET_PREFIX \
            and ipres not in self.ARP_RESOLV_TABLE:
                # WNG: no protection (at all) against ARP cache poisoning
                self.ARP_RESOLV_TABLE[ipres] = buf[22:28]
                self._log('DBG', 'got ARP response for new local IP: {0}'\
                          .format(ipres))
    
    def _process_ipbuf(self, buf=bytes()):
        # this is an IPv4 packet : check if src IP is in our subnet
        ipsrc = inet_ntoa(buf[26:30])
        #
        # if local IP and not alreay resolved, store the Ethernet MAC address
        if ipsrc.split('.')[:3] == self.SUBNET_PREFIX \
        and ipsrc not in self.ARP_RESOLV_TABLE:
            # WNG: no protection (at all) against ARP cache poisoning
            self.ARP_RESOLV_TABLE[ipsrc] = buf[6:12]
            self._log('DBG', 'got MAC address from IPv4 packet for new local '\
                      'IP {0}'.format(ipsrc))
    
    def resolve(self, ip='192.168.1.2'):
        #
        # check if already resolved
        if ip in self.ARP_RESOLV_TABLE:
            return self.ARP_RESOLV_TABLE[ip]
        #
        # else, need to request it live on the Ethernet link
        # response will be handled by .listen()
        elif ip.split('.')[:3]  == self.SUBNET_PREFIX:
            ip_buf = inet_aton
            try:
                self.sk_arp.sendto(
                 '{0}{1}\x08\x06\0\x01\x08\0\x06\x04\0\x01{2}{3}\0\0\0\0\0\0{4}'\
                 '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'.format(
                   self.ROUTER_MAC_BUF, self.GGSN_MAC_BUF, # Ethernet hdr
                   self.GGSN_MAC_BUF, self.GGSN_IP_BUF, # ARP sender
                   inet_aton(ip)), # ARP target
                 (self.GGSN_ETH_IF, 0x0806))
            except Exception as err:
                self._log('ERR', 'external network error (sendto) on ARP '\
                          'request: {0}'.format(err))
            else:
                self._log('DBG', 'ARP request sent for IP {0}'.format(ip))
            cnt = 0
            while ip not in self.ARP_RESOLV_TABLE:
                sleep(self.SELECT_SLEEP)
                cnt += 1
                if cnt >= 3:
                    break
            if cnt < 3:
                return self.ARP_RESOLV_TABLE[ip]
            else:
                return 6*'\xFF' # LAN broadcast, maybe a bit strong !
        else:
            return self.ROUTER_MAC_BUF


#------------------------------------------------------------------------------#
# GTPUd                                                                        #
#------------------------------------------------------------------------------#
# This is to be instanciated as a unique handler for all GTPU tunnels
# in the core network.
# Then, it is possible to add or remove GTP tunnel endpoints at will, 
# for each mobile:
# add_mobile(mobile_ip, rnc_ip, teid_from_rnc)
#   -> returns teid_to_rnc for the given mobile
# rem_mobile(mobile_ip)
#   -> returns None 
#
# When a GTP-U packet arrives on the internal interface,
# it is transferred to the external Gi interface.
# When an Ethernet packet arrives in the external Gi interface,
# it is transferred to the internal interface.
#
# A little traffic statistics feature can be used
# DPI = True
# Traffic statistics are then placed into the attribute .stats
# It is populated even if GTP trafic is not forwarded (see BLACKHOLING...)
#
# A blackholing feature is integrated to possibly isolate mobiles 
# from the whole network
# BLACKHOLING = True
# or from any external network routed from the Gi ethernet interface
# BLACKHOLING = 'ext'
# disabling the feature
# BLACKHOLING = False
#
# A whitelist feature (TCP/UDP, port) is also integrated, when activated
# WL_ACTIVE = True
# only packets for the given protocol / port are transferred to the Gi
# WL_PORTS = [('UDP', 53), ('UDP', 123), ('TCP', 80), ...]
# This is bypassing the blackholing feature.
#

class GTPUd(object):
    '''
    GTPU forwarder
    bridge Ethernet to GTPU to handle IP data traffic of connected UE
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # packet buffer space (over MTU...)
    BUFLEN = 2048
    # select loop settings
    SELECT_TO = 0.2
    #
    # Gi interface, with GGSN ethernet IF and mobile IP address
    EXT_IF = ARPd.GGSN_ETH_IF
    GGSN_MAC_ADDR = ARPd.GGSN_MAC_ADDR
    # IPv4 protocol only, to be forwarded
    EXT_PROT = 0x0800
    #
    # internal IF interface, for handling GTP-U packets from RNC
    INT_IP = '10.1.1.1'
    INT_PORT = 2152
    #
    # GTP TEID toward RNC / eNodeBs
    GTP_TEID = 0
    GTP_TEID_MAX = 2**32 - 1
    # in case the GTP TEID is assigned by an external entity
    GTP_TEID_EXT = True
    #
    # in case we dont want mobile traffic to reach the external IF
    # False: all the GTP traffic is relayed to the external IF
    # True: no GTP traffic is relayed at all
    # 'ext': only GTP traffic toward dest IP through the ROUTER_MAC_ADDR
    #        is blocked
    BLACKHOLING = 'ext'
    # traffic that we want to allow, even if BLACKHOLING is activated
    WL_ACTIVE = False
    #WL_ACTIVE = True
    WL_PORTS = [('UDP', 53), ('UDP', 123)]
    #
    # in case we want to generate traffic statistics (available in .stats)
    DPI = True
    
    def __init__(self):
        #
        self.GGSN_MAC_BUF = mac_aton(self.GGSN_MAC_ADDR)
        #
        # these are 2 dict for handling mobile GTPU packets' transfers :
        # take mobile IPv4 addr as key, and references (TEID, RNC_IP) 
        self._mobiles_ip = {}
        # take mobile TEID as key, and references mobile_IP
        self._mobiles_teid = {}
        # global TEID to RNC value, to be incremented from here
        if not self.GTP_TEID_EXT:
            self.GTP_TEID = randint(0, 20000)
        #
        # create a single GTP format decoder for input from RNC
        self._GTP_in = GTPv1()
        # and for output to RNC (un-automatize GTP length calculation)
        self._GTP_out = GTPv1()
        self._GTP_out.msg.Pt = 0xff
        self._GTP_out.len.PtFunc = None
        #
        # initialize the traffic statistics
        self.init_stats()
        self.__prot_dict = {1:'ICMP', 6:'TCP', 17:'UDP'}
        # initialize the list of modules that can act on GTP-U payloads
        self.MOD = []
        #
        # create a RAW PF_PACKET socket on the `Internet` side
        # python is not convinient to configure dest mac addr 
        # when using SOCK_DGRAM (or I missed something...), 
        # so we use SOCK_RAW and build our own ethernet header:
        self.ext_sk = socket(AF_PACKET, SOCK_RAW, ntohs(self.EXT_PROT))
        # configure timeouting and interface binding
        self.ext_sk.settimeout(0.1)
        self.ext_sk.bind((self.EXT_IF, self.EXT_PROT))
        # put the interface in promiscuous mode
        set_promisc(self.ext_sk)
        #
        # create an UDP socket on the RNC / eNobeB side, on port 2152
        self.int_sk = socket(AF_INET, SOCK_DGRAM)
        # configure timeout, binding and rebinding on same address
        self.int_sk.settimeout(0.1)
        self.int_sk.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.int_sk.bind((self.INT_IP, self.INT_PORT))
        #
        # interrupt handler
        #def sigint_handler(signum, frame):
        #    if self.DEBUG > 1:
        #        self._log('INF', 'CTRL+C caught')
        #    self.stop()
        #signal.signal(signal.SIGINT, sigint_handler)
        #
        # and start listening and transferring packets in background
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('INF', 'GTPU handler started')
        #
        # and finally start ARP resolver
        self.arpd = ARPd()
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[{0}] [GTPUd] {1}'.format(logtype, msg))
    
    def init_stats(self):
        self.stats = {
            'DNS':[], # for referencing IP of DNS servers requested
            'NTP':[], # for referencing IP of NTP servers requested
            'resolved':[], # for referencing domain name resolved
            'ICMP':[], # for referencing ICMP endpoint (IP) contacted
            'TCP':[], # for referencing TCP endpoint (IP, port) contacted
            'UDP':[], # for referencing UDP endpoint (IP, port) contacted
            'alien':[], # for referencing other protocol endpoint contacted
            }
    
    def stop(self):
        # stop ARP resolver
        self.arpd.stop()
        # stop local GTPU handler
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            try:
                # unset promiscuous mode
                unset_promisc(self.ext_sk)
                # closing sockets
                self.int_sk.close()
                self.ext_sk.close()
            except Exception as err:
                self._log('ERR', 'socket error: {0}'.format(err))
    
    def listen(self):
        # select() until we receive something on 1 side
        while self._listening:
            r = []
            r = select([self.int_sk, self.ext_sk], [], [], self.SELECT_TO)[0]
            for sk in r:
                buf = bytes()
                if sk is self.int_sk:
                    try:
                        buf = sk.recv(self.BUFLEN)
                    except Exception as err:
                        self._log('ERR', 'internal network IF error (recv)'\
                                  ': {0}'.format(err))
                    if buf:
                        self.transfer_to_ext(buf)  
                elif sk is self.ext_sk:
                    # WNG: seems some pseudo-RNC IP stack crashes when we send
                    # fragmented IP packets on Iu side...
                    try:
                        buf = sk.recvfrom(self.BUFLEN-128)[0]
                    except Exception as err:
                        self._log('ERR', 'external network IF error (recvfrom)'\
                                  ': {0}'.format(err))
                    else:
                        if len(buf) >= 34 and buf[12:14] == '\x08\0' \
                        and buf[:6] == self.GGSN_MAC_BUF:
                            # transferring over GTPU after removing Ethernet hdr
                            self.transfer_to_int(buf[14:])
        #
        self._log('INF', 'GTPU handler stopped')
    
    def transfer_to_ext(self, buf='\0'):
        # if GTP-U TEID in self._mobiles_teid, just forward...
        # in this direction, there is no reason to filter
        # except to avoid IP spoofing from malicious mobile 
        # (damned ! Would it be possible ?!?)
        #
        self._GTP_in.map(buf)
        # in case GTP TEID is not correct, drop it 
        if self._GTP_in.teid() not in self._mobiles_teid:
            return
        # in case GTP does not contain UP data, drop it
        if self._GTP_in.msg() != 0xff:
            self._log('WNG', 'GTP msg type unsupported: {0}'.format(
                      repr(self._GTP_in.msg)))
            return
        #
        # get the IP packet: use the length in GTPv1 header to cut the buffer
        buflen = self._GTP_in.len()
        if self._GTP_in.ext() or self._GTP_in.seq() or self._GTP_in.pn():
            buflen -= 4
        ipbuf = buf[-buflen:]
        #
        # drop dummy packets
        if len(ipbuf) < 24:
            self._log('WNG', 'dummy packet from mobile dropped: {0}'.format(
                      hexlify(ipbuf)))
            return
        ipdst = inet_ntoa(ipbuf[16:20])
        #
        # analyze the packet content for statistics
        if self.DPI:
            self._analyze(ipbuf)
        #
        # possibly process the UL GTP-U payload within modules
        try:
            if self.MOD:
                for mod in self.MOD:
                    if mod.TYPE == 0:
                        ipbuf = mod.handle_ul(ipbuf)
                    else:
                        mod.handle_ul(ipbuf)
        except Exception as err:
            self._log('ERR', 'MOD error: {0}'.format(err))
        #
        # resolve the dest MAC addr
        macdst = self.arpd.resolve(ipdst)
        #
        # possibly bypass blackholing rule for allowed ports
        # check if PROT / PORT is allowed in the whilelist
        if self.WL_ACTIVE:
            dst, prot, pay = DPI.get_ip_dst_pay(ipbuf)
            # TCP:6, UDP:17
            if prot in (6, 17) and pay:
                port = DPI.get_port(pay)
                if (self.__prot_dict[prot], port) in self.WL_PORTS:
                    self._transfer_to_ext(macdst, ipbuf)
                    return
        #
        # blackhole the packet if you want (full blackholing)
        if self.BLACKHOLING is True:
            return
        #
        # blackhole the packet (blackholing only external routed traffic)
        if self.BLACKHOLING == 'ext' and macdst == self.arpd.ROUTER_MAC_BUF:
            return
        #
        self._transfer_to_ext(macdst, ipbuf)
    
    def _transfer_to_ext(self, macdst=bytes(), ipbuf='\0'):
        # forward to the external PF_PACKET socket, over the Gi interface
        try:
            self.ext_sk.sendto('{0}{1}\x08\0{2}'.format(
                                macdst, self.GGSN_MAC_BUF, ipbuf),
                               (self.EXT_IF, self.EXT_PROT))
        except Exception as err:
            self._log('ERR', 'external network IF error (sendto): {0}'\
                      .format(err))
        else:
            self._log('DBG', 'buffer transferred from GTPU to RAW')
    
    def transfer_to_int(self, buf='\0'):
        # possibly process the DL GTP-U payload within modules
        try:
            if self.MOD:
                for mod in self.MOD:
                    if mod.TYPE == 0:
                        buf = mod.handle_dl(buf)
                    else:
                        mod.handle_dl(buf)
        except Exception as err:
            self._log('ERR', 'MOD error: {0}'.format(err))
        #
        # prepend GTP-U header and forward on internal sk
        if len(buf) >= 20:
            # check dest IP
            ipdst = buf[16:20]
            if ipdst in self._mobiles_ip:
                # get the TEID to the RNC
                self._GTP_out.teid > self._mobiles_ip[ipdst][1]
                # GTP header type for GTPU packet: G-PDU
                self._GTP_out.msg > 0xFF
                self._GTP_out.len > len(buf)
                self._transfer_to_int(ipdst, str(self._GTP_out)+buf)
    
    def _transfer_to_int(self, ipdst=bytes(), gtpbuf=bytes()):
        try:
            ret = self.int_sk.sendto(gtpbuf,
                                    (self._mobiles_ip[ipdst][0], self.INT_PORT))
        except Exception as err:
            self._log('ERR', 'internal network IF error (sendto): {0}'\
                      .format(err))
        else:
            self._log('DBG', '{0} bytes transferred from RAW to GTPU'.format(
                      ret))
    
    ###
    # Now we can add and remove (mobile_IP, TEID_from/to_RNC),
    # to configure filters and really start forwading packets over GTP
    def add_mobile(self, mobile_IP='192.168.1.201', rnc_IP='10.1.1.1',
                         TEID_from_rnc=0x1, TEID_to_rnc=0x1):
        try:
            ip = inet_aton(mobile_IP)
        except Exception as err:
            self._log('ERR', 'mobile_IP ({0}) has not the correct format: '\
                      'cannot configure the GTPU handler'.format(mobile_IP))
            return
        if not self.GTP_TEID_EXT:
            TEID_to_rnc = self.get_teid_to_rnc()
        self._mobiles_ip[ip] = (rnc_IP, TEID_to_rnc)
        self._mobiles_teid[TEID_from_rnc] = ip
        self._log('INF', 'setting GTP tunnel for mobile with IP {0}'.format(
                  mobile_IP))
        return TEID_to_rnc
    
    def rem_mobile(self, mobile_IP='192.168.1.201'):
        try:
            ip = inet_aton(mobile_IP)
        except Exception as err:
            self._log('ERR', 'mobile_IP ({0}) has not the correct format: ' \
                      'cannot configure the GTPU handler'.format(mobile_IP))
            return
        if ip in self._mobiles_ip:
            self._log('INF', 'unsetting GTP tunnel for mobile with IP '\
                      '{0}'.format(mobile_IP))
            del self._mobiles_ip[ip]
        if ip in self._mobiles_teid.values():
            for teid in self._mobiles_teid.keys():
                if self._mobiles_teid[teid] == ip:
                    del self._mobiles_teid[teid]
                    return
    
    def get_teid_to_rnc(self):
        if self.GTP_TEID >= self.GTP_TEID_MAX:
            self.GTP_TEID = randint(0, 20000)
        self.GTP_TEID += 1
        return self.GTP_TEID
    
    def _analyze(self, ipbuf):
        #
        dst, prot, pay = DPI.get_ip_dst_pay(ipbuf)
        # UDP
        if prot == 17 and pay:
            port = DPI.get_port(pay)
            if (dst, port) not in self.stats['UDP']:
                self.stats['UDP'].append((dst, port))
            # DNS
            if port == 53:
                if dst not in self.stats['DNS']:
                    self.stats['DNS'].append(dst)
                name = DPI.get_dn_req(pay[8:])
                if name not in self.stats['resolved']:
                    self.stats['resolved'].append(name)
            elif port == 123 and dst not in self.stats['NTP']:
                self.stats['NTP'].append(dst)
        # TCP
        elif prot == 6 and pay:
            port = DPI.get_port(pay)
            if (dst, port) not in self.stats['TCP']:
                self.stats['TCP'].append((dst, port))
        # ICMP
        elif prot == 1 and pay and dst not in self.stats['ICMP']:
            self.stats['ICMP'].append(dst)
        # alien
        else:
            self.stats['alien'].append(hexlify(ipbuf))
        
class DPI:
    
    @staticmethod
    def get_ip_dst_pay(ipbuf):
        # returns a 3-tuple: dst IP, protocol, payload buffer
        # get IP header length
        l = (ord(ipbuf[0]) & 0x0F) * 4
        # get dst IP
        dst = inet_ntoa(ipbuf[16:20])
        # get protocol
        prot = ord(ipbuf[9:10])
        #
        return (dst, prot, ipbuf[l:])
    
    @staticmethod
    def get_port(pay):
        return unpack('!H', pay[2:4])[0]
    
    @staticmethod
    def get_dn_req(req):
        # remove fixed DNS header and Type / Class
        s = req[12:-4]
        n = []
        while len(s) > 1:
            l = ord(s[0])
            n.append( s[1:1+l] )
            s = s[1+l:]
        return '.'.join(n)


class MOD(object):
    # This is a skeleton for GTP-U payloads specific handler.
    # After It gets loaded by the GTPUd instance, it acts on each GTP-U payloads (UL and DL)
    #
    # In can work actively on GTP-U packets (possibly changing them) with TYPE = 0
    # or passively (not able to change them), only getting copy of them, with TYPE = 1
    TYPE = 0
    
    # reference to the GTPUd instance
    GTPUd = None
    
    @classmethod
    def handle_ul(self, ippuf):
        pass
    
    @classmethod
    def handle_dl(self, ipbuf):
        pass

class DNSRESP(MOD):
    # this module answers to any DNS request incoming from UE (UL direction) with a single or random IP address
    # to be used with GTPUd.BLACKHOLING capability to avoid UE getting DNS responses from real servers
    TYPE = 1
    
    # put UDP checksum in DNS response
    UDP_CS = True
    # in case we want to answer random addresses
    RAND = False
    # the IPv4 address to answer all requests
    IP_RESP = '192.168.1.50'
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have an UDP/53 request
        ip_proto, (udpsrc, udpdst) = ord(ipbuf[9]), unpack('!HH', ipbuf[20:24])
        if ip_proto != 17:
            # not UDP
            return
        if udpdst != 53:
            # not DNS
            return
        
        # build the UDP / DNS response: invert src / dst UDP ports
        udp = UDP(src=udpdst, dst=udpsrc, with_cs=self.UDP_CS)
        # DNS request: transaction id, flags, questions, queries
        dnsreq = ipbuf[28:]
        transac_id, questions, queries = dnsreq[0:2], unpack('!H', dnsreq[4:6])[0], dnsreq[12:]
        if questions > 1:
            # not supported
            return
        # DNS response: transaction id, flags, questions, answer RRs, author RRs, add RRs,
        # queries, answers, autor nameservers, add records
        if self.RAND:
            ip_resp = _urandom(4)
        else:
            ip_resp = inet_aton(self.IP_RESP)
        dnsresp = '{0}\x81\x80\0\x01\0\x01\0\0\0\0{1}\xc0\x0c\0\x01\0\x01\0\0\0\x20\0\x04{2}'\
                  .format(transac_id, queries, ip_resp)
        
        # build the IPv4 header: invert src / dst addr
        ipsrc, ipdst = map(inet_ntoa, (ipbuf[12:16], ipbuf[16:20]))
        iphdr = IPv4(src=ipdst, dst=ipsrc)
        
        p = Block()
        p.append(iphdr)
        p.append(udp)
        p[-1].hierarchy = 1
        p.append(dnsresp)
        p[-1].hierarchy = 2
        
        # send back the DNS response
        self.GTPUd.transfer_to_int(bytes(p))

class TCPSYNACK(MOD):
    # this module answers to TCP SYN request incoming from UE (UL direction)
    # to be used with GTPUd.BLACKHOLING capability to avoid UE getting SYN-ACK from real servers
    TYPE = 1
    
    @classmethod
    def handle_ul(self, ipbuf):
        # check if we have a TCP SYN
        ip_proto, ip_pay = ord(ipbuf[9]), ipbuf[20:]
        if ip_proto != 6:
            # not TCP
            return
        if ip_pay[13] != '\x02':
            # not TCP SYN
            return
        
        # build the TCP SYN-ACK: invert src / dst ports, seq num (random), ack num (SYN seq num + 1)
        tcpsrc, tcpdst, seq = unpack('!HHI', ip_pay[:8])
        tcp_synack = TCP(src=tcpdst, dst=tcpsrc, flags=['SYN', 'ACK'])
        tcp_synack[2] = randint(1, 4294967295) # seq num
        tcp_synack[3] = (seq + 1) % 4294967296 # ack num
        tcp_synack[15] = 0x1000 # window
        
        # build the IPv4 header: invert src / dst addr
        ipsrc, ipdst = map(inet_ntoa, (ipbuf[12:16], ipbuf[16:20]))
        iphdr = IPv4(src=ipdst, dst=ipsrc)
        
        p = Block()
        p.append(iphdr)
        p.append(tcp_synack)
        p[1].hierarchy = 1 # TCP, payload of IP
        
        # send back the TCP SYN-ACK
        self.GTPUd.transfer_to_int(bytes(p))
