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
#!/usr/bin/env python

'''
HOWTO:

1) in order to use this GTP tunnels handler, the following parameters need to be configured:

-> some internal parameters
ARPd.GGSN_ETH_IF = 'eth0' : ethernet interface toward external networks (e.g. Internet)
APRd.GGSN_MAC_ADDR = '\x08\x00\x00\x01\x02\x03' : the MAC address of our ethernet interface
APRd.GGSN_IP_ADDR = '192.168.1.100' : our own IP address set for the ethernet interface
GTPUd.EXT_IF = 'eth0' : same as ARPd.GGSN_ETH_IF
GTPUd.GGSN_MAC_ADDR = '\x08\x00\x00\x01\x02\x03' : same as ARPd.GGSN_MAC_ADDR

-> some mobiles parameters
APRd.IP_POOL = ('192.168.1.201', '192.168.1.202') : the pool of IP addresses to be used by our mobiles

-> some external network parameters (toward e.g. Internet)
APRd.SUBNET_PREFIX = '192.168.1.' : the subnet prefix for the external network (we only handle /24 subnet at this time)
APRd.ROUTER_MAC_ADDR = '\xf4\x\x00\x00\x01\02\03' : the 1st IP hop MAC address
APRd.ROUTER_IP_ADDR = '192.168.1.1' : the 1st IP hop IP address

-> some internal network parameters (toward RNC / eNodeB)
GTPUd.INT_IP = '10.1.1.1' : our own IP address on the RAN side
GTPUd.INT_PORT = 2152 : our GTPU UDP port on the RAN side

There are also few others parameters configurable for GTPUd. Please read the code.

2) To use the GTPUd, you need to be root (due to the use of raw sockets, but you could also use Linux cap):

Just launch the demon, and add_mobile() / rem_mobile() to add or remove
GTPU tunnel endpoint.

>>> gsn = GTPUd()
>>> teid_to_rnc = gsn.add_mobile(mobile_IP='192.168.1.201', rnc_IP='10.2.1.1', TEID_from_rnc=0x1):
>>> gsn.rem_mobile(mobile_IP='192.168.1.201'):

3) That's all !
'''

import os
#import signal
from select import select
from struct import pack, unpack
from binascii import hexlify, unhexlify
from time import time, sleep
from random import randint
#
if os.name != 'nt':
    from fcntl import ioctl
    from socket import socket, timeout, error, 
                       ntohs, htons, inet_aton, inet_ntoa, 
                       AF_PACKET, SOCK_RAW, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
else:
    print('[ERR] GTPmgr : you\'re not on *nix system. It\'s not going to work:\n' \
          'You need PF_PACKET socket')

from libmich.formats.GTP import *
from libmich.mobnet.utils import *
#
# filtering exports
__all__ = ['GTPUd', 'ARPd', 'DPI']

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
    #
    DEBUG = 2
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
    GGSN_MAC_ADDR = '080000010203'.decode('hex')
    GGSN_IP_ADDR = '192.168.1.100'
    #
    # the pool of IP address to be used by our mobiles
    IP_POOL = ('192.168.1.201', '192.168.1.202')
    #
    # network parameters:
    # subnet prefix (we only handle /24 subnet at this time)
    SUBNET_PREFIX = '192.168.1.'
    # and 1st IP router (MAC and IP addresses)
    # this is to resolve directly any IP outside our subnet
    ROUTER_MAC_ADDR = 'f40000010203'.decode('hex')
    ROUTER_IP_ADDR = '192.168.1.1'
    
    def __init__(self):
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
            self.ROUTER_IP_ADDR : self.ROUTER_MAC_ADDR,
            self.GGSN_IP_ADDR : self.GGSN_MAC_ADDR,
            }
        for ip in self.IP_POOL:
            self.ARP_RESOLV_TABLE[ip] = self.GGSN_MAC_ADDR
        #
        # interrupt handler
        #def sigint_handler(signum, frame):
        #    if self.DEBUG > 1:
        #        self._log('CTRL+C caught')
        #    self.stop()
        #signal.signal(signal.SIGINT, sigint_handler)
        #
        # starting main listening loop in background
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('ARP resolver started')
        #
        # .resolve(ip) method is available for ARP resolution by GTPUd
    
    def _log(self, msg=''):
        if self.DEBUG:
            logit('[ARPd] %s' % msg)
    
    def stop(self):
        if self._listening:
            self._listening = False
            sleep(self.SELECT_TO * 2)
            self.sk_arp.close()
            self.sk_ip.close()
    
    def listen(self):
        # select() until we receive arp or ip packet
        while self._listening:
            r = []
            r = select([self.sk_arp, self.sk_ip], [], [], self.SELECT_TO)[0]
            for sk in r:
                buf = ''
                buf = sk.recvfrom(self.BUFLEN)[0]
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
        self._log('ARP resolver stopped')
    
    def _process_arpbuf(self, buf=''):
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
                      buf[6:12], self.GGSN_MAC_ADDR, self.GGSN_MAC_ADDR,
                      buf[38:42], buf[6:12], buf[28:32]),
                     (self.GGSN_ETH_IF, 0x0806))
                except:
                    self._log('Exception on ARP socket sendto (ARP response)')
                else:
                    if self.DEBUG > 1:
                        self._log('ARP response sent for IP: %s' % ipreq)
        # 2) check if it responses something useful for us
        elif arpop == 2:
            ipres = inet_ntoa(buf[28:32])
            if ipres[:11] == self.SUBNET_PREFIX \
            and ipres not in self.ARP_RESOLV_TABLE:
                self.ARP_RESOLV_TABLE[ipres] = buf[22:28]
                if self.DEBUG > 1:
                    self._log('got ARP response for new local IP %s' % ipres)
    
    def _process_ipbuf(self, buf=''):
        # this is an IPv4 packet : check if src IP is in our subnet
        ipsrc = inet_ntoa(buf[26:30])
        if ipsrc[:11] == self.SUBNET_PREFIX and ipsrc not in self.ARP_RESOLV_TABLE:
            # if local IP and not alreay resolved, store the Ethernet MAC address
            self.ARP_RESOLV_TABLE[ipsrc] = buf[6:12]
            if self.DEBUG > 1:
                self._log('got MAC address from IPv4 packet for new local IP %s' % ipsrc)
    
    def resolve(self, ip='192.168.1.2'):
        #
        # check if already resolved, possibly bypassing LAN subnet prefix
        if ip in self.ARP_RESOLV_TABLE:
            return self.ARP_RESOLV_TABLE[ip]
        #
        #if ip[:11] == self.SUBNET_PREFIX:
        elif '.'.join(ip.split('.')[:3]) == self.SUBNET_PREFIX:
            # else, need to request it live on the Ethernet link
            # response will be handled by .listen()
            try:
                self.sk_arp.sendto(
                 '\xFF\xFF\xFF\xFF\xFF\xFF{0}\x08\x06\0\x01\x08\0\x06\x04'\
                 '\0\x01{1}{2}{3}\0\0\0\0\0\0%s\0\0\0\0\0\0\0\0\0\0\0\0\0\0'\
                 '\0\0\0\0'.format(
                   self.GGSN_MAC_ADDR, self.GGSN_MAC_ADDR, 
                   inet_aton(self.GGSN_IP_ADDR), inet_aton(ip)),
                 (self.GGSN_ETH_IF, 0x0806))
            except:
                self._log('Exception on ARP socket sendto (ARP request)')
            else:
                if self.DEBUG > 1:
                    self._log('ARP request sent for our IP %s' % ip)
            cnt = 0
            while ip not in self.ARP_RESOLV_TABLE:
                sleep(self.SELECT_SLEEP)
                cnt += 1
                if cnt >= 3:
                    break
            if cnt < 3:
                return self.ARP_RESOLV_TABLE[ip]
            else:
                return 6*'\xFF'
        else:
            return self.ROUTER_MAC_ADDR


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
# only the packet for the given protocol / ports are transferred to the Gi
# WL_PORTS = [('UDP', 53), ('UDP', 123), ('TCP', 80), ...]
# This is bypapssing the blackhiling feature.
#

class GTPUd(object):
    #
    # debug level
    DEBUG = DBG
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
        # these are 2 dict for handling mobile GTPU packets' transfers :
        # take mobile IPv4 addr as key, and references (TEID, RNC_IP) 
        self._mobiles_ip = {}
        # take mobile TEID as key, and references mobile_IP
        self._mobiles_teid = {}
        # global TEID to RNC value, to be incremented from here
        self.GTP_TEID = randint(0, 20000)
        #
        # create a single GTP format decoder for input from RNC
        self._GTP_in = GTPv1()
        # and for output to RNC (un-automatize GTP length calculation)
        self._GTP_out = GTPv1()
        self._GTP_out.type.Pt = 0xff
        self._GTP_out.len.PtFunc = None
        # initialize the traffic statistics
        self.init_stats()
        self.__prot_dict = {1:'ICMP', 6:'TCP', 17:'UDP'}
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
        #        self._log('CTRL+C caught')
        #    self.stop()
        #signal.signal(signal.SIGINT, sigint_handler)
        #
        # and start listening and transferring packets in background
        self._listening = True
        self._listener_t = threadit(self.listen)
        self._log('GTPU handler started')
        #
        # and finally start ARP resolver
        self.arpd = ARPd()
    
    def _log(self, msg=''):
        if self.DEBUG:
            logit('[GTPUd] %s' % msg)
    
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
            # closing sockets
            self.int_sk.close()
            self.ext_sk.close()
            # unset promiscuous mode
            unset_promisc(self.ext_sk)
    
    def listen(self):
        # select() until we receive something on 1 side
        while self._listening:
            r = []
            r = select([self.int_sk, self.ext_sk], [], [], self.SELECT_TO)[0]
            for sk in r:
                buf = ''
                if sk is self.int_sk:
                    buf = sk.recv(self.BUFLEN)
                    if buf:
                        self.transfer_to_ext(buf)  
                elif sk is self.ext_sk:
                    # WNG: seems some pseudo-RNC IP stack crashes when we send
                    # fragmented IP packets on Iu side...
                    buf = sk.recvfrom(self.BUFLEN-128)[0]
                    if len(buf) >= 34 and buf[12:14] == '\x08\0' \
                    and buf[:6] == self.GGSN_MAC_ADDR :
                        # transferring over GTPU after removing Ethernet header
                        self.transfer_to_int(buf[14:])
        #
        self._log('GTPU handler stopped')
    
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
            self._log('dummy packet from mobile dropped: %s' % hexlify(ipbuf))
            return
        ipdst = inet_ntoa(ipbuf[16:20])
        #
        # analyze the packet content for statistics
        if self.DPI:
            self._analyze(ipbuf)
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
        if self.BLACKHOLING == 'ext' and macdst == self.arpd.ROUTER_MAC_ADDR:
            return
        #
        self._transfer_to_ext(macdst, ipbuf)
    
    def _transfer_to_ext(self, macdst='', ipbuf='\0'):
        # forward to the external PF_PACKET socket, over the Gi interface
        try:
            self.ext_sk.sendto('{0}{1}\x08\0{2}'.format(
                                macdst, self.GGSN_MAC_ADDR,self.EXT_PROT),
                               (self.EXT_IF, self.EXT_PROT))
        except:
            self._log('Exception on external Ethernet socket sendto')
        else:
            if self.DEBUG > 1:
                self._log('buffer transferred from GTPU to RAW')
    
    def transfer_to_int(self, buf='\0'):
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
    
    def _transfer_to_int(self, ipdst='', gtpbuf=''):
        try:
            ret = self.int_sk.sendto(gtpbuf,
                                    (self._mobiles_ip[ipdst][0], self.INT_PORT))
        except:
            self._log('Exception on internal UDP socket sendto')
        else:
            if self.DEBUG > 1:
                self._log('%i bytes transferred from RAW to GTPU' % ret)
    
    ###
    # Now we can add and remove (mobile_IP, TEID_from/to_RNC),
    # to configure filters and really start forwading packets over GTP
    def add_mobile(self, mobile_IP='192.168.1.201', rnc_IP='10.1.1.1', \
                                                    TEID_from_rnc=0x1):
        try:
            ip = inet_aton(mobile_IP)
        except error:
            self._log('mobile_IP has not the correct format: ' \
                      'cannot configure the GTPU handler')
            return
        TEID_to_rnc = self.get_teid_to_rnc()
        self._mobiles_ip[ip] = (rnc_IP, TEID_to_rnc)
        self._mobiles_teid[TEID_from_rnc] = ip
        self._log('setting GTP tunnel for mobile with IP %s' % mobile_IP)
        return TEID_to_rnc
    
    def rem_mobile(self, mobile_IP='192.168.1.201'):
        try:
            ip = inet_aton(mobile_IP)
        except error:
            self._log('mobile_IP has not the correct format: ' \
                      'cannot configure the GTPU handler')
            return
        if ip in self._mobiles_ip:
            self._log('unsetting GTP tunnel for mobile with IP %s' % mobile_IP)
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
#