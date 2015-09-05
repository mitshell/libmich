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
# * File Name : mobnet/AuC.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

'''
HOWTO:

1) in order to use this AuC, the following parameters and files need to be configured:
-> files AuC.db and AuC_2G.db need to be edited with IMSI and authentication parameters from your USIM cards
-> AuC.AuC_db_path can be change if files .db files are copied elsewhere
-> AuC.OP needs to be changed according to your Milenage customization

2) To use the AuC:
>>> auc = AuC()
>>> vec2g = auc.make_2g_vector('001010000000001')
>>> vec3g = auc.make_3g_vector('001010000000001', AMF='\x00\x00')
>>> vec4g = make_4g_vector('001010000000001', SN_ID='\x00\xf1\x10', AMF='\x80\x00')
>>> auc.synchronize('001010000000001', RAND=16*'\0', AMF='\0\0', AUTS=14*'\0')

3) That's all !
'''
# filtering exports
__all__ = ['AuC']

import os, time
from random import _urandom as urandom
from binascii import hexlify, unhexlify
from struct import pack, unpack
from time import sleep
#
try:
    from CryptoMobile.Milenage import *
except ImportError as err:
    print('CryptoMobile library is required for Milenage')
    raise(err)
#
from .utils import log

class AuC:
    '''
    3GPP Authentication Centre
    
    manages the AuC.db file with (IMSI, K, SQN) records for 3G auth vectors
    and the AuC_2G.db file with (IMSI, RAND, Kc, RES) hardcoded triplets for 2G auth vectors
    '''
    
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    
    AuC_db_path = '%s/' % os.path.dirname(os.path.abspath( __file__ ))
    #AuC_db_path = 'C:\Python27\Lib\sitepackages\HLR'
    
    # MNO OP diversification parameter
    OP =  'ffffffffffffffff'
    
    def __init__(self):
        self.start()
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[{0}] [AuC] {1}'.format(logtype, msg))
    
    def start(self):
        '''
        start the AuC:
        
        open AuC.db file
        parse it into a dict: self.db, containing IMSI: (K, SQN)
            IMSI: string of digit
            K: string (16 bytes)
            SQN: integer
        '''
        self._running = True
        self._log('INF', 'Starting AuC')
        
        # open authentication database AuC.db
        file_db = open('%s/AuC.db' % self.AuC_db_path)
        # parse it into a dict object with IMSI as key
        self.db = {}
        
        for line in file_db:
            if line [0] != '#' and line.count(';') >= 2:
                fields = line.split(';')
                IMSI    = str( fields[0] )
                K       = unhexlify( fields[1] )
                SQN     = int( fields[2] )
                self.db[IMSI] = [ K, SQN ]
        
        self._log('DBG', 'AuC.db file opened: {0} record(s) found'.format(
                  len(self.db.keys())))
        # close the file
        file_db.close()
        
        # open authentication database AuC_2G.db
        file_db = open('%s/AuC_2G.db' % self.AuC_db_path)
        # parse it into a dict object with IMSI as key
        self.db_2G = {}
        
        for line in file_db:
            if line [0] != '#' and line.count(';') >= 3:
                fields = line.split(';')
                IMSI    = fields[0]
                RAND    = unhexlify( fields[1] )
                Kc      = unhexlify( fields[2] )
                RES     = unhexlify( fields[3] )
                self.db_2G[IMSI] = [ RAND, Kc, RES ]
        
        self._log('DBG', 'AuC_2G.db file opened: {0} record(s) found'.format(
                  len(self.db_2G.keys())))
        # close the file
        file_db.close()
    
    def stop(self):
        '''
        stop the AuC:
        
        save old AuC.db with time information
        write the current content of self.db dict into AuC.db
        '''
        if not self._running:
            return
        
        T = time.strftime( '20%y%m%d_%H%M', time.gmtime() )
        self._log('INF', 'AuC stopped')
        
        # get header from file AuC.db
        header = ''
        file_db = open('%s/AuC.db' % self.AuC_db_path)
        for line in file_db:
            if line[0] == '#': header += line
            else: break
        header += '\n'
        file_db.close()
        
        # save the last current version of AuC.db
        os.rename( '%s/AuC.db' % self.AuC_db_path, '%s/AuC.db.%s' % (self.AuC_db_path, T) )
        self._log('DBG', 'old AuC.db saved with timestamp')
        
        # save the current self.db into a new AuC.db file
        file_db = open('%s/AuC.db' % self.AuC_db_path, 'w')
        file_db.write( header )
        indexes = self.db.keys()
        indexes.sort()
        for imsi in indexes:
            file_db.write( '%s;%s;%s\n' % (imsi, hexlify(self.db[imsi][0]), str(self.db[imsi][1])) )
        file_db.write('\n\n')
        file_db.close()
        self._log('DBG', 'new AuC.db saved from current db')
        
        self._running = False
    
    def make_3g_vector(self, IMSI, AMF='\0\0', RAND=None):
        '''
        produces a 3G authentication vector "quintuplet" for a given IMSI
        
        requests self.db for the authentication key corresponding to the IMSI
        and returns RAND, XRES, CK, IK, AUTN obtained from the Milenage functions
        '''
        # lookup AuC_db for authentication key and SQN from IMSI
        if IMSI not in self.db.keys():
            self._log('WNG', '[make_3g_vector] IMSI {0} not present in '\
                      'AuC.db'.format(IMSI))
            return -1
        
        # WNG : there is an issue when retrieving SQN from 2 parallel threads
        #       (almost) at the same time
        # -> both threads can get the same SQN value
        # TODO: we would need a Queue / Lock mechanism so that MM & GMM stacks
        # never get the same SQN value
        
        # get Key and counter
        K, SQN = self.db[IMSI][0], self.db[IMSI][1]
        # increment counter
        self.db[IMSI][1] += 1
        
        # pack SQN from integer to buffer
        SQN = '\0\0' + pack('!I', SQN)
        
        # generate challenge
        if not isinstance(RAND, bytes) or len(RAND) != 16:
            RAND = urandom(16)
        
        # compute Milenage functions
        Mil = Milenage( self.OP )
        XRES, CK, IK, AK = Mil.f2345( K, RAND )
        MAC_A = Mil.f1( K, RAND, SQN, AMF ) # pack SQN
        AUTN = xor_string( SQN, AK ) + AMF + MAC_A # pack SQN
        
        # return auth vector
        self._log('DBG', '[make_3g_vector] returning 3G authentication vector:'\
                  ' RAND, XRES, CK, IK, AUTN for IMSI {0} with SQN {1}'.format(
                  IMSI, hexlify(SQN)))
        return RAND, XRES, CK, IK, AUTN
    
    def synchronize(self, IMSI, RAND=16*'\0', AMF='\0\0', AUTS=14*'\0'):
        '''
        synchronize the local counter SQN with AUTS provided by the USIM
        in response to a given 3G authentication challenge (RAND, AMF)
        '''
        # lookup AuC_db for authentication key and SQN from IMSI
        if IMSI not in self.db.keys():
            self._log('WNG', '[synchronize] IMSI {0} not present in '\
                      'AuC.db'.format(IMSI))
            return -1
        K, SQN = self.db[IMSI][0], self.db[IMSI][1]
        
        # 33.102, section 6.3.3, for resynch, AMF is always null (0x0000)
        AMF = '\0\0'
        
        # compute Milenage functions and unmask SQN
        Mil = Milenage( self.OP )
        AK = Mil.f5star( K, RAND )
        SQN_MS = xor_string( AUTS[0:6], AK )
        #self._log('DBG', '[synchronize] USIM synchronization, unmasked '\
        #          'SQN_MS: %s' % hexlify(SQN_MS))
        MAC_S = Mil.f1star( K, RAND, SQN_MS, AMF )
        #self._log('DBG', '[synchronize] USIM synchronization, computed '\
        #          'MAC_S: %s' % hexlify(MAC_S))
        
        # authenticate the USIM
        if MAC_S != AUTS[6:14]:
            self._log('ERR', '[synchronize] USIM authentication failure during'\
                      ' synchronization for IMSI {0}'.format(IMSI))
            return -1
        
        # re-synchronize local SQN value
        sqn = unpack('!I', SQN_MS[2:])[0] + 1
        self.db[IMSI][1] = sqn
        self._log('DBG', '[synchronize] SQN resynchronized with value {0} for '\
                  'IMSI {1}'.format(sqn, IMSI))
        return 0
    
    def make_2g_vector(self, IMSI):
        '''
        produces a 2G authentication vector "triplet" for a given IMSI
        
        requests self.db_2G for the triplet corresponding to the IMSI
        and returns RAND, Kc, RES obtained from the db
        '''
        # lookup AuC_db_2G for authentication hardcoded triplet from IMSI
        if IMSI not in self.db_2G.keys():
            self._log('WNG', '[make_2g_vector] IMSI {0} not present in '\
                      'AuC_2G.db'.format(IMSI))
            return -1
        RAND, Kc, RES = self.db_2G[IMSI][0], self.db_2G[IMSI][1], self.db_2G[IMSI][2]
        
        # return auth vector
        self._log('DBG', '[make_2g_vector] returning 2G authentication vector:'\
                  ' RAND, RES, Kc for IMSI {0}'.format(IMSI))
        return RAND, RES, Kc
    
    def make_4g_vector(self, IMSI, SN_ID, AMF='\x80\x00', RAND=None):
        '''
        produces a 4G authentication vector "quadruplet" for a given IMSI and
        network (MCC / MNC)
        
        requests self.db for the authentication key corresponding to the IMSI
        and returns RAND, XRES, AUTN, Kasme obtained from the Milenage 
        and key derivation function functions
        '''
        # lookup AuC_db for authentication key and SQN from IMSI
        if IMSI not in self.db.keys():
            self._log('WNG', '[make_4g_vector] IMSI {0} not present in '\
                      'AuC.db'.format(IMSI))
            return -1
        if len(SN_ID) != 3:
            self._log('ERR', '[make_4g_vector] incorrect Serving Network ID:'\
                      ' {0}'.format(hexlify(SN_ID)))
            return -1
        
        # get Key and counter
        K, SQN = self.db[IMSI][0], self.db[IMSI][1]
        # increment counter
        self.db[IMSI][1] += 1
        
        # pack SQN from integer to buffer
        SQN = '\0\0' + pack('!I', SQN)
        
        # generate challenge
        if not isinstance(RAND, bytes) or len(RAND) != 16:
            RAND = urandom(16)
        
        # compute Milenage functions
        Mil = Milenage( self.OP )
        XRES, CK, IK, AK = Mil.f2345( K, RAND )
        MAC_A = Mil.f1( K, RAND, SQN, AMF ) # pack SQN
        AUTN = xor_string( SQN, AK ) + AMF + MAC_A # pack SQN
        
        # convert to LTE master key
        Kasme = conv_A2(CK=CK, IK=IK, sn_id=SN_ID, sqn_x_ak=AUTN[:6])
        
        # return auth vector
        self._log('DBG', '[make_4g_vector] returning 4G authentication vector:'\
                  ' RAND, XRES, AUTN, KASME for IMSI {0} with SQN {1} and SN '\
                  'ID {2}'.format(IMSI, hexlify(SQN), hexlify(SN_ID)))
        return RAND, XRES, AUTN, Kasme
