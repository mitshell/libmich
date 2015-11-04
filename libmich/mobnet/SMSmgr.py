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
# * File Name : mobnet/SMSmgr.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

'''
HOWTO:

1) in order to use this SMS relay, the following parameters need to be configured:
-> SMSRelay.SMSC_RP_NUM with the phone number you want (as str)
-> SMSRelay.TIMEZONE with the timezone identifier you want (uint8)

2) To use the SMSReleay:
>>> smsc = SMSRelay()
>>> rpresp = smsc.process_rp(rppdu)
>>> smsc.send_tp(ue, tppdu) # where ue is an UEd instance as defined in UEmgr.py
>>> smsc.send_text(ue, text)

3) That's all !
'''

from Queue import Queue
from time import localtime
#
#from libmich.formats.L3Mobile import *
from libmich.formats.L3Mobile_IE import *
from libmich.formats.L3Mobile_SMS import *
#
from .utils import *

# export filter
__all__ = ['SMSRelay']

class SMSRelay(object):
    '''
    Very basic SMS relay
    Receive, store, acknoledge (and does not forward...) SMS-RP messages
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    #
    # SMSC phone number
    SMSC_RP_NUM = '1234'
    #
    # timezone for TP_SCTS information
    TIMEZONE = 0
    #
    # MMEd reference, for sending MT-SMS
    MME = None
    
    def __init__(self):
        # 
        self.SMQueue = Queue()
        self._SMQ = self.SMQueue.queue
        #
        # TODO: 
        # we should start a loop that wait for incoming SMS message
        # into the SMQueue, and process / forward them to destination UE
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[{0}] [SMSRelay] {1}'.format(logtype, msg))
    
    def stop(self):
        pass
        # TODO:
        # when we will process the SMQueue for message forwarding, 
        # we will need to stop this background processing
    
    def process_rp(self, rp_msg):
        # incoming RP_DATA from the UE
        if isinstance(rp_msg, RP_DATA_MSToNET):
            self._log('DBG', 'received SMS RP message addressed to SMSC {0}'.format(
                      repr(rp_msg.RP_Destination_Address.Num)))
            # TODO: should validate the RP address number
            if isinstance(rp_msg.Data.V.getobj(), SMS_SUBMIT):
                return self.process_submit(rp_msg)
            else:
                self._log('WNG', 'unhandled SMS TP msg received:\n{0}'.format(tp_msg.show()))
        #
        # incoming RP_ACK_ or RP_ERROR
        elif isinstance(rp_msg, (RP_ACK_MSToNET, RP_ERROR)):
            # should connect to the SMS delivering procedure
            # thanks to the RP "Ref" value (maybe in the future...)
            if isinstance(rp_msg, RP_ACK_MSToNET):
                self._log('DBG', 'received RP_ACK: {0}'.format(repr(rp_msg.Data.V.getobj())))
            else:
                self._log('WNG', 'RP_ERROR error:\n{0}'.format(rp_msg.show()))
        #
        return None
    
    def process_submit(self, rp_msg):
        # get TP
        tp_msg = rp_msg.Data.V.getobj()
        # fill in SMQ
        if len(self._SMQ) > 0 and str(tp_msg) == str(self._SMQ[-1]):
            self._log('DBG', 'received duplicated SMS_SUBMIT...')
        else:
            self.SMQueue.put( tp_msg )
            try:
                num = repr(tp_msg.TP_Destination_Address.Num)
                text = repr(tp_msg.TP_UD)
                self._log('INF', 'received SMS_SUBMIT for {0}: {1}'.format(num, text))
            except Exception as err:
                self._log('INF', 'received SMS_SUBMIT: unable to content')
            self._log('DBG', 'SMS_SUBMIT structure:\n{0}'.format(tp_msg.show()))
        if tp_msg.TP_RD() == 1:
            # reject duplicates
            # unable to understand clearly the spec from here...
            # so replying with RPCause 21, SM transfer rejected
            err = RP_ERROR(Type=5, Ref=rp_msg.Ref(), RPCause=21)
            return err
        else:
            # send RP_ACK back to the UE
            return RP_ACK_NETToMS(Ref=rp_msg.Ref())
    
    def send_tp(self, num, tp_msg):
        # ensures an MME is referenced, and the dest number exists and is attached
        if self.MME is None:
            self._log('ERR', 'No MME referenced: unable to send MT-SMS')
            return
        elif num not in self.MME.Num_IMSI:
            self._log('ERR', 'Number {0} does not exist in the MME'.format(num))
            return
        imsi = self.MME.Num_IMSI[num]
        if imsi not in self.MME.UE:
            self._log('WNG', 'IMSI {0} corresponding to number {1} is not attached'.format(imsi, num))
            return
        # get the UEd instance and initiate the SMS transfer
        ue = self.MME.UE[imsi]
        # build the RP message
        # add current timestamp
        tp_msg = self._fill_time(tp_msg)
        # prepare RP message with SMSC number in RP header
        rp_msg = RP_DATA_NETToMS(Ref=1)
        rp_msg.RP_Originator_Address.Num.encode( self.SMSC_RP_NUM )
        rp_msg.Data.V.Pt = tp_msg
        # start the MT-SMS procedure
        self._log('DBG', 'sending TP message to {0}: {1}'.format(num, repr(tp_msg)))
        ue._run_smscpmt(Data=rp_msg)
    
    def _fill_time(self, tp_msg):
        if hasattr(tp_msg, 'TP_SCTS') and len(tp_msg.TP_SCTS) == 7:
            S, T = tp_msg.TP_SCTS, localtime()
            S.Year < T.tm_year
            S.Month < T.tm_mon
            S.Day < T.tm_mday
            S.Hour < T.tm_hour
            S.Minutes < T.tm_min
            S.Seconds < T.tm_sec
            S.TimeZone < self.TIMEZONE
        else:
            self._log('custom timestamping unhandled yet')
        return tp_msg
