# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich
# * Version : 0.2.2
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
# * File Name : libmich/mobnet/utils.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 
#!/usr/bin/env python

import thread
import os
from inspect import stack
from time import time, sleep
from datetime import datetime
from Queue import Queue
from random import choice
from subprocess import Popen, PIPE
from threading import Thread, Event
#
# for logit() to Qt widget
try:
    from services.build_qt import LogViewer, LogWriter, QThread
except:
    print('utils.py: No QT services')
#
# and jingle playing with sound()
try:
    import pygame
    __pygame_imported = True
except ImportError:
    print('[import pygame] WNG: pygame not found, unable to play sounds')
    __pygame_imported = False
    def sound(*args, **kwargs):
        pass
else:
    pygame.mixer.init(32000, -16, 1, 1024)
    pygame.mixer.set_num_channels(16)

# export filtering
__all__ = ['pthreadit', 'threadit', 'logit', 'LOG_WITH_TIME', 'LOG_DIRTY', \
           'speech', 'SPEECH_USE', 'sound', 'SOUND_USE', \
           'tracecall', 'Timer', 'L3stack', 'show_msg', \
           ]


###
# sound facility
###
#
# automatic text-to-speech announcement
SPEECH_USE = True
_flite_path='/usr/bin/'
_flite_voice='slt'
def speech(msg=''):
    if not SPEECH_USE:
        return
    cmd = '%sflite' % _flite_path
    if not os.path.exists(cmd):
        print('[WNG] Flite binary not found at %s: no text-to-speech fun' % cmd)
        return
    #
    # TODO: insecure os.system() call
    os.system('%s "%s " -voice %s -o play >/dev/null 2>&1 &' \
              % (cmd, str(msg), _flite_voice))

# sound jingle playing, using pygame sound engine
SOUND_USE = True
_sounds_path = './sounds/'
if __pygame_imported:
    def sound(filename='to.wav', channel=1):
        if not SOUND_USE:
            return
        sample = '%s%s' % (_sounds_path, filename)
        if not os.path.exists(sample):
            print('[ERR] sound sample at %s not found' % sample)
            return
        try:
            chan = pygame.mixer.Channel( int(channel)%16 )
            sound = pygame.mixer.Sound( sample )
            chan.play( sound )
        except:
            print('[ERR] playing sound sample at %s' % sample)

###
# thread facility
###
# pthread the function / method (for e.g. backgrounding a TCP server)
def pthreadit(f, *args, **kwargs):
    if len(args) == 0 and len(kwargs) == 0:
        thread.start_new_thread(f, ())
    else:
        thread.start_new_thread(f, *args, **kwargs)
    return None

try:
    class _QThread(QThread):
        def __init__(self, f, *args, **kwargs):
            self.f = f
            self.args = args
            self.kwargs = kwargs
            QThread.__init__(self)
        
        def run(self):
            self.f(*self.args, **self.kwargs)
    
    def qthreadit(f, *args, **kwargs):
        qth = _QThread(f, *args, **kwargs)
        qth.start()
        return qth
except:
    pass

def pythreadit(f, *args, **kwargs):
    th = Thread(target=f, args=args, kwargs=kwargs)
    th.start()
    return th

def threadit(f, *args, **kwargs):
    #return pthreadit(f, *args, **kwargs)
    #return qthreadit(f, *args, **kwargs)
    return pythreadit(f, *args, **kwargs)


####
# log facility
###
#
LOG_WITH_TIME = True
#
LOG_TO_FILE = False
_log_file = '/tmp/mobnet_logs'
#
LOG_TO_NEW_WINDOW = False
_log_window_path = '/tmp/mobnet_logs_fifo'
def _create_window():
    os.mkfifo(_log_window_path)
    Popen(['xterm', '-e', 'tail', '-f', _log_window_path])
#
LOG_TO_WIDGET = False
_qlog_queue = Queue()
try:
    _qlog_writer = LogWriter()
    _qlog_writer.queue = _qlog_queue
    #print('LogWriter OK')
except:
    _qlog_writer = None
    print('LogWriter creation failed')

#
LOG_TO_CONSOLE = True


LOG_DIRTY = False
_dirty_logs = ( \
'bro', 'dude', 'baby', 'son', 'man', 'toh !!!', 'rastafary !!',
'oh my god !!', 'ok, but only this time', 'bitte ein Bit', 'on vend la caravane', 
'con una cerveza, por favor', 'si senior Valdez', 'please ?', 'isn\'t it, my Lord',
'r\'yu kidding me ?!', 'yu\'r talking to me ?!', 'don\'t move, i\'ll do it',
'just for you, baby', 'yu\'r so sexy', 'you dirty nerd', 'lol', 'looooool',
'lolol', 'ooooh baby !!', 'i like it like that', 'wu-tang forever', 'alleluia !!',
'whazzzup, bro ?', 'right now!', 'bingo !!!', 'ouais gros', 'let\'s do this',
)


def logit(msg=''):
    #
    if LOG_WITH_TIME:
        #log = '[%.3f] %s' % (time(), msg)
        log = '[%s] %s' % (datetime.now(), msg)
    else:
        log = msg
    if LOG_DIRTY:
        log = '%s; %s' % (log, choice(_dirty_logs))
    #
    if LOG_TO_FILE:
        try:
            fd = open(_log_file, 'a')
        except IOError:
            print('[ERR] logit : cannot append to log file %s' % _log_file)
        else:
            fd.write('%s\n' % log)
            fd.close()
    #
    if LOG_TO_NEW_WINDOW:
        if not os.path.exists(_log_window_path):
            _create_window()
        try:
            fd = open(_log_window_path, 'w')
        except IOError:
            print('[ERR] logit : cannot write to log fifo %s' % _log_window_path)
        else:
            fd.write('%s\n' % log)
    #
    elif LOG_TO_WIDGET:
        if hasattr(_qlog_writer, 'connected') and _qlog_writer.connected:
            _qlog_queue.put( log )
        else:
            print('[ERR] logit : log writer not connecting to widget %s' \
                   % _qlog_writer.ref)
    #
    elif LOG_TO_CONSOLE:
        print(log)

###
# tracing facility
###
# tracing function calls with this decorator, for debugging purpose
def tracecall(func):
    def wrapped(*args, **kwargs):
        #
        if 'function' in repr(func.__class__):
            funcname = func.__name__
        elif 'instancemethod' in repr(func.__class__):
            funcname = '%s.%s' % (func.im_class.__name__, func.__name__)
        print('[TRACECALL] %s, args: %s, %s' \
              % (funcname, repr(args), repr(kwargs)))
        #
        return func(*args, **kwargs)
    return wrapped


####
# global L3stack container, with built-in logging facilities
# and other standard methods and attributes
###
#
def show_msg(msg=''):
    if hasattr(msg, 'show'):
        return '\n%s' % msg.show()
    elif isinstance(msg, str):
        return '\n%s' % hexlify(msg)
    #elif isinstance(msg, (int, float, long)):
    #    return '\n%s' % repr(msg)
    else:
        return '\n%s' % repr(msg)
#
class L3stack(object):
    #
    # this is a fixed signal to unblock the listening loop
    _STACK_STOP = 0x574E
    #
    # settings to be more or less verbose, and to print IO signalling messages
    DEBUG = 1
    TRACE_IO = True
    
    def _log(self, msg=''):
        '''
        logging message
        '''
        if self.DEBUG:
            # try to get IMSI
            if hasattr(self, 'IMSI'):
                ident = self.IMSI
            elif hasattr(self, '_eNBID'):
                ident = self._eNBID
            else:
                ident = ''
            # log name of class, name of function calling for log, and msg
            _stack = stack()
            if len(_stack) >= 2:
                funcname = _stack[2][3]
            else:
                funcname = ''
            #
            logit('[%s] [%s - %s] %s' \
                  % (ident, self.__class__.__name__, funcname, msg))
    
    def _trace(self, msg=''):
        '''
        tracing signalling message passed between L3stack
        '''
        if self.DEBUG and self.TRACE_IO:
            # try to get IMSI
            if hasattr(self, 'IMSI'):
                imsi = self.IMSI
            else:
                imsi = ''
            # log name of class, name of function calling for log, and msg
            _stack = stack()
            if len(_stack) >= 1:
                funcname = _stack[2][3]
            else:
                funcname = ''
            #
            logit('[%s] [%s - %s - IO tracing]%s' \
                  % (imsi, self.__class__.__name__, funcname, show_msg(msg)))
    

###
# synchro facility with timer for queue and thread
###
#
class Timer(object):
    '''
    Timer instance sleeps for $dur seconds (it handles int and float),
    waking up every second to check if it has been stopped through self.stop(),
    and finally sends self.TIMER_EXPIRED signal to the $queue.
    '''
    # signal to throw on a queue when expiring
    TIMER_EXPIRED = 0x10000001
    #
    def __init__(self, dur=1, queue=Queue(), **kwargs):
        # maximum timer duration is fixed to 120s
        self.dur = min(120.0, float(dur))
        # queue to which timer will send signal when expiring
        self.queue = queue
        # Timer can embed more custom attributes
        for argname in kwargs:
            setattr(self, argname, kwargs[argname])
        #
        self.TIMER_EXPIRED = Timer.TIMER_EXPIRED
        Timer.TIMER_EXPIRED += 1
        #
        self._running = False
        threadit(self._run)
    
    def _run(self):
        # this timer count runs in background
        # so it can be stopped before expiry
        #
        s, f = divmod(self.dur, 1)
        self._running = True
        # sleep (several time) for 1 sec.
        while self._running and s > 0:
            sleep(1)
            s -= 1
        # sleep the fractional second time
        if self._running and f > 0:
            sleep(f)
        # if timer is still running after those sleep(), throw TIMER_EXPIRED
        if self._running:
            self.queue.put(self.TIMER_EXPIRED)
            self.stop()
    
    def is_running(self):
        return self._running
    
    def stop(self):
        # this stops the timer
        self._running = False
#