#!/usr/bin/env python

# generic imports
from libmich.core.element import Bit, Str, Int, Layer, Block, show, debug

###
# ISO IEC 13818
# section 2.4.3
# transport stream syntax
###

PID_type = {
    0x0000 : 'Program Association Table',
    0x0001 : 'Conditional Access Table',
    0x0002 : 'Transport Stream Description Table',
    0x00010 : 'other purposes',
    0x1FFF : 'Null packet',
    }
Scramb_type = {
    0x0 : 'not scrambled',
    }
Adapt_type = {
    0x0 : 'FFU',
    0x1 : 'payload only',
    0x2 : 'adaptation only',
    0x3 : 'adaptation and payload',
    }

class Adaptation(Layer):
    constructorList = [
        Int('len', Pt=0, Type='uint8', Repr='hum'),
        Str('adapt_data', ReprName='Raw adaption data', Pt='', Repr='hex')]
    
    def __init__(self):
        Layer.__init__(self)
        self.adapt_data.Len = self.len
        self.adapt_data.LenFunc = lambda len: int(len)-1


class Transport(Layer):
    constructorList = [
        Int('sync', ReprName='Sync Byte', Pt=0, Type='uint8', Repr='hum'),
        Bit('trans_err', ReprName='Transport error indicator', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit('start_ind', ReprName='Payload unit start indicator', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit('trans_pri', ReprName='Transport priority', Pt=0, \
            BitLen=1, Repr='hum'),
        Bit('PID', Pt=0, BitLen=13, Dict=PID_type, Repr='hum'),
        Bit('trans_scramb', ReprName='Transport scrambling control', Pt=0, \
            BitLen=2, Dict=Scramb_type, Repr='hum'),
        Bit('adapt_ctrl', ReprName='Adaptation field Control', Pt=0, \
            BitLen=2, Dict=Adapt_type, Repr='hum'),
        Bit('cont_count', ReprName='Continuity counter', Pt=0, \
            BitLen=4, Repr='hum'),
        Str('adapt', ReprName='Adaptation field', Pt=Adaptation(), \
            Trans=True, Repr='hum'),
        Str('data', Pt='', Len=0, Repr='hex')]
    
    def __init__(self):
        Layer.__init__(self)
        self.adapt.Trans = self.adapt_ctrl
        self.adapt.TransFunc = self.__have_adapt
        self.data.Len = self.adapt_ctrl
        self.data.LenFunc = self.__data_len
        # the following is not compatible with preceeding processing:
        #self.adapt_ctrl.Pt = self.adapt
        #self.adapt_ctrl.PtFunc = self.__set_adapt_ctrl
    
    def __have_adapt(self, adapt_ctrl):
        if adapt_ctrl() & 0b10 == 1:
            # adaptation field not transparent
            return False
        return True
    
    def __data_len(self, adapt_ctrl):
        if adapt_ctrl() & 0b10 == 1:
            # adaptation field not transparent
            return max(184-len(self.adapt), 0)
        return 184
    
    #def __set_adapt_ctrl(self, adapt):
    #    if len(adapt) > 0:
    #        self.adapt_ctrl > self.adapt_ctrl() | 0b10
    #    else:
    #        self.adapt_ctrl > self.adapt_ctrl() & 0b01
    



