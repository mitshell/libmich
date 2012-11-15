# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2012. Benoit Michau. ANSSI.
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
# * File Name : core/CSN1.py
# * Created : 2012-04-18 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

# check python version for deepcopy bug in 2.6
import sys
def __version_err():
    print('[ERR] only python 2.6 and 2.7 are supported (unfortunately)')
    raise(Exception)
if sys.version_info[0] == 2:
    if sys.version_info[1] == 6:
        import copy
        import types
        def _deepcopy_method(x, memo):
            return type(x)(x.im_func, deepcopy(x.im_self, memo), x.im_class)
        copy._deepcopy_dispatch[types.MethodType] = _deepcopy_method
    elif sys.version_info[1] != 7:
        __version_err()
else:
    __version_err()
#
#
from binascii import hexlify, unhexlify

# exporting
__all__ = ['CSN1', 'LHFlag', 'CSN1FIELDS', 'BREAK', 'BREAK_LOOP']

from libmich.core.element import Bit, Int, Str, Layer, show, showattr, \
    log, DBG, WNG, ERR
from libmich.core.shtr import shtr
from libmich.core.IANA_dict import IANA_dict as iad
from copy import deepcopy

######
# 3GPP CSN.1 is completely demoniac
######
# Attempt for csn1 codec
#
# CSN1() is a Layer instance
# any GSM IE (e.g. MobAlloc) are actually Layer instances
# and any Bit() instances (including LHFlag)
CSN1FIELDS = (Bit, Layer)
#
# this is special keys for dictionnary and their recursive decoding
BREAK_LOOP = 0xdead1004
BREAK      = 0xdead1001

class CSN1(Layer):
    '''
    CSN1 Layer provides an extended notation compared to traditional Layer.
    This allows to handle condition flags for selecting the correct field(s)
    to be inserted in the Layer.
    It is based on the class attribute `csn1List`, 
    which lists possible bit-fields from a csn.1 structure:
    - mandatory fields: Bit(), Str(), Layer() including CSN1(), 
    - tuple of mandatory fields
    - dictionnary where keys are flags for selecting the correct bit-fields,
      or tuple or sub-dictionnary (this is done recursively)
    -> condition (dictionnary keys) can be:
    'L', 'H' or '0', '1', '00', '01', 'LH' ...
    -> 'L' means padding bit (e.g. '2b' for GSM), 
    -> 'H' means opposite bit from padding
    Do not try to mix LH and 01 into single condition
    '''
    # Layer byte alignment, should never be True for CSN1
    _byte_aligned = False
    #
    # those are used when decoding CSN1 fields
    pad_name = 'CSN1_padding'
    cond_name = 'CSN1_condition'
    #
    # L is padding, H is non-padding: 
    # eg in GSM, padding is 0x2b in binary [MSB, ..., LSB]
    L = [0,0,0,0,0,0,0,0]
    #
    # this is the list to fulfill from the CSN1 syntax
    # with Bit() fields, CSN1() structures, dict() and tuple()
    csn1List = []
    # during decoding, those fields will be pushed to the Layer.elementList
    # depending of the conditions evaluated
    #
    # to enforce a maximum bit length, especially during map()
    max_bitlen = None
    # IE not to appear when using .show()
    _show_all = False
    _IE_no_show = ['CSN1_padding', 'CSN1_condition']
    
    def __init__(self, build_auto=False, build_path=None, name=''):
        # ensure L is binary only
        if self.safe:
            assert(all([l in (0, 1) for l in self.L]))
        Layer.__init__(self, CallName=name)
        self.max_bitlen = CSN1.max_bitlen
        # decorrelate the csn1List of the instance from the class one
        self.csn1List = deepcopy(self.csn1List)
        # elementList is still empty as it might not be needed
        # eg when using only .map()
        self.elementList = []
        #
        # if we want to build a valid layer with the easiest path possible
        # through the csn1List
        if build_auto:
            self.build(self.csn1List, offset=0, build_path=None)
        elif build_path is not None:
            self.build(self.csn1List, offset=0, build_path=build_path)
    
    # TODO: this needs to be enhanced with specific build_path, 
    # when we want to build more complex CSN1 messages
    def build(self, csn1iter, offset=0, build_path=None):
        self.elementList = []
        # create ._offset to handle LH values
        self._offset = offset
        #
        if build_path is None:
            self._build_auto(csn1iter)
        else:
            log(ERR, '(CSN1 build() with build_path not yet implemented')
            # TODO
        # clean the temporary ._offset attribute
        del self._offset
    
    def _build_auto(self, csn1iter):
        # recursive automatic loading of CSN.1 fields
        for f in csn1iter:
            if self.dbg >= DBG:
                log(DBG, '(build - %s) iterating over: %s' \
                    % repr(f))
            if isinstance(f, CSN1FIELDS):
                self._append_csn1_field(f)
            elif isinstance(f, tuple):
                self._build_auto(f)
            elif isinstance(f, dict):
                # select the shortest path: BREAK, BREAK_LOOP,
                # or the shortest value
                values = f.values()
                # easiest path is to get straight out of the dict
                if (BREAK or BREAK_LOOP) in values:
                    for i in f.items():
                        if i[1] in (BREAK, BREAK_LOOP):
                            self._append_path(i[0])
                            break
                # 2nd easiest path is to take a single CSN1FIELDS if exist
                elif True in [isinstance(i, CSN1FIELDS) for i in values]:
                    for i in f.items():
                        # "au petit bonheur la chance"
                        if isinstance(i[1], CSN1FIELDS):
                            self._append_path(i[0])
                            self._append_csn1_field(i[1])
                            break
                # 3rd easiest path is to take the shortest tuple available
                elif True in [isinstance(i, tuple) for i in values]:
                    min_tuple = min(map(len, values))
                    for i in f.items():
                        if len(i[1]) == min_tuple:
                            # "au petit bonheur la chance" again
                            self._append_path(i[0])
                            self._build_auto(i[1])
                            break
                # 4th easiest path is to enter the shortest dict available
                elif True in [isinstance(i, dict) for i in values]:
                    min_dict = min(map(len, values))
                    for i in f.items():
                        if len(i[1]) == min_dict:
                            # "au petit bonheur la chance" once again
                            self._append_path(i[0])
                            self._build_auto(i[1])
                            break
    
    def _append_path(self, path):
        if self.dbg >= DBG:
            log(DBG, '(build - %s) going path: %s' \
                % (self.__class__, repr(path)))
        cond = ''
        for c in path:
            # if LH, get the correct value with self._offset
            if c in 'LH':
                L = self.L[self._offset%8]
                self.append(Bit('%s' % self.cond_name, \
                    Pt={'L':L, 'H':(1, 0)[L]}[c] , BitLen=1))
            elif c in '01':
                self.append(Bit('%s' % self.pad_name, Pt=int(c, 2), BitLen=1))
            else:
                self._cond_error(path)
            self._offset += 1
    
    def _append_csn1_field(self, field):
        if isinstance(field, LHFlag):
            print self._offset
            if self.L[self._offset%8] == 1:
                field.LHdict = iad({1:'L', 0:'H'})
        if isinstance(field, CSN1):
            # TODO: this is a shortcut, will need changes for implementing
            # build_path
            self.append(field.__class__(build_auto=True))
        else:
            self.append(field)
        self._offset += field.bit_len()
    
    def map(self, string='', byte_offset=0):
        # pop each member of the initial csn1List
        # and see what we have
        # 1) CSN1FIELD -> map it directly
        # 2) dict -> conditions -> CSN1FIELD | dict | tuple
        # 3) tuple -> CSN1FIELD | dict
        # consume the string buffer bit per bit depending of the 
        # csn1List member poped
        #
        # as a CSN1 field does not always start on a byte limit,
        # we need to keep track of the byte offset, 
        # for solving padding (L | H) adequately
        #
        # in case CSN1 list is empty
        if len(self.csn1List) == 0:
            return
        # initialize the string buffer to be mapped
        self.BUF, self._buflen = shtr(string), len(string)*8
        self._consumed, self._offset, self._map_exit = 0, byte_offset, False
        self.elementList = []
        #
        # MAIN loop
        # go over the string, bit per bit
        index = 0
        while (self._consumed + self._offset) < self._buflen:
            if self._map_exit:
                break
            # get csn1 fields 1 by 1
            self._eval_csn1(self.csn1List[index])
            index += 1
            # when csn1List is empty, finish with padding
            if index >= len(self.csn1List):
                break
        #
        # TODO: the padding should only be done when instructed so in CSN1
        remaining = self._buflen - (self._consumed + self._offset)
        if remaining:
            if self.dbg >= DBG:
                log(DBG, '(CSN1._eval_csn1_dict) bits are remaining unmapped')
        # clean temporary data
        del self.BUF, self._buflen, self._consumed, \
            self._offset, self._map_exit
        # BUF is mapped on each CSN1 element each time one is appended
        # see ._append_map_csn1_field() method
    
    def _eval_csn1(self, csn1f):
        #
        # if we have directly a CSN.1 field
        if isinstance(csn1f, CSN1FIELDS):
            if isinstance(csn1f, CSN1):
                # decorrelate class attribute .csn1List from the instance' one
                csn1f = csn1f.__class__()
            elif isinstance(csn1f, Layer):
                csn1f._byte_aligned = False
            self._append_map_csn1_field(csn1f)
        #
        # if we have a dict with conditions
        elif isinstance(csn1f, dict):
            # special processing for recursive struct (syntax like {1 expr}**0)
            if BREAK_LOOP in csn1f.values():
                # then, loop on evaluating the expression until the 
                # key corresponding to the BREAK_LOOP item is found
                self._loop = True
                while self._loop:
                    self._eval_csn1_dict(csn1f)
            # classic dict & conditions processing
            else:
                self._eval_csn1_dict(csn1f)
        #
        # if we have a tuple: recursive call on each fields within the tuple
        elif isinstance(csn1f, tuple):
            for f in csn1f:
                self._eval_csn1(f)
    
    def _eval_csn1_dict(self, csn1f):
        # get the list of possible conditions
        # get it twice, 2nd going to be truncated
        conds_ori, conds_proc = csn1f.keys(), csn1f.keys()
        # initialize possible condition as retrieved from the buffer
        cond_from_buf, offset = '', 0
        #
        # Now we loop until we found a matching condition from the buffer
        while len(conds_proc) > 0:
            # collect a uniq set of the 1st bit from all conditions
            conds_1bit = set([c[:1] for c in conds_proc])
            # consume buffer bit per bit: 1st get binary value from BUF
            bufval = (self.BUF<<offset).left_val(1)
            #
            # check if we need to evaluate padding conditions
            if all([c in 'LH' for c in conds_1bit]):
                # get LH value from the current buffer, taking care of offset
                cond_from_buf += 'L' \
                    if bufval == self.L[(self._consumed+self._offset+offset)%8] \
                    else 'H'
            # or binary conditions
            elif all([c in '01' for c in conds_1bit]):
                cond_from_buf += str(bufval)
            # otherwise we mixed binary and padding conditions 
            # at the same iteration and this is unsolvable... call C.E. Shannon
            else:
                self._cond_error(conds_ori)
            #
            # if we found a matching condition
            # return and append the corresponding object
            if cond_from_buf in conds_ori:
                self._append_from_dict(csn1f[cond_from_buf], len(cond_from_buf))
                return
            # otherwise truncate conditions' 1st bit for next iteration
            # add an offset bit, and loop
            conds_proc = [c[1:] for c in conds_proc if len(c) > 1]
            offset += 1
        #
        # we should never come here,
        # or maybe we forgot a condition in our dict
        self._cond_error(conds_ori)
    
    def _cond_error(self, condset):
        if self.dbg >= ERR:
            log(ERR, '(CSN1._get_cond - %s) undefined CSN1 condition set: %s' \
                     % (condset, self.__class__))
        if self.safe:
            assert()
    
    def _append_from_dict(self, from_dict, condlen):
        # xtra verbose debugging
        if self.dbg > DBG:
            if type(from_dict) is tuple: obj = list(from_dict)
            elif hasattr(from_dict, 'CallName'): obj = from_dict.CallName
            else: obj = from_dict
            log(DBG, '(CSN1._eval_csn1_dict) selected from_dict: %s' % obj)
        # if condition lead to None: padding
        if from_dict == BREAK:
            self._append_map_csn1_field(Bit('%s' % self.pad_name, BitLen=condlen))
        # if condition lead to breaking a loop 
        # for crappy CSN1 syntax like {1 expr}**0
        elif from_dict == BREAK_LOOP:
            self._append_map_csn1_field(Bit('%s' % self.pad_name, BitLen=condlen))
            self._loop = False
        # if condition lead to something:
        else:
            self._append_map_csn1_field(Bit('%s' % self.cond_name, BitLen=condlen))
            # recurse to the main csn1 eval method applied to object from dict
            self._eval_csn1(from_dict)
    
    # In case we directly have a CSN1 field
    def _append_map_csn1_field(self, csn1f):
        # ensure there is still enough buffer to map on new fields
        if hasattr(csn1f, 'bit_len') \
        and csn1f.bit_len() > (self._buflen - (self._consumed+self._offset)):
            if self.dbg >= WNG:
                log(WNG, '(CSN1.map - %s) buffer not long enough for field: ' \
                         '%s from csn1List' % (self.__class__, csn1f.CallName))
            self._map_exit = True
            return
        # append the field to the layer
        if self.dbg >= DBG:
            log(DBG, '(CSN1._append_map_csn1_field) appending csn1 field: %s' \
                % csn1f.CallName)
        #
        # map the BUF on the element: this solves its bit length
        # moreover, we transmit the byte offset, for solving correctly L|H flags
        if type(csn1f) == type and issubclass(csn1f, CSN1):
            self.append(csn1f().clone())
        else:
            self.append(csn1f)
        #
        if isinstance(self[-1], CSN1):
            self[-1].map(self.BUF, (self._consumed+self._offset)%8)
            bitlen = self[-1].bit_len()
        else:
            self[-1].map(self.BUF)
            bitlen = self[-1].bit_len()
            # check if LHFlag to possibly update its LH dictionnary
            if isinstance(self[-1], LHFlag):
                l = self.L[(self._consumed+self._offset)%8]
                h = (1, 0)[l]
                self[-1].LHdict = iad({l:'L', h:'H'})
        #
        # update global BUFFER and consumed bit length 
        self.BUF = self.BUF << bitlen
        self._consumed += bitlen
        #
    
    def show(self, with_trans=False):
        re, tr = '', ''
        if self.ReprName != '':
            re = '%s ' % self.ReprName
        if self.is_transparent():
            # TODO: eval the best convinience here
            if not with_trans:
                return ''
            tr = ' - transparent'
        # Layer content
        #str_lst = [e.show().replace('\n', '\n ') for e in self]
        str_lst = []
        for e in self:
            if e.is_transparent():
                pass
            elif not self._show_all and e.CallName in self._IE_no_show:
                pass
            else:
                if isinstance(e, Str) and isinstance(e.Pt, Layer):
                    str_lst.append(e.Pt.show(with_trans).replace('\n', '\n '))
                else:
                    str_lst.append(e.show(with_trans).replace('\n', '\n '))
        #
        # insert spaces for nested layers and filter out empty content
        str_lst = [' %s\n' % s for s in str_lst if s]
        # insert layer's title
        str_lst.insert(0, '### %s[%s]%s ###\n' % (re, self.CallName, tr))
        # return full inline string without last CR
        return ''.join(str_lst)[:-1]

class LHFlag(Bit):
    # LHFlag has new attributes: .LHdict = {0:'L',1:'H'}, .LH = 'L' | 'H'
    # 
    # when mapping a buffer string to the LHFlag, the CSN1 Layer must take
    # care that this dict is correctly set depending of the byte offset and
    # padding pattern
    def __init__(self, CallName='', LH='L', Dict=None):
        self.LHdict = iad({0:'L', 1:'H'})
        Bit.__init__(self, CallName=CallName, BitLen=1, Dict=Dict, Repr='hum')
        if LH not in ('L', 'H'): LH = 'L'
        self.LH = LH
        self.Pt = 0
        self.PtFunc = self.__lh_val
        
    def __lh_val(self, _unused):
        return self.LHdict[self.LH]
        
    def __repr__(self):
        if self.Repr == "hex": return "0x%s" % self.__hex__()
        elif self.Repr == "bin": return "0b%s" % self.__bin__()
        elif self.Repr == "hum":
            if self.Dict:
                try: val = self.Dict[self.LHdict[self()]]
                except KeyError: val = self.LHdict[self()]
            else: 
                val = self.LHdict[self()]
            return repr(val)
    
    def clone(self):
        clone = self.__class__(self.CallName, self.LH, self.Dict)
        return clone
#