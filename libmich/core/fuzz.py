# −*− coding: UTF−8 −*−
#/**
# * Software Name : libmich 
# * Version : 0.2.1 
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
# * File Name : core/fuzz.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Element, Str, Int, Bit, Layer
from random import _urandom as urandom
from random import randint

# danger_str = '\x00\x01\x04\x06\t\x13!"&\'2!"#$%&\'()*+,-./0:;' \
#              '<=>?@[\\]^\\_{`{|}~\x7f\xae\xaf'
# termin_str = '\x00:;@\xff'


class MutationException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class TypeExhausted(MutationException):
    pass

class MutorExhausted(MutationException):
    pass

class LayorExhausted(MutationException):
    pass


class Mutor:
    '''
    A Mutor is a class to mutate Element taken from the core.element library.
    It is initialized with an Element instance, 
    that is taken as attribute: self.elmt
    and provides then methods to manage its mutation:
    - 'get_types': returns the identifiers of available types of mutations
    - 'select_type': takes an identifier of type of mutation 
                     to (re)initialize the mutate method
    - 'count_max_mutations': returns the number of available mutations 
                             for a given mutation's identifier, 
                             or all types of mutation
    - 'mutate': changes the returned value of this Element instance 
                thanks to its .Val attribute
    - 'exhausted': returns boolean, 
                   depending if all types of mutations are exhausted
    
    Different kind of mutations are defined in private methods:
    - '__count_%ElementType%_mut_%MutationType%()': returns the maximum number 
        of mutation for given types of Element and mutation
    - '__mutate_%ElementType%_%MutationType%()': mutate the element 
        and place the result in the .Val attribute of the Element.
    Parameters / settings are defined in the global attributes of Mutor 
    that can be adjusted for those private methods.
    
    New mutations techniques for Element can also be added 
    as new private methods, with identical naming rules and 
    adaptation on the global attributes.
    '''
    # Here, the mutate method places the mutated value into the .Val attribute 
    # of the element instance
    # So the "Mutor._orig_Val" stores the possible existing .Val attribute
    # before the mutation starts and helps to retrieves it when needed: 
    # e.g. for computing len / str methods for the original element
    
    # Str objects mutations parameters:
    # types of mutations defined for Str instance
    Str_type_available = [1, 2, 3, 4]
    # 
    # mutation type 1: truncate the original string 1 char by 1
    #
    # mutation type 2: replace some char of the original string by specific char
    # makes use of specific delimiters 
    # or dangerous characters for format strings :
    Str_type_2_char = ('\0', '@', ';', '&', '\'', '"', '*', '%')
    #Str_type_2_char = ('\x00', '\x01', '\x04', '\x06', '\t', '\x13', \
    #'!', '"', '&', "'", '2', '!', '"', '#', '$', '%', '&', "'", '(', \
    #')', '*', '+', ',', '-', '.', '/', '0', ':', ';', '<', '=', '>', \
    #'?', '@', '[', '\\', ']', '^', '\\', '_', '{', '`', '{', '|', '}', \
    #'~', '\x7f', '\xae', '\xaf', '\xff')
    # number of division of the original string 
    # to replace with the dangerous string:
    Str_type_2_steps = 5
    #
    # mutation type 3: appends specific char to the original string
    # keep something readable for identifying easily 
    # memory corruption in targets:
    Str_type_3_char = 'Z'
    # max length of the Str will be pow(2, Str_type_3_max_mutations)
    Str_type_3_max_mutations = 12
    #
    # mutation type 4: the powerful urandom fuzzer !!!
    Str_type_4_max_mutations = 32
    Str_type_4_max_len = 1280
    
    # Int objects mutations parameters:
    Int_type_available = [1, 2]  # types of mutations defined for Int instance
    # mutation type 1: test min value, max value, and each single bit at 1
    # mutation type 2: add specific values to the original value
    Int_type_2_val = (-0xFF, -0xF, -2, -1, 1, 2, 0xF, 0xFF)
    
    # Bit objects mutations parameters:
    Bit_type_available = [1, 2]  # types of mutations defined for Bit instance
    # mutation type 1: test min value, max value, and each single bit at 1
    # mutation type 2: add specific values to the original value
    Bit_type_2_val = (-0xFF, -0xF, -2, -1, 1, 2, 0xF, 0xFF)
    
    
    def __init__(self, my_Element):
        if not isinstance(my_Element, Element):
            raise MutationException('not an Element()')
        # never rewrites on .elmt attribute after Mutor instantiation
        self.elmt = my_Element
        self.elmt_type = str(self.elmt.__class__)[-5:-2]
        # never rewrites on ._orig_Val after Mutor instantiation
        self._orig_Val = self.elmt.Val
        self._orig_str = str(self.elmt)
        self._orig_len = len(self.elmt)
        self._orig_int = int(self.elmt)
        #self.types_exhausted = []
        self.__init_state()
    
    def __init_state(self):
        self.state = dict()
        for t in self.get_types():
            self.state[t] = [ 0, getattr(self, '_Mutor__count_%s_mut_%i' \
                                 % (self.elmt_type, t))() ]
    
    def get_types(self):
        if hasattr(self, 'elmt_type'):
            return getattr(Mutor, '%s_type_available' % self.elmt_type)
        return ()
    
    def count_max_mutations(self, type='all'):
        if type in self.get_types():
            return self.state[type][1]
        elif type == 'all':
            return sum(v[1] for v in self.state.values())
        raise MutationException('undefined type of mutation')
    
    def count_left_mutations(self, type='all'):
        if type in self.get_types():
            return self.count_max_mutations(type) - \
                   self.state[type][0]
        elif type == 'all':
            return self.count_max_mutations(type) - \
                   sum(v[0] for v in self.state.values())
        else:
            raise MutationException('undefined type of mutation')
    
    def mutate(self, type):
        # check if type is defined
        if type not in self.state.keys():
            self.elmt.Val = self._orig_Val
            raise MutationException('undefined type of mutation')
        # check if type is not already exhausted
        if self.state[type][0] == self.state[type][1]:
            self.elmt.Val = self._orig_Val
            raise TypeExhausted('Element %s, Mutations %s exhausted' \
                                % (self.elmt_type, type))
        # restore element original value (mutations must be ~stateless)
        self.elmt.Val = self._orig_Val
        # call corresponding element and type Mutor 
        getattr(self, '_Mutor__mutate_%s_%i' % (self.elmt_type, type))()
    
    def initialize(self, type='all'):
        if type == 'all':
            self.__init_state()
        elif type in self.state.keys():
            self.state[type][0] = 0
    
    def restore(self):
        self.elmt.Val = self._orig_Val
    
    def is_exhausted(self):
        for t in self.get_types():
            if self.state[t][0] != self.state[t][1]:
                return False
        return True
    
    #########################################
    # Now defines 4 methods for Str objects #
    #########################################
    def __count_Str_mut_1(self):
        return self._orig_len
    
    def __mutate_Str_1(self):
        # truncate self.elmt until having a null one:
        self.elmt.Val = str(self.elmt)[:-1]
        self.state[1][0] += 1
    
    def __count_Str_mut_2(self):
        # for short Str(), with length <= 4, 
        # need adaptation of the "Str_type_2_steps" attribute
        if len(self.elmt) < self.Str_type_2_steps:
            self.Str_type_2_steps = len(self.elmt)
        return self.Str_type_2_steps * len(Mutor.Str_type_2_char)
    
    def __mutate_Str_2(self):
        # for some char into self.elmt, 
        # replace it by one taken in Mutor.Str_type_2_char
        # those char are corresponding to the original string 
        # divided with the Str_type_2_steps
        # method local referencement
        chars = self.Str_type_2_char
        steps = self.Str_type_2_steps
        # char selection
        cur_char = chars[ self.state[2][0] // steps ]
        # step calculation
        step_len = self._orig_len//(steps-1)
        cur_step = self.state[2][0]%steps
        # current position in the string
        pos = min( self._orig_len-1, cur_step*step_len )
        self.elmt.Val = ''.join(( self._orig_str[:pos], \
                                  cur_char, self._orig_str[pos+1:] ))
        self.state[2][0] += 1
    
    def __count_Str_mut_3(self):
        return self.Str_type_3_max_mutations
    
    def __mutate_Str_3(self):
        # append Mutor.Str_type_3_char with exponentially increased length 
        self.elmt.Val = ''.join(( self._orig_str,
                           pow(2, self.state[3][0])*self.Str_type_3_char ))
        self.state[3][0] += 1
    
    def __count_Str_mut_4(self):
        return self.Str_type_4_max_mutations
    
    def __mutate_Str_4(self):
        # replace the whole self.elmt by urandom data 
        # of maximum length Mutor.Str_type_4_max_len
        self.elmt.Val = urandom( randint(1, self.Str_type_4_max_len) )
        self.state[4][0] += 1
    
    ########################################
    # Now defines 2 methods for Int object #
    ########################################
    def __count_Int_mut_1(self):
        return self._orig_len * 8 + 2
        
    def __mutate_Int_1(self):
        # test 0 integer value, max integer value, and each single bit to 1
        if self.state[1][0] == 0 :
            self.elmt.Val = 0
        # max value
        elif self.state[1][0] == 1 :
            if self.elmt.Type[0] == 'u': # unsigned
                self.elmt.Val = pow(2, self.state[1][1]-self.state[1][0]-1)-1
            else: # signed
                self.elmt.Val = pow(2, self.state[1][1]-self.state[1][0]-2)-1
        # each bit to 1
        else :
            if self.elmt.Type[0] == 'u' : # unsigned
                self.elmt.Val = pow(2, self.state[1][0]-2)
            else : # signed
                self.elmt.Val = pow( -1, (self.state[1][0]-1)// \
                                         (self._orig_len*8) ) * \
                                pow(2, self.state[1][0]-2)
        self.state[1][0] += 1
    
    def __count_Int_mut_2(self):
        return len(self.Int_type_2_val)
    
    def __mutate_Int_2(self):
        # add values taken from Mutor.Int_type_2_val
        self.elmt.Val = self._orig_int + self.Int_type_2_val[self.state[2][0]]
        self.state[2][0] += 1
    
    #######################################
    # Now defines 2 methods for Bit object 
    # > similar to uint Int object 
    #######################################
    def __count_Bit_mut_1(self):
        bitlen = self.elmt.bit_len()
        if bitlen == 1 :
            return 2
        return bitlen + 2
        
    def __mutate_Bit_1(self):
        # test 0 integer value, max integer value, and each single bit to 1
        if self.state[1][0] == 0 :
            self.elmt.Val = 0
        elif self.state[1][0] == 1 :
            self.elmt.Val = pow(2, self.elmt.bit_len())-1
        else :
            self.elmt.Val = pow(2, self.state[1][0]-2)
        self.state[1][0] += 1
    
    def __count_Bit_mut_2(self):
        return len(self.Bit_type_2_val)
        # coule be improved with a check of overflowing values 
        # for too short Bit element
    
    def __mutate_Bit_2(self):
        # add values taken from Mutor.Bit_type_2_val
        self.elmt.Val = self._orig_int + \
                        self.Bit_type_2_val[self.state[2][0]] 
        self.state[2][0] += 1
    


class Layor:
    '''
    Intermediate fuzzer for an element.Layer instance.
    Uses all mutations thanks to Mutor for each designated Element instance 
    in the Layer, referenced into the attribute list '.to_fuzz'.
    Provides the following methods:
    - 'remove': to remove an element or list of element from the list 'to_fuzz'
    - 'count_max_mutations': returns the number of available mutations 
                            for all mutations of elements in the list '.to_fuzz'
    - 'mutate': changes the returned value of a given element instance 
                thanks to its .Val attribute into the Layer
    
    Makes use for "evil" switches in order to trigger 
    even more possible memory corrupution:
    - '__evil_switch_%i': trigger specific inter-dependencies within the Layer
    
    Parameters / settings are defined in global dict attributes of Layor 
    '.evil_s%i', that can be adjusted for those private methods.
    '''
    dbg = 1
    
    evil_switches = (1, )
    # evil switch 1 is to increase Str size when mutating an Int element 
    # referencing Str size
    evil_s1 = { 'state' : 'off',
                'param' : 255, }
    
    
    def __init__(self, my_Layer) :
        if not isinstance(my_Layer, Layer) :
            raise MutationException('not a Layer()')
        self.mutors = [Mutor(elmt) for elmt in my_Layer]
    
    def remove(self, elmt=[]) :
        # handles a single elmt passed as arg
        if isinstance(elmt, Element) :
            for m in self.mutors :
                if elmt == m.elmt :
                    self.mutors.remove(m)
        # handles a list of elmt passed as arg
        elif isinstance(elmt, list) :
            for e in elmt :
                for m in self.mutors :
                    if e == m.elmt :
                        self.mutors.remove(m)
    
    def count_max_mutations(self) :
        count = 0
        for m in self.mutors:
            count += m.count_max_mutations('all')
        return count
    
    def count_left_mutations(self) :
        count = 0
        for m in self.mutors:
            count += m.count_left_mutations('all')
        return count
    
    def initialize(self) :
        for m in self.mutors :
            m._Mutor__init_state()
    
    def mutate(self, with_evil_intention=True) :
        # check for mutor(element) not yet exhausted in .to_fuzz list
        self.__select_mutor()
        self.__select_type()
        self.__mutate(with_evil_intention)
    
    def __select_mutor(self) :
        # select the elmt in the layer that has not yet exhausted its mutations
        self.rk = 0
        for m in self.mutors :
            if m.is_exhausted() :
                m.restore()
            else :
                self.current_mutor = m
                return
        raise LayorExhausted('No more mutations for %s' \
                              % self)
    
    def __select_type(self) :
        m = self.current_mutor
        for t in m.get_types():
            if m.state[t][0] < m.state[t][1]:
                self.current_type = t
    
    def __mutate(self, with_evil_intention) :
        # trigger in and out "evil" switches
        if with_evil_intention :
            for i in self.evil_switches :
                getattr(self, '_Layor__evil_switch_%s' % i)()
        self.current_mutor.mutate(self.current_type)
    
    # Str(), Int(), Bit() independently
    # within a Layer(): Str(), Int(), Bit() can be linked through 
    # their .PtFunc, .LenFunc, .TransFunc attributes
    # within a Block(): Layer(), Int(), Bit() can be linked through 
    # their .PtFunc, .LenFunc, .TransFunc attributes
    
    def __evil_switch_1(self) :
        # favorize memory corruption by having a long value in the Str Element 
        # and for which the length is currently corrupted by mutation
        # ... useful for 'LV' fields type 
        m = self.current_mutor
        # condition to enter the switch
        if self.current_type == 1 and isinstance(m.elmt, (Int, Bit)) and \
        m.elmt.PtFunc is not None and isinstance(m.elmt.Pt, Str) :
            #when entering the 1st time in the switch
            if self.evil_s1['state'] == 'off' :
                self.evil_s1['state'] = 'on'
                self.evil_s1['mem'] = m.elmt.Pt.Val
                self.evil_s1['val'] = m.elmt.Pt()
            # extend the value of the Str element that is used by the Int 
            # or Bit element for length 
            m.elmt.Pt.Val = self.evil_s1['val'] + \
                            self.evil_s1['param'] * m.Str_type_3_char
        # when leaving the switch after target mutation has exhausted
        elif self.evil_s1['state'] == 'on' and \
        self.current_type == 2 and isinstance(m.elmt, (Int, Bit)) and \
        m.elmt.PtFunc is not None and isinstance(m.elmt.Pt, Str) :
            self.evil_s1['state'] = 'off'
            m.elmt.Pt.Val = self.evil_s1['mem']
            del self.evil_s1['mem'], self.evil_s1['val']
    
    def __evil_switch_2(self):
        # add a Str() element at the end of the Layer, and fuzz it
        pass


class Blockor:
    
    pass
    
    #def fuzz_Layer(self, Layer):
       #pass
        #for el in Layer:
        #    if isinstance(el, element.Str):
        #        self.fuzz_Str(el)
        #    elif isinstance(el, element.Int):
        #        self.fuzz_Int(el)
        # must handle relationships between Elements:
        # True when PtFunc, LenFunc, TransFunc are not None
        # when Pt, Len, Trans are pointing to other Elements: .Str(), .Int(), 
        # or subclass, or list of Element subclass ... whatelse
        
    #def fuzz_Block(self, Block):
        #pass
        # loop on Layer in Block, and call fuzz_Layer() 
        #for l in Block:
        #    if isinstance(lay, Layer):
        #        self.fuzz_Layer(lay)
        #        
        # must handle relationship between Layers:
        # True when PtFunc, LenFunc, TransFunc are not None
        # when Pt, Len, Trans are pointing to other Layers: .get_payload(), 
        # .get_header(), .get_previous(), .get_next()


