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
# * File Name : formats/MPEG4.py
# * Created : 2011-08-28 
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Str, Int, Bit, \
     Layer, Block, RawLayer, show, debug
#from libmich.core.IANA_dict import IANA_dict

# from ISO_IEC_14496-12_2008.pdf (free ISO spec)
# does not implement 64-bit size field for atom / box
# does not implement specific atoms with extended header

class MPEG4(Block):
    
    def __init__(self):
        Block.__init__(self, Name='MPEG4')
        self.append(atom())
    
    def parse(self, s='', recursive=True):
        self[0].map(s)
        self[0].atomic = False
        s=s[len(self[0]):]
        while len(s) > 0:
            self.append(atom())
            self[-1].map(s)
            self[-1].atomic = False
            s=s[len(self[-1]):]
        if not recursive:
            return
        while not self.__all_atomic():
            self.__check_atomic()
    
    def __all_atomic(self):
        for atom in self:
            if not atom.atomic:
                return False
        #for atom in self:
        #    del atom.atomic
        return True
    
    def __check_atomic(self):
        for p_atom in self:
            if not p_atom.atomic:
                child = self.get_child(p_atom)
                if len(child) == 0:
                    p_atom.atomic = True
                else:
                    self.__insert_atoms(p_atom, child)
                    p_atom.data.Val = ''
                    p_atom.atomic = True
    
    def __insert_atoms(self, p_atom, child=[]):
        child.reverse() # reverse child atoms order, due to Block.insert()
        debug(self.dbg, 3, '(MPEG4) p_atom %s index in Block: %s' \
              % (p_atom.type, p_atom.get_index()))
        debug(self.dbg, 3, '(MPEG4) inserting: %s' % [c.type for c in child])
        for atom in child:
            self.insert(p_atom.get_index()+1, atom)
            self[p_atom.get_index()+1].atomic = False
            self[p_atom.get_index()+1].hierarchy = p_atom.hierarchy+1
    
    def get_child(self, p_atom):
        if int(p_atom.size) <= 8:
            return []
        s = str(p_atom.data)
        child_atoms = []
        while len(s) > 0:
            child_atoms.append(atom())
            child_atoms[-1].map(s)
            debug(self.dbg, 3, '(MPEG4) child_atoms:\n%s\n' % child_atoms)
            s=s[len(child_atoms[-1]):] 
        if sum([int(c_atom.size) for c_atom in child_atoms]) == \
           int(p_atom.size)-8:
            return child_atoms
        else:
            return []

# MPEG4 atom / box basic structure
class atom(Layer):
    constructorList = [
        Int(CallName='size', Type='uint32'),
        Str(CallName='type', Len=4),
        Str(CallName='data', Pt=''),
        ]
    
    def __init__(self, type='ftyp', data=''):
        Layer.__init__(self, CallName='atom', ReprName='MPEG4 atom')
        self.type.Pt = type
        self.data.Pt = data
        self.data.Len = self.size
        self.data.LenFunc = lambda size: int(size)-8
        self.size.Pt = (self.data, self.get_payload)
        self.size.PtFunc = lambda (data, pay): len(data)+len(pay())+8




