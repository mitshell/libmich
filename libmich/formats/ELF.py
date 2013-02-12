# -*- coding: UTF-8 -*-
#/**
# * Software Name : libmich 
# * Version : 0.2.2
# *
# * Copyright © 2013. Benoit Michau.
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
# * File Name : formats/ELF.py
# * Created : 2013-02-06
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

#!/usr/bin/env python

from libmich.core.element import Bit, Int, Str, Layer, show, debug
from libmich.core.IANA_dict import IANA_dict
#from libmich.core.shtr import shtr

# ARM little endian
Int._endian = 'little'

e_type_dict = IANA_dict({
    0 : 'No file type',
    1 : 'Relocatable file',
    2 : 'Executable file',
    3 : 'Shared object file',
    4 : 'Core file',
    0xFE00 : 'OS specific',
    0xFEFF : 'OS specific',
    0xFF00 : 'Processor specific',
    0xFFFF : 'Processor specific',
    })
e_machine_dict = {
    0 : 'No machine',
    1 : 'AT&T WE 32100',
    2 : 'SPARC',
    3 : 'Intel 80386',
    4 : 'Motorola 68000',
    5 : 'Motorola 88000',
    7 : 'Intel 80860',
    8 : 'MIPS I Architecture',
    10 : 'MIPS RS3000 little-endian',
    15 : 'HP PA-RISC',
    17 : 'Fujitsu VPP500',
    18 : 'Enhanced Instruction Set SPARC',
    19 : 'Intel 80960',
    20 : 'Power PC',
    36 : 'NEC V800',
    37 : 'Fujitsu FR20',
    38 : 'TRW RH-32',
    39 : 'Motorola RCE',
    40 : 'Advanced RISC Machines ARM',
    41 : 'Digital Alpha',
    42 : 'Hitachi SH',
    43 : 'SPARC Version 9',
    44 : 'Siemens Tricore embedded processor',
    45 : 'Argonaut RSIC Core',
    46 : 'Hitachi H8/300',
    47 : 'Hitachi H8/300H',
    48 : 'Hitachi H8S',
    49 : 'Hitachi H8/500',
    50 : 'Intel Merced Processor',
    51 : 'Stanford MIPS-X',
    52 : 'Motorola Coldfire',
    53 : 'Motorola M68HC12',
    }
e_version_dict = {
    0 : 'Invalid',
    1 : 'Current',
    }
ei_class_dict = {
    0 : 'Invalid',
    1 : '32-bit objects',
    2 : '64-bit objects',
    }
ei_data_dict = {
    0 : 'Invalid',
    1 : 'Little endian',
    2 : 'Big endian',
    }
ei_osabi_dict = {
    0 : 'UNIX System V ABI',
    1 : 'HP-UX',
    255 : 'standalone application',
    }
#
class e_ident(Layer):
    constructorList = [
        Str('EI_MAG', Pt='\x7FELF', Len=4, Repr='hum'),
        Int('EI_CLASS', Pt=1, Type='uint8', Dict=ei_class_dict),
        Int('EI_DATA', Pt=1, Type='uint8', Dict=ei_data_dict),
        Int('EI_VERSION', Pt=1, Type='uint8', Dict=e_version_dict),
        Int('EI_OSABI', Pt=0, Type='uint8', Dict=ei_osabi_dict),
        Int('EI_OSABIVERSION', Pt=0, Type='uint8'),
        Str('EI_PAD', Pt='\0\0\0\0\0\0\0', Len=6, Repr='hex'),
        Int('EI_NIDENT', Pt=0, Type='uint8')
        ]
    
class Header(Layer):
    constructorList = [
        e_ident(),
        Int('e_type', Pt=0, Type='uint16', Dict=e_type_dict),
        Int('e_machine', Pt=0, Type='uint16', Dict=e_machine_dict),
        Int('e_version', Pt=1, Type='uint32', Dict=e_version_dict),
        Int('e_entry', Pt=0, Type='uint32'),
        Int('e_phoff', Pt=0, Type='uint32'),
        Int('e_shoff', Pt=0, Type='uint32'),
        Int('e_flags', Pt=0, Type='uint32', Repr='hex'),
        Int('e_ehsize', Pt=0, Type='uint16'),
        Int('e_phentsize', Pt=0, Type='uint16'),
        Int('e_phnum', Pt=0, Type='uint16'),
        Int('e_shentsize', Pt=0, Type='uint16'),
        Int('e_shnum', Pt=0, Type='uint16'),
        Int('e_shstrndx', Pt=0, Type='uint16'),
        ]