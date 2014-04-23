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
from libmich.core.element import Bit, Int, Str, Layer, RawLayer, Block, show, debug
from libmich.core.IANA_dict import IANA_dict

# endianness to use when mapping an ELF file onto our Elf Layers
Int._endian = 'little'

# global header info
e_type_dict = IANA_dict({
    0 : 'ET_NONE: No file type',
    1 : 'ET_REL: Relocatable file',
    2 : 'ET_EXEC: Executable file',
    3 : 'ET_DYN: Shared object file',
    4 : 'ET_CORE: Core file',
    0xfe00 : 'ET_LOOS: OS specific',
    0xfeff : 'ET_HIOS: OS specific',
    0xff00 : 'ET_LOPROC: Processor specific',
    0xffff : 'ET_HIPROC: Processor specific',
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
    164 : 'Qualcomm Hexagon',
    }
e_version_dict = {
    0 : 'EV_NONE: Invalid',
    1 : 'EV_CURRENT: Current',
    }
ei_class_dict = {
    0 : 'ELFCLASSNONE: Invalid',
    1 : 'ELFCLASS32: 32-bit objects',
    2 : 'ELFCLASS64: 64-bit objects',
    }
ei_data_dict = {
    0 : 'ELFDATANONE: Invalid',
    1 : 'ELFDATA2LSB: Little endian',
    2 : 'ELFDATA2MSB: Big endian',
    }
ei_osabi_dict = {
    0 : 'ELFOSABI_SYSV: UNIX System V ABI',
    1 : 'ELFOSABI_HPUX: HP-UX',
    255 : 'ELFOSABI_STANDALONE: standalone application',
    }

# program header info
p_type_dict = IANA_dict({
    0 : 'PT_NULL: Null',
    1 : 'PT_LOAD: Loadable segment',
    2 : 'PT_DYNAMIC: Dynamic linking information',
    3 : 'PT_INTERP: Interpreter',
    4 : 'PT_NOTE: Auxiliary information',
    5 : 'PT_SHLIB: unspecified',
    6 : 'PT_PHDR: Program header table',
    0x60000000 : 'PT_LOOS: OS specific',
    0x6fffffff : 'PT_HIOS: OS specific',
    0x70000000 : 'PT_LOPROC: Processor specific',
    0x7fffffff : 'PT_HIPROC: Processor specific',
    0x80000000 : 'unknown',
    0xffffffff : 'unknown',
    })
p_flags_dict = {
    0 : 'None: All access denied',
    1 : 'PF_X: Execute',
    2 : 'PF_W: Write',
    3 : 'PF_X+W',
    4 : 'PF_R: Read',
    5 : 'PF_X+R',
    6 : 'PF_W+R',
    7 : 'PF_X+W+R',
    }

# section header info
#sh_type_dict = IANA_dict({
sh_type_dict = {
    0 : 'SHT_NULL: Null',
    1 : 'SHT_PROGBITS: Program specific',
    2 : 'SHT_SYMTAB: Symbol table',
    3 : 'SHT_STRTAB: String table',
    4 : 'SHT_RELA: Relocation with addends',
    5 : 'SHT_HASH: Symbol hash table',
    6 : 'SHT_DYNAMIC: Info for dynamic linking',
    7 : 'SHT_NOTE: Auxiliary information',
    8 : 'SHT_NOBITS: Empty program specifics',
    9 : 'SHT_REL: Relocation without addends',
    10 : 'SHT_SHLIB: unspecified semantics',
    11 : 'SHT_DYNSYM: Dynamic linking symbol table',
    0x60000000 : 'SHT_LOOS: OS specific',
    0x6fffffff : 'SHT_HIOS: OS specific',
    0x70000000 : 'SHT_LOPROC: Processor specific',
    0x7fffffff : 'SHT_HIPROC: Processor specific',
    0x80000000 : 'SHT_LOUSER: Program specific',
    0xffffffff : 'SHT_HIUSER: Program specific',
    }
    #})
#sh_flags_dict = IANA_dict({
sh_flags_dict = {
    1 : 'SHF_WRITE: Writable during exec',
    2 : 'SHF_ALLOC: In memory during exec',
    3 : 'SHF_WRITE+ALLOC',
    4 : 'SHF_EXECINSTR: Executable instructions',
    5 : 'SHF_WRITE+EXECINSTR',
    6 : 'SHF_ALLOC+EXECINSTR',
    7 : 'SHF_WRITE+ALLOC+EXECINSTR',
    }
    #0x0f000000 : 'SHF_MASKOS: OS specific',
    #0xf0000000 : 'SHF_MASKPROC: Processor specific',
    #})
#
class ELF(Block):
    def __init__(self, arch='Elf32'):
        Block.__init__(self, Name='ELF')
        if arch != 'Elf32':
            print('pfff... no 64 bit yet')
            raise()
        else:
            self._arch=arch
        self.append(Elf32_Ehdr())
    
    def map(self, s=''):
        self.__init__(self._arch)
        self._stream = s
        self._ph = []
        self._sh = []
        # map the stream to the ELF header
        self[0].map(s)
        off = len(self[0])
        if off < self[0].e_ehsize():
            self | void(Len=self[0].e_ehsize()-off)
            self[-1].map(s[off:])
            off = self[0].e_ehsize()
        elif off > self[0].e_ehsize():
            print('Invalid ELF header size: %s' % self[0].e_ehsize())
            return
        # ELF stream mapping is not linear
        # so every needed part is mapped within a given Layer
        # which is kept in 2 private lists : self._ph and self._sh
        #
        # 1) program headers
        p_num = self[0].e_phnum()
        p_size = self[0].e_phentsize()
        p_start = self[0].e_phoff()
        p_stop = p_start + p_num * p_size
        # check program header length consistency
        if len(Elf32_Phdr()) != p_size:
            print('Invalid ELF program header size: %s' % p_size)
            return
        # map the stream to each program header
        for i in range(p_num):
            self._ph.append( Elf32_Phdr() )
            self._ph[-1].map( s[p_start+i*p_size:p_stop] )
        #
        # 2) section headers
        s_num = self[0].e_shnum()
        s_size = self[0].e_shentsize()
        s_start = self[0].e_shoff()
        s_stop = s_start + s_num * s_size
        # check section header length consistency
        if len(Elf32_Shdr()) > s_size:
            print('Invalid ELF section header size: %s' % s_size)
            return
        # map the stream to each section header
        for i in range(s_num):
            self._sh.append( Elf32_Shdr() )
            self._sh[-1].map( s[s_start+i*s_size:s_stop] )
    
    def get_program(self, ind=-1):
        if self._ph and self._stream:
            b = Block('program')
            # get all program segments
            if ind == -1:
                for ph in self._ph:
                    # program header
                    b.append( ph )
                    b[-1].set_hierarchy(0)
                    # program segment
                    b.append( program() )
                    b[-1].set_hierarchy(1)
                    b[-1].map( self._stream[b[-2].p_offset():b[-2].p_offset()+b[-2].p_filesz()] )
            # get a given program segment
            elif ind in range(len(self._ph)):
                b.append(self._ph[ind])
                b[-1].set_hierarchy(0)
                # program segment
                b.append( program() )
                b[-1].set_hierarchy(1)
                b[-1].map( self._stream[b[-2].p_offset():b[-2].p_offset()+b[-2].p_filesz()] )
            #
            return b
        #
        else:
            print('No ELF stream has been mapped yet...')
    
    def get_section(self, ind=-1):
        if self._sh and self._stream:
            b = Block('section')
            # get all sections
            if ind == -1:
                for sh in self._sh:
                    # section header
                    b.append( sh )
                    b[-1].set_hierarchy(0)
                    # section content
                    b.append( section() )
                    b[-1].set_hierarchy(1)
                    b[-1].map( self._stream[b[-2].sh_offset():b[-2].sh_offset()+b[-2].sh_size()] )
            # get a given section
            elif ind in range(len(self._sh)):
                b.append(self._sh[ind])
                b[-1].set_hierarchy(0)
                # section content
                b.append( section() )
                b[-1].set_hierarchy(1)
                b[-1].map( self._stream[b[-2].sh_offset():b[-2].sh_offset()+b[-2].sh_size()] )
            #
            return b
        #
        else:
            print('No ELF stream has been mapped yet...')
    
    def get_all(self):
        if self._sh and self._ph and self._stream:
            p = self.get_program()
            p.inc_hierarchy()
            s = self.get_section()
            s.inc_hierarchy()
            elf = Block('all')
            elf.append(self[0])
            elf.extend( p )
            elf.extend( s )
            return elf
        else:
            print('Some ELF sub-streams seem missing...')
            print('check ._ph for program header, ._sh for section header')
            return None
        
    def show(self, with_trans=False):
        elf_full = self.get_all()
        if elf_full:
            return elf_full.show(with_trans)
        else:
            return Block.show(self, with_trans)

        
# this is for program content
class program(RawLayer):
    pass
# this is for section content
class section(RawLayer):
    pass
# this is for dummy file part, unreferenced from the various elf headers
class void(RawLayer):
    pass


# ELF file global header
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
    
class Elf32_Ehdr(Layer):
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

class Elf64_Ehdr(Layer):
    constructorList = [
        e_ident(),
        Int('e_type', Pt=0, Type='uint32', Dict=e_type_dict),
        Int('e_machine', Pt=0, Type='uint32', Dict=e_machine_dict),
        Int('e_version', Pt=1, Type='uint64', Dict=e_version_dict),
        Int('e_entry', Pt=0, Type='uint64'),
        Int('e_phoff', Pt=0, Type='uint64'),
        Int('e_shoff', Pt=0, Type='uint64'),
        Int('e_flags', Pt=0, Type='uint64', Repr='hex'),
        Int('e_ehsize', Pt=0, Type='uint32'),
        Int('e_phentsize', Pt=0, Type='uint32'),
        Int('e_phnum', Pt=0, Type='uint32'),
        Int('e_shentsize', Pt=0, Type='uint32'),
        Int('e_shnum', Pt=0, Type='uint32'),
        Int('e_shstrndx', Pt=0, Type='uint32'),
        ]

# ELF program header
class Elf32_Phdr(Layer):
    constructorList = [
        Int('p_type', Pt=0, Type='uint32', Dict=p_type_dict),
        Int('p_offset', Pt=0, Type='uint32'),
        Int('p_vaddr', Pt=0, Type='uint32'),
        Int('p_paddr', Pt=0, Type='uint32'),
        Int('p_filesz', Pt=0, Type='uint32'),
        Int('p_memsz', Pt=0, Type='uint32'),
        Int('p_flags', Pt=0, Type='uint32', Dict=p_flags_dict),
        Int('p_align', Pt=0, Type='uint32'),
        ]

class Elf64_Phdr(Layer):
    constructorList = [
        Int('p_type', Pt=0, Type='uint64', Dict=p_type_dict),
        Int('p_offset', Pt=0, Type='uint64'),
        Int('p_vaddr', Pt=0, Type='uint64'),
        Int('p_paddr', Pt=0, Type='uint64'),
        Int('p_filesz', Pt=0, Type='uint64'),
        Int('p_memsz', Pt=0, Type='uint64'),
        Int('p_flags', Pt=0, Type='uint64', Dict=p_flags_dict),
        Int('p_align', Pt=0, Type='uint64'),
        ]

# ELF section header
class Elf32_Shdr(Layer):
    constructorList = [
        Int('sh_name', Pt=0, Type='uint32'),
        Int('sh_type', Pt=0, Type='uint32', Dict=sh_type_dict),
        Int('sh_flags', Pt=0, Type='uint32', Dict=sh_flags_dict),
        Int('sh_addr', Pt=0, Type='uint32'),
        Int('sh_offset', Pt=0, Type='uint32'),
        Int('sh_size', Pt=0, Type='uint32'),
        Int('sh_link', Pt=0, Type='uint32'),
        Int('sh_info', Pt=0, Type='uint32'),
        Int('sh_addralign', Pt=0, Type='uint32'),
        Int('sh_entsize', Pt=0, Type='uint32'),
        ]

class Elf64_Shdr(Layer):
    constructorList = [
        Int('sh_name', Pt=0, Type='uint64'),
        Int('sh_type', Pt=0, Type='uint64', Dict=sh_type_dict),
        Int('sh_flags', Pt=0, Type='uint64', Dict=sh_flags_dict),
        Int('sh_addr', Pt=0, Type='uint64'),
        Int('sh_offset', Pt=0, Type='uint64'),
        Int('sh_size', Pt=0, Type='uint64'),
        Int('sh_link', Pt=0, Type='uint64'),
        Int('sh_info', Pt=0, Type='uint64'),
        Int('sh_addralign', Pt=0, Type='uint64'),
        Int('sh_entsize', Pt=0, Type='uint64'),
        ]

#
