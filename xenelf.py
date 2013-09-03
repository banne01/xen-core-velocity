# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors: 
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# phil@teuwen.org (Philippe Teuwen)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
# References:
# VirtualBox core format: 
#     http://www.virtualbox.org/manual/ch12.html#guestcoreformat
#     http://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h
#     http://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/DBGFCoreWrite.cpp

import volatility.obj as obj
import volatility.addrspace as addrspace
import math
from ctypes import c_ulonglong
# pylint: disable-msg=C0111

NT_VBOXCORE = 0xb00
NT_VBOXCPU = 0xb01
DBGFCORE_MAGIC = 0xc01ac0de
DBGFCORE_FMT_VERSION = 0x00010000
XEN_ELFNOTE_DUMPCORE_NONE = 0x2000000
XEN_ELFNOTE_DUMPCORE_HEADER = 0x2000001
XEN_ELFNOTE_DUMPCORE_XEN_VERSION = 0x2000002
XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION = 0x2000003

XEN_VERSION_DESC_SIZE = 1276
XEN_ELF_HEADER_DESC_SIZE = 32
XEN_FORMAT_VERSION_DESC_SIZE = 8
XEN_ELFNOTE_DESC_SIZE = 16

class XEN_ELF_HEADER_DESC(obj.CType):
    pass
    
class XenElfModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'XEN_ELF_HEADER_DESC' : [ 32, {
                'xch_magic' : [ 0, ['unsigned long long']],
                'xch_nr_cpu' : [ 8, ['unsigned long long']],
                'xch_nr_pages' : [ 16, ['unsigned long long']],
                'xch_page_size' : [ 24, ['unsigned long long']],
            }]})
        profile.object_classes.update({'XEN_ELF_HEADER_DESC': XEN_ELF_HEADER_DESC})
        
# struct xen_dumpcore_elfnote_xen_version_desc {
# 62    uint64_t                    major_version;
# 63    uint64_t                    minor_version;
# 64    xen_extraversion_t   char 16       extra_version;
# 65    xen_compile_info_t    8 byte      compile_info;
# 66    xen_capabilities_info_t  char[1024]   capabilities;
# 67    xen_changeset_info_t     char[64]   changeset;
# 68    xen_platform_parameters_t 8byte  platform_parameters;
# 69    uint64_t                  8 byte  pagesize;
# 70};
# struct xen_dumpcore_elfnote_header_desc {
#    uint64_t    xch_magic;
#    uint64_t    xch_nr_vcpus;
#    uint64_t    xch_nr_pages;
#   uint64_t    xch_page_size;
# };

# 40struct elfnote {
# 41    uint32_t    namesz; /* Elf_Note note; */
# 42    uint32_t    descsz;
# 43    uint32_t    type;
# 44    char        name[4]; /* sizeof("Xen") = 4

      

# Section Headers:
#  [Nr] Name              Type             Address           Offset        Size              EntSize          Flags  Link  Info  Align
#  [ 0]                   NULL             0000000000000000  00000000      0000000000000000  0000000000000000           0     0     0
#  [ 1] .shstrtab         STRTAB           0000000000000000  200f7fa8      0000000000000048  0000000000000000           0     0     0
#  [ 2] .note.Xen         NOTE             0000000000000000  00000200      0000000000000564  0000000000000000           0     0     0
#  [ 3] .xen_prstatus     PROGBITS         0000000000000000  00000764      0000000000001430  0000000000001430           0     0     8
#  [ 4] .xen_shared_info  PROGBITS         0000000000000000  00001b94      0000000000001000  0000000000001000           0     0     8
#  [ 5] .xen_pages        PROGBITS         0000000000000000  00003000      000000001fff5000  0000000000001000           0     0     4096
#  [ 6] .xen_pfn          PROGBITS         0000000000000000  1fff8000      00000000000fffa8  0000000000000008           0     0     8

class XenCoreDumpElf64(addrspace.AbstractRunBasedMemory):
    """ This AS supports VirtualBox ELF64 coredump format """

   
    def print_section(self, shdr, no):
        print ("section " + str(no))
        print ("\t xen sh_name " + str(shdr.sh_name))
        print ("\t xen sh_type " + str(shdr.sh_type))
        print ("\t xen sh_flags " + str(shdr.sh_flags))
        print ("\t xen sh_addr " + str(shdr.sh_addr))
        print ("\t xen sh_offset " + str(shdr.sh_offset))
        print ("\t xen sh_size " + str(shdr.sh_size))
        print ("\t xen sh_link " + str(shdr.sh_link))
        print ("\t xen sh_info " + str(shdr.sh_info))
        print ("\t xen sh_addralign " + str(shdr.sh_addralign))
        print ("\t xen sh_entsize " + str(shdr.sh_entsize))
        
    def __init__(self, base, config, **kwargs):
        # # We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)

        # # Quick test (before instantiating an object) 
        # # for ELF64, little-endian - ELFCLASS64 and ELFDATA2LSB
        self.as_assert(base.read(0, 6) == '\x7fELF\x02\x01',
                       "ELF64 Header signature invalid")

        # # Base AS should be a file AS
        elf = obj.Object("elf64_hdr", offset=0, vm=base)

        # # Make sure its a core dump
        self.as_assert(str(elf.e_type) == 'ET_CORE',
                       "ELF64 type is not a Core file")

        # # Tuple of (physical memory address, file offset, length)
        self.runs = []

        # # The PT_NOTE core descriptor structure 
        #self.self.header = None
        self.PAGE_SIZE = 0
        self.PAGE_SHIFT = 0
        self.xen_mem_offset = 0
        self.pfn_offsets = dict()
        self.xen_vm_max_pfn = 0;

        print (" Xen elf header ")
        print ("xen phdr_type " + str(elf.e_phnum))
        print ("xen shdr_type " + str(elf.e_shnum))
        
        i = 0;
        for shdr in elf.section_headers():
            i = i + 1;   
            # We Need to parse all descriptors   
            #   elfnote_dump_none
            # /* elf note section: xen version */   
            # /* elf note section: format version */
    
            if i == 3:  # '.xen.Note Section '
                # note = shdr.sh_offset.dereference_as("elf64_note")
                self.print_section(shdr, i)
                offset = shdr.sh_offset
                note = obj.Object("elf64_note", offset, vm=base)
                if note != None:
                    print ("\t name for note " + note.namesz)
                    print ("\t size of note " + str(note.n_descsz))
                    
                if note.namesz == 'Xen\0' and note.n_type == XEN_ELFNOTE_DUMPCORE_NONE:
                    print (" \t found xen note none header ")
                    
                offset = offset + XEN_ELFNOTE_DESC_SIZE
                    
                note_dhead = obj.Object("elf64_note", offset, vm=base)
            
                if note_dhead != None:
                    print ("\t name for note " + note_dhead.namesz)
                    print ("\t size of note " + str(note_dhead.n_descsz))
                    print ("\t size of note " + str(hex(note_dhead.n_type)))
                    
                if note_dhead.n_type == XEN_ELFNOTE_DUMPCORE_HEADER:
                    print (" \t found xen note Dumpcore header ")
                else:
                    print (" \t Warning dumpcore header missing fron .xen.Note ")
                    return
                    
                offset = offset + XEN_ELFNOTE_DESC_SIZE     
                
                hdr_desc = obj.Object("XEN_ELF_HEADER_DESC", offset, vm=base)
                if hdr_desc != None:
                    print ("\t header magic %0X" % hdr_desc.xch_magic)
                    print ("\t dom cpus  %0X" % hdr_desc.xch_nr_cpu)
                    print ("\t dom pages %d " % hdr_desc.xch_nr_pages)
                    print ("\t dom page size %d " % hdr_desc.xch_page_size)
                    
                    # we are only interseted in nr pages 
                    self.PAGE_SIZE = hdr_desc.xch_page_size
                    self.PAGE_SHIFT = int(math.log(self.PAGE_SIZE,2))
                    #self.mem_offset = shdr.sh_offset  
                    self.xen_vm_max_pfn = hdr_desc.xch_nr_pages 
                continue
            if i == 6:
                self.xen_mem_offset = shdr.sh_offset 
                print ("\t memory offset %0X" % self.xen_mem_offset)
            if i == 7:
                self.print_section(shdr, i)
                pfn_offset = shdr.sh_offset
                page_offset = self.xen_mem_offset 
                while pfn_offset < (shdr.sh_offset + shdr.sh_size):
                    pfn = obj.Object("unsigned long long", pfn_offset, vm=base)
                    #print ("pnf "+ str(pfn))
                    pfnno = int(pfn)
                    self.pfn_offsets[pfnno] = page_offset
                    pfn_offset = pfn_offset + 8
                    page_offset = page_offset + self.PAGE_SIZE
     
        max_memory_len =  self.pfn_to_memory(self.xen_vm_max_pfn) + 1
        ## Tuple of (physical memory address, file offset, length)
        self.runs = []
        self.runs.append((int(0), int(0), int(max_memory_len)))
             
        #self.as_assert(self.hdr_desc, 'ELF error: did not find any PT_NOTE segment with XEN_ELF_HEADER_DESC')
        # self.as_assert(self.header.xch_magic == DBGFCORE_MAGIC, 'Could not find VBox core magic signature')
        # self.as_assert(self.header.u32FmtVersion == DBGFCORE_FMT_VERSION, 'Unknown VBox core format version')
        self.as_assert(self.runs, 'ELF error: did not find any LOAD segment with main RAM')
        
    # Convert memory to physical frame number

    def is_valid_address(self, phys_addr):
        """Check if a physical address is in the file.

        @param phys_addr: a physical address
        """
        t = (self.address_out_range(phys_addr) == False)
        return t
    
    def memory_to_pfn(self, mem):
        return  (mem >> self.PAGE_SHIFT )

    #from frame no to memory
    def pfn_to_memory(self, pfn):
        return (((pfn + 1 ) <<  self.PAGE_SHIFT) -1)

    def get_header(self):
        return None

    def get_runs(self):
        """Get the memory block info this is just one run from 0 to max memory"""
        return self.runs

    def get_addr(self, addr):
        """Find the offset in pfn map file were a physical
        memory address can be found.
        @param addr: a physical address
        """
        #Check our pfn to offset map
        pfn = self.memory_to_pfn(addr)      
        try:
            if self.pfn_offsets[pfn] != None:
                return (self.pfn_offsets[pfn] + addr % self.PAGE_SIZE )
        except:
            pass
        return None

    def get_available_pages(self):
        page_list = []
        for phys_addr, length in self.get_available_addresses():
            start = phys_addr
            for page in range(start, start + length):
                page_list.append([page * 0x1000, 0x1000])
        return page_list
    
    def get_available_addresses(self):
        """Get a list of physical memory runs"""
        ## The first and only memory run
        first_run_addr, _, first_run_size = self.runs[0]
        yield (first_run_addr, first_run_size)

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        print "get_address_range"
        (physical_address, _, length) = self.runs[-1]
        size = physical_address + length
        return [0, size]

    def address_out_range(self, addr):
        if self.memory_to_pfn(addr) > self.xen_vm_max_pfn:
            return True
        return False
    
    def read(self, addr, length):
        """Read data.

        @param addr: the physical memory base address
        @param length: number of bytes to read from phys_addr
        """
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000

        if  self.address_out_range(addr):
            return obj.NoneObject("Could not get base address at " + str(addr))

        baddr = self.get_addr(addr)
        #if baddr is None this is an absent page, might be a hole or xen did
        #not write this to snapshot fill zeroes
        if length < first_block:
            if baddr == None:
                return '\0'*length #fill zeros
            else:
                stuff_read = self.base.read(baddr, length)
            return stuff_read

        if baddr == None:
            stuff_read = '\0'*first_block
        else:
            stuff_read = self.base.read(baddr, first_block)

        new_addr = addr + first_block
        for _i in range(0, full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + '0'*0X1000
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)
            new_addr = new_addr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + '0'*left_over
            else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)

        return stuff_read

    def check_address_range(self, addr):
        if self.memory_to_pfn(addr) > self.xen_vm_max_pfn:
            raise IOError

    def zread(self, addr, length):
        first_block = 0x1000 - addr % 0x1000
        full_blocks = ((length + (addr % 0x1000)) / 0x1000) - 1
        left_over = (length + addr) % 0x1000

        self.check_address_range(addr)

        baddr = self.get_addr(addr)

        if baddr == None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)
        else:
            if length < first_block:
                return self.base.read(baddr, length)
            stuff_read = self.base.read(baddr, first_block)

        new_addr = addr + first_block
        for _i in range(0, full_blocks):
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.read(baddr, 0x1000)

            new_addr = new_addr + 0x1000

        if left_over > 0:
            baddr = self.get_addr(new_addr)
            if baddr == None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.read(baddr, left_over)
        return stuff_read

    