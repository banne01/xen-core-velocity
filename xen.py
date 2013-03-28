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

#pylint: disable-msg=C0111

Xen_Header = "XenSavedDomain\n"

#"Folliwing are xen page frames for VM so these hole are nasty (coz some of them do
# not belong to VM memory
# we need to fill stop before them for smaller VM ro fill them
# with zeroes for Bigger Vms
# 983040 - 984063 ( 1024 pfns worth 4MB)
# 1032192 - 1032206    ( 15 pfns)
# 1044475 - 104479     ( 5 pfns)

XC_SAVE_ID_ENABLE_VERIFY_MODE = -1
XC_SAVE_ID_VCPU_INFO          = -2
XC_SAVE_ID_HVM_IDENT_PT       = -3
XC_SAVE_ID_HVM_VM86_TSS       = -4
XC_SAVE_ID_TMEM               = -5
XC_SAVE_ID_TMEM_EXTRA         = -6
XC_SAVE_ID_TSC_INFO           = -7
XC_SAVE_ID_HVM_CONSOLE_PFN    = -8
XC_SAVE_ID_LAST_CHECKPOINT    = -9
XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION  = -10
XC_SAVE_ID_HVM_VIRIDIAN       = -11
XC_SAVE_ID_COMPRESSED_DATA    = -12
XC_SAVE_ID_ENABLE_COMPRESSION = -13
XC_SAVE_ID_HVM_GENERATION_ID_ADDR = -14
XC_SAVE_ID_HVM_PAGING_RING_PFN    = -15
XC_SAVE_ID_HVM_ACCESS_RING_PFN    = -16
XC_SAVE_ID_HVM_SHARING_RING_PFN   = -17
XC_SAVE_ID_TOOLSTACK              = -18
XEN_DOMCTL_PFINFO_LTAB_SHIFT    = 28
XEN_DOMCTL_PFINFO_NOTAB         = (0x0 << 28)
XEN_DOMCTL_PFINFO_L1TAB         = (0x1 << 28)
XEN_DOMCTL_PFINFO_L2TAB         = (0x2 << 28)
XEN_DOMCTL_PFINFO_L3TAB         = (0x3 << 28)
XEN_DOMCTL_PFINFO_L4TAB         = (0x4 << 28)
XEN_DOMCTL_PFINFO_LTABTYPE_MASK = (0x7 << 28)
XEN_DOMCTL_PFINFO_LPINTAB       = (0x1 << 31)
XEN_DOMCTL_PFINFO_XTAB          = (0xf << 28)
XEN_DOMCTL_PFINFO_XALLOC        = (0xe << 28)
XEN_DOMCTL_PFINFO_BROKEN        = (0xd << 28)
XEN_DOMCTL_PFINFO_LTAB_MASK     = (0xf << 28)



class tmem_oid(obj.CType):
    """A class for VBox core dump descriptors"""
    def zero(self):
        return 0

class XenModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
                'tmem_oid' : [ 24, {
                'oid' : [ 0, ['array', 3, ['unsigned long long']]],
            }]
         })
        profile.object_classes.update({'tmem_oid': tmem_oid})

class XenSnapshot(addrspace.BaseAddressSpace):
    """ This AS supports xen snapshot format """

    PAGE_SIZE  = 4096
    PAGE_SHIFT = 12
    # file offset while reading
    s_offset   = 0;
    # pfn to file_offset list
    pfn_offsets = dict()
    # memory runs in the batch of 1024 pages
    xen_pfn_breaks = []
    # max pfn
    xen_vm_max_pfn = 0

    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)

        self.s_offset = 0;
        self.as_assert(base.read(0, len(Xen_Header)) == Xen_Header,"Xen signature invalid")
        self.s_offset = self.s_offset + len(Xen_Header);
        ## Base AS should be a file AS
        print ("Xen Signature valid")

        p2m_size = obj.Object("unsigned long", offset = self.s_offset, vm = base)

        print(p2m_size)
        print("p2m_size read")
        self.s_offset = self.s_offset + p2m_size.size()

        while True:
            rc = self.read_pfn_list(base, self.s_offset)
            if rc <= 0:
                break

        print("page reading done")

        #print self.pfn_offsets
        #for key,val in self.pfn_offsets.items():
        #    print "PFns is  " + str(key) + " Offset " + str(val)

        ## Make sure its a core dump

        max_memory_len =  self.pfn_to_memory(self.xen_vm_max_pfn) + 1
        print "Max frame no for the VM is " + str(self.xen_vm_max_pfn)
        print "Max MEMORY for the VM is " + str(max_memory_len)

        ## Tuple of (physical memory address, file offset, length)
        self.runs = []
        self.runs.append((int(0),int(0),int(max_memory_len)))
        ## The PT_NOTE core descriptor structure
        self.header = None

        #for phdr in self.program_headers():

            ## The first note should be the VBCORE segment
            #if str(phdr.p_type) == 'PT_NOTE':
            #    note = phdr.p_offset.dereference_as("elf64_note")

            #    if note.namesz == 'VBCORE' and note.n_type == NT_VBOXCORE:
            #        self.header = note.cast_descsz("DBGFCOREDESCRIPTOR")
            #    continue

            # Only keep load segments with valid file sizes
            #if (str(phdr.p_type) != 'PT_LOAD' or
            #        phdr.p_filesz == 0 or
            #        phdr.p_filesz != phdr.p_memsz):
            #    continue

            #self.runs.append((int(phdr.p_paddr),
            #                  int(phdr.p_offset),
            #                  int(phdr.p_memsz)))

        #self.as_assert(self.header, 'ELF error: did not find any PT_NOTE segment with VBCORE')
        #self.as_assert(self.header.u32Magic == DBGFCORE_MAGIC, 'Could not find VBox core magic signature')
        #self.as_assert(self.header.u32FmtVersion == DBGFCORE_FMT_VERSION, 'Unknown VBox core format version')
        #self.as_assert(self.runs, 'ELF error: did not find any LOAD segment with main RAM')

#    def tmem_restore(self,base,offset):
#
#        uint32_t save_version;
#        uint32_t pool_id;
#        uint32_t weight, cap, flags;
#        int rc;
#        offset = offset + 28 #
#    #if ( RDEXACT(io_fd, &this_version, sizeof(this_version)) )
#    #if ( RDEXACT(io_fd, &this_max_pools, sizeof(this_max_pools)) )
#    #if ( RDEXACT(io_fd, &minusone, sizeof(minusone)) )
#    #if ( RDEXACT(io_fd, &flags, sizeof(flags)) )
#    #if ( RDEXACT(io_fd, &weight, sizeof(weight)) )
#    #if ( RDEXACT(io_fd, &cap, sizeof(cap)) )
#    #if ( RDEXACT(io_fd, &minusone, sizeof(minusone)) )
#        while True:
#            pool_id = obj.Object("unsigned long", offset = self.s_offset, vm = base)
#            self.s_offset = self.s_offset + pool_id.size()
#            if pool_id == -1:
#                break
#            self.s_offset = self.s_offset + 4; #flag
#            n_pages = obj.Object("unsigned long", offset = self.s_offset, vm = base)
#            self.s_offset = self.s_offset + 4; #npages
#            self.s_offset = self.s_offset + 4; #uuuid
#
#            while n_pages > 0:
#
#
#      while ( RDEXACT(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
#    {
#        uint64_t uuid[2];
#        uint32_t n_pages;
#        char *buf = NULL;
#        int bufsize = 0, pagesize;
#        int j;
#
#        if ( RDEXACT(io_fd, &flags, sizeof(flags)) )
#            return -1;
#        if ( RDEXACT(io_fd, &n_pages, sizeof(n_pages)) )
#            return -1;
#        if ( RDEXACT(io_fd, &uuid, sizeof(uuid)) )
#            return -1;
#        if ( n_pages <= 0 )
#            continue;
#
#        pagesize = 1 << (((flags >> TMEM_POOL_PAGESIZE_SHIFT) &
#                    TMEM_POOL_PAGESIZE_MASK) + 12);
#        if ( pagesize > bufsize )
#        {
#            bufsize = pagesize;
#            if ( (buf = realloc(buf,bufsize)) == NULL )
#                return -1;
#        }
#        for ( j = n_pages; j > 0; j-- )
#        {
#            struct tmem_oid oid;
#            uint32_t index;
#            int rc;
#            if ( RDEXACT(io_fd, &oid, sizeof(oid)) )
#                return -1;
#            if ( oid.oid[0] == -1L && oid.oid[1] == -1L && oid.oid[2] == -1L )
#                break;
#            if ( RDEXACT(io_fd, &index, sizeof(index)) )
#                return -1;
#            if ( RDEXACT(io_fd, buf, pagesize) )
#                return -1;
#        }
#    }
#    return 0;
#}

    def memory_to_pfn(self, mem):
        return  (mem >> self.PAGE_SHIFT )

    def pfn_to_memory(self, pfn):
        return (((pfn + 1 ) <<  self.PAGE_SHIFT) -1)



    def read_pfn_list(self, base, offset):
        #print "read_pfn_list"
        count = obj.Object("int", self.s_offset, base)
        self.s_offset = self.s_offset + count.size()
        #print count

        if count == 0:
            return 0

        elif count == XC_SAVE_ID_TSC_INFO:
            self.s_offset = self.s_offset + 20; #TSC_INFO uin32,uin64,uin32,uint32
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_ENABLE_VERIFY_MODE:
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_VCPU_INFO:
            self.s_offset = self.s_offset + count.size(); #max_vpuid
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_HVM_IDENT_PT:
        # Skip padding 4 bytes then read the EPT identity PT location
            self.s_offset = self.s_offset + 4 # uint32
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_HVM_VM86_TSS:
            self.s_offset = self.s_offset + 4 # uint32
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_TMEM:
            #if ( xc_tmem_restore(fd) ) {
            #TBD
            print ("In tmem_ID Not implemented")
            return -1;
        elif count == XC_SAVE_ID_TMEM_EXTRA:
            #if ( xc_tmem_restore_extra(fd) ) {
            return -1;
            #return pagebuf_get_one(fd);
        elif count == XC_SAVE_ID_TSC_INFO:
            #if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            #RDEXACT(fd, &t2, sizeof(uint64_t)) ||
            #RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            #RDEXACT(fd, &t1, sizeof(uint32_t)) )
            self.s_offset = self.s_offset + 20 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_HVM_CONSOLE_PFN :
            #if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            #        RDEXACT(fd, &t2, sizeof(uint64_t)) )
            self.s_offset = self.s_offset + 12 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_LAST_CHECKPOINT:
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION:
            #if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            #        RDEXACT(fd, &t2, sizeof(uint64_t)) )
            self.s_offset = self.s_offset + 12 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif count == XC_SAVE_ID_HVM_VIRIDIAN:
            #if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            #        RDEXACT(fd, &t2, sizeof(uint64_t)) )
            self.s_offset = self.s_offset + 12 # uint64
            return self.read_pfn_list(base,self.s_offset)

        elif  (count > 1024) or (count < 0)  :
            return -1;

        else:
            pass

        pfn_array = obj.Object(theType = 'Array', offset = self.s_offset, vm = base, targetType = 'unsigned long', count = count)
        #pfns = obj.Object("pfn_array", self.s_offset, base)
        self.s_offset = self.s_offset + pfn_array.size()

        countpages = count

        for x in pfn_array:
            if self.check_pfnvalid(x) == 0:
                countpages = countpages -1;
            else :
                pfnno = (x & ~XEN_DOMCTL_PFINFO_LTAB_MASK)
                self.pfn_offsets[pfnno] =  self.s_offset
                self.s_offset = self.s_offset + self.PAGE_SIZE
                self.update_max_pfnno(pfnno)

        #print "reached at the end with count " + str(countpages)

        return count

    def check_pfnvalid(self, x):
        if  ((x & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XTAB ) or
             (x  & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XALLOC)) :
            return 0
        return 1

    def update_max_pfnno(self, pfn):
        if (pfn >= 983040 and  pfn <= 984063):
            return
        elif (pfn >= 1032192 and pfn <= 1032206):
            return
        elif (pfn >=1044475 and pfn <= 1044479):
            return
        elif  (pfn > self.xen_vm_max_pfn):
            #print "found max  " + str(pfn)
            self.xen_vm_max_pfn = pfn
        return

    #===============================================================
    ## FIXME: everything below can be abstract - shared with vmware
    #===============================================================



    def get_header(self):
        """Get the DBGFCOREDESCRIPTOR, used by vboxinfo plugin"""
        return self.header

    def get_runs(self):
        """Get the memory block info, used by vboxinfo plugin"""
        return self.runs

    def get_addr(self, addr):
        """Find the offset in the ELF64 file were a physical
        memory address can be found.

        @param addr: a physical address
        """
        "Cehck our pfn to offset map "
        #print "xen get addr "  + str((addr))
        pfn = self.memory_to_pfn(addr)
        #print "xen pfn "  + str((pfn))
        try:
            if self.pfn_offsets[pfn] != None:
                #print "Found address"
         #       print "Found Address at offset" + str((self.pfn_offsets[pfn] + addr % self.PAGE_SIZE ))
                return (self.pfn_offsets[pfn] + addr % self.PAGE_SIZE )
        except:
             pass
        #for phys_addr, file_offset, length in self.runs:
        #    if addr >= phys_addr and addr < phys_addr + length:
        #        return file_offset + (addr - phys_addr)
        #print "Not Found address" + str((addr))
        return None

    def is_valid_address(self, phys_addr):
        """Check if a physical address is in the file.

        @param phys_addr: a physical address
        """
        t =  (self.address_out_range(phys_addr) == False)
        print "is valid address" + str(t)
        return t

    def get_available_pages(self):
        page_list = []
        for phys_addr, length in self.get_available_addresses():
            start = phys_addr
            for page in range(start, start + length):
                page_list.append([page * 0x1000, 0x1000])
        return page_list

    def get_available_addresses(self):
        """Get a list of physical memory runs"""

        ## The first (and possibly the only) main memory run
        first_run_addr, _, first_run_size = self.runs[0]
        print "get_available_addresses"
        print first_run_addr
        print first_run_size
        yield (first_run_addr, first_run_size)

        ## If a system has more than 3.5 GB RAM, it will be
        ## split into multiple runs due to the VGA device mem
        ## constant VBE_DISPI_LFB_PHYSICAL_ADDRESS 0xE0000000.
        #if first_run_size == 0xE0000000:
        #    for run_addr, _, run_size in self.runs[1:]:
        #        ## not all segments above 0xE0000000 are main
        #        ## memory, try to skip those that are not.
        #        if run_addr >= 0x100000000:
        #            yield (run_addr, run_size)

    def get_address_range(self):
        """ This relates to the logical address range that is indexable """
        print "get_address_range"
        (physical_address, _, length) = self.runs[-1]
        size = physical_address + length
        return [0, size]
    def address_out_range(self, addr):
        if self.memory_to_pfn(addr) > self.xen_vm_max_pfn:
            print "error :Address out of range "
            return True
        return False
    #===============================================================
    ## FIXME: everything below can be abstract - copied from crash
    #===============================================================

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
        print " addr" + str(addr)
        print " offset" + str(baddr)
        print "length"  + str(length)
        #if baddr == None: #this is an absent page , fill zeros
        if length < first_block:
            if baddr == None:
                return '\0'*length #fille zeros
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
