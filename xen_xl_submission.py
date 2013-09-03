# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2005,2006,2007 4tphi Research
#
# Authors:
# {nehal.bandi@citrix.com} (Nehal Bandi)
# Copyright (c) Citrix Systems Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above
#     copyright notice, this list of conditions and the
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the
#     following disclaimer in the documentation and/or other
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#Reference : (Xen save format is only documented in the form of source code)
# xen/tools/libxc/xg_save_restore.h
# Xen snapshot is stack of tags
# some tags are for VM memory others for different states like
# vcpu and qemu.
# To use volatility checkpoint the domain to a file
# Bash$ xl save domain checkpointfile

import volatility.obj as obj
import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

# XEN snapshot Magic
XEN_MAGIC = "Xen saved domain, xl format\n \0 \r";
SAVEFILE_BYTEORDER_VALUE = 0x01020304

#Following are tags in the snapshot
XC_SAVE_ID_ENABLE_VERIFY_MODE           = -1
XC_SAVE_ID_VCPU_INFO                    = -2
XC_SAVE_ID_HVM_IDENT_PT                 = -3
XC_SAVE_ID_HVM_VM86_TSS                 = -4
XC_SAVE_ID_TMEM                         = -5
XC_SAVE_ID_TMEM_EXTRA                   = -6
XC_SAVE_ID_TSC_INFO                     = -7
XC_SAVE_ID_HVM_CONSOLE_PFN              = -8
XC_SAVE_ID_LAST_CHECKPOINT              = -9
XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION    = -10
XC_SAVE_ID_HVM_VIRIDIAN                 = -11
XC_SAVE_ID_COMPRESSED_DATA              = -12
XC_SAVE_ID_ENABLE_COMPRESSION           = -13
XC_SAVE_ID_HVM_GENERATION_ID_ADDR       = -14
XC_SAVE_ID_HVM_PAGING_RING_PFN          = -15
XC_SAVE_ID_HVM_ACCESS_RING_PFN          = -16
XC_SAVE_ID_HVM_SHARING_RING_PFN         = -17
XC_SAVE_ID_TOOLSTACK                    = -18

## Xen PFN info
XEN_DOMCTL_PFINFO_LTAB_SHIFT    = 28
XEN_DOMCTL_PFINFO_NOTAB         = (0x0 << 28)
XEN_DOMCTL_PFINFO_XTAB          = (0xf << 28)
XEN_DOMCTL_PFINFO_XALLOC        = (0xe << 28)
XEN_DOMCTL_PFINFO_BROKEN        = (0xd << 28)
XEN_DOMCTL_PFINFO_LTAB_MASK     = (0xf << 28)


SUPERPAGE_PFN_SHIFT = 9
SUPERPAGE_NR_PFNS   = (1L << SUPERPAGE_PFN_SHIFT)

def SUPERPAGE(_pfn):
    return ((_pfn) & (~(SUPERPAGE_NR_PFNS-1)))
def SUPER_PAGE_START(pfn):
    return (((pfn) & (SUPERPAGE_NR_PFNS-1)) == 0 )


class _XEN_HEADER(obj.CType):
    """A class for XEN Header"""
    @property
    def HeaderSize(self):
        #Header size is 48
        return self.struct_size

class XenModification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            '_XEN_HEADER' : [ 48, {
                'Magic' : [ 0, ['String', dict(length = 32)]],
                'ByteOrder' : [ 32, ['unsigned int']],
                'MandatofyFlag' : [ 36, ['unsigned int']],
                'OptFlag' : [ 40, ['unsigned int']],
                'OptDataLen' : [ 44, ['unsigned int']],
            }],
        })
        profile.object_classes.update({
            '_XEN_HEADER': _XEN_HEADER
            })

class XenSnapshot(addrspace.BaseAddressSpace):
    """ This AS supports new xen snapshot format """
    """ The new format is part of xen light library """
    """ The old fomat does not have any header """

    PAGE_SIZE  = 4096
    PAGE_SHIFT = 12
    # file offset while reading
    s_offset = 0;
    # pfn to file_offset dictionary
    pfn_offsets = dict()
    # max pfn for the machine
    xen_vm_max_pfn = 0
    def __init__(self, base, config, **kwargs):
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.s_offset = 0;

        "If you are using xen with old save format remove these three lines"
        "or upgrade to the latest xen "
        self.header = obj.Object("_XEN_HEADER", offset = 0, vm = base)
        self.as_assert(self.header.Magic == XEN_MAGIC," Xen Header Mismatch")
        self.s_offset = self.s_offset + self.header.HeaderSize + self.header.OptDataLen;

        #read p2m_size first
        p2m_size = obj.Object("unsigned long", offset = self.s_offset, vm = base)
        self.s_offset = self.s_offset + p2m_size.size()

        # Read recursively all sections and pulpulate the pfn to file_offset
        while True:
            rc = self.read_pfn_list(base)
            if rc <= 0:
                break
        max_memory_len =  self.pfn_to_memory(self.xen_vm_max_pfn) + 1

        ## Tuple of (physical memory address, file offset, length)
        self.runs = []
        self.runs.append((int(0), int(0), int(max_memory_len)))

    # Convert memory to physical frame number
    def memory_to_pfn(self, mem):
        return  (mem >> self.PAGE_SHIFT )

    #from frame no to memory
    def pfn_to_memory(self, pfn):
        return (((pfn + 1 ) <<  self.PAGE_SHIFT) -1)

    # read snapshot recursive
    # We need to skip all the non-memory field
    def read_pfn_list(self, base):

        count = obj.Object("int", self.s_offset, base)
        self.s_offset = self.s_offset + count.size()
        if count == 0:
            return 0

        elif count == XC_SAVE_ID_ENABLE_VERIFY_MODE:
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_VCPU_INFO:
            self.s_offset = self.s_offset + count.size(); #max_vpuid
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_HVM_IDENT_PT:
        # Skip padding 4 bytes then read the EPT identity PT location
            self.s_offset = self.s_offset + 4 # uint32
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_HVM_VM86_TSS:
            self.s_offset = self.s_offset + 4 # uint32
            self.s_offset = self.s_offset + 8 # uint64
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_TMEM: # not in snapshot for HVM
            print ("In tmem_ID Not implemented")
            raise IOError

        elif count == XC_SAVE_ID_TMEM_EXTRA: ## not in snapshot for HVM
            print ("In tmem_ID_Extra Not implemented")
            raise IOError

        elif count == XC_SAVE_ID_TSC_INFO:
            #RDEXACT(fd, &t1, sizeof(uint32_t))
            #RDEXACT(fd, &t2, sizeof(uint64_t))
            #RDEXACT(fd, &t1, sizeof(uint32_t))
            #RDEXACT(fd, &t1, sizeof(uint32_t)))
            # Skip all the bytes read above
            self.s_offset = self.s_offset + 20
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_HVM_CONSOLE_PFN :
            #   RDEXACT(fd, &t1, sizeof(uint32_t))
            #   RDEXACT(fd, &t2, sizeof(uint64_t)))
            # Skip all the bytes read above
            self.s_offset = self.s_offset + 12
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_LAST_CHECKPOINT:
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION:
            #RDEXACT(fd, &t1, sizeof(uint32_t))
            #RDEXACT(fd, &t2, sizeof(uint64_t)))
            # Skip all the bytes read above
            self.s_offset = self.s_offset + 12
            return self.read_pfn_list(base)

        elif count == XC_SAVE_ID_HVM_VIRIDIAN:
            #RDEXACT(fd, &t1, sizeof(uint32_t))
            #RDEXACT(fd, &t2, sizeof(uint64_t)))
            # Skip all the bytes read above
            self.s_offset = self.s_offset + 12
            return self.read_pfn_list(base)

        elif  (count > 1024) or (count < 0)  :
            print ("Xen Invalid header")
            raise IOError

        pfn_array = obj.Object(theType = 'Array', offset = self.s_offset, vm = base,
                               targetType = 'unsigned long', count = count)

        self.s_offset = self.s_offset + pfn_array.size()

        # check valid pages in this bunch
        countpages = count
        for x in pfn_array:
            if self.check_pfnvalid(x) == 0:
                countpages = countpages -1;
            else :
                # update the pfn map with the location of the offset
                pfnno = (x & ~XEN_DOMCTL_PFINFO_LTAB_MASK)
                self.pfn_offsets[pfnno] =  self.s_offset
                self.s_offset = self.s_offset + self.PAGE_SIZE
                self.update_max_pfnno(pfnno,x)
        return count

    #check if this frame is valid and present
    def check_pfnvalid(self, x):
        if  ((x & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XTAB ) or
             (x  & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_XALLOC) or
             (x  & XEN_DOMCTL_PFINFO_LTAB_MASK == XEN_DOMCTL_PFINFO_BROKEN)) :
            return 0
        return 1

    # Create only a single run for all the VMs
    # the holes are filled with zeroes

    # the e820 table from xen bios looks like following
    # a typical < 4 GB VM
    # kernel: BIOS-e820: 0000000000000000 - 000000000009e000 (usable) - fixed
    # kernel: BIOS-e820: 000000000009e000 - 00000000000a0000 (reserved) - fixed
    # kernel: BIOS-e820: 00000000000e0000 - 0000000000100000 (reserved) -fixed
    # kernel: BIOS-e820: 0000000000100000 - 000000007fc00000 (usable) --grow
    # kernel: BIOS-e820: 00000000fc000000 - 0000000100000000 (reserved) --fixed
    # max pfn for this VM is ox7fc00000/0x1000

    # this is  > 4GB VM
    # kernel: BIOS-e820: 0000000000000000 - 000000000009e000 (usable) --fixed
    # kernel: BIOS-e820: 000000000009e000 - 00000000000a0000 (reserved) --> fixed
    # kernel: BIOS-e820: 00000000000e0000 - 0000000000100000 (reserved) --> fixed
    # kernel: BIOS-e820: 0000000000100000 - 00000000f0000000 (usable) -- grows with VM size
    # kernel: BIOS-e820: 00000000fc000000 - 0000000100000000 (reserved) --fixed
    # kernel: BIOS-e820: 0000000100000000 - 000000018fc00000 (usable) --grows with VM size
    # max pfn for this VM is 0x18fc00000/0x1000

    def update_max_pfnno(self, pfn, x):
        if (pfn >= 983040 and  pfn <= 984063): # xen memory
            return
        elif (pfn >= 1032192 and pfn <= 1032206): # xen memory
            return
        elif (pfn >=1044475 and pfn <= 1044479): # xen memory
            return
        elif  (pfn > self.xen_vm_max_pfn):
            #update the VM max pfn
            self.xen_vm_max_pfn = pfn
        return

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

    def is_valid_address(self, phys_addr):
        """Check if a physical address is in the file.

        @param phys_addr: a physical address
        """
        t = (self.address_out_range(phys_addr) == False)
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
    #===============================================================
    ## FIXME: read and zread are same of us
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
