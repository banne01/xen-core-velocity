#include<stdio.h>
#include<stdint.h>
#include<errno.h>
#include<stdlib.h>
#include<string.h>
#include "xen_header.h"

#define PAGE_SIZE 4096

#define XEN_HEAD "XenSavedDomain\n"

pagebuf_t pagebuf;
pagebuf_t *buf  = &pagebuf;

int main(int argc, char*argv[])
{
    FILE *fin = fopen64(argv[1],"r");
    
    if(!fin) {
       printf(" input file error \n %s", argv[1]);    
       perror("error"); 
    }
   unsigned long p2m_size = -1 ;
   char temp[256] = {'\0'}; 
   int rc; 
   //( write_exact(io_fd, &dinfo->p2m_size, sizeof(unsigned long)) )
   //*
   // *     unsigned long    : signature == ~0UL
   //*     uint32_t	        : number of bytes remaining in extended-info
   // *
   // *     1 or more extended-info blocks of form:
   // *     char[4]          : block identifier
   // *     uint32_t         : block data size
   // *     bytes            : block data
   // *
   // *     defined extended-info blocks:
   // *     "vcpu"		: VCPU context info containing vcpu_guest_context_t.
   // *                        The precise variant of the context structure
   // *                        (e.g. 32 vs 64 bit) is distinguished by
   // *                        the block size.
   // *     "extv"           : Presence indicates use of extended VCPU context in
   // *                        tail, data size is 0.
   //   *
   //   * A series of chunks with a common header:
   //   *   int              : chunk type
   //   *
   //   * If the chunk type is +ve then chunk contains guest memory data, and
   //   * type contains the number of pages in the batch:
   //   *
   //   *     unsigned long[]  : PFN array, length == number of pages in
   //  tch
   //   *                        Each entry consists of XEN_DOMCTL_PFINFO_*
   //   *                        in bits 31-28 and the PFN number in bits
   //  -0.
   //   *     page data        : PAGE_SIZE bytes for each page marked present
   //   PFN
   //   *                        array
   //   *
   //   * If the chunk type is -ve then chunk consists of one of a number of
   //   * metadata types.  See definitions of XC_SAVE_ID_* below.
   //   *
   //   * If chunk type is 0 then body phase is complete.
   //   *

   if(fread(temp,strlen(XEN_HEAD),1,fin) < 0){
        perror("error in reading Xen Head \n"); 
        exit(1);
   }
   
   if(strncmp(temp,XEN_HEAD,strlen(XEN_HEAD) !=0 )){
        perror("Head does not match\n"); 
        exit(1);
   }

   if( fread(&(p2m_size),sizeof(unsigned long),1,fin) < 0) {
       perror("error in reading p2m_szie"); 
   }
   
   printf(" p2m_size is  %ld \n",p2m_size);
   
   int chunk = 0;
   int type =  0;
  
    buf->nr_physpages = buf->nr_pages = 0;
    buf->compbuf_pos = buf->compbuf_size = 0;

    do {
        rc = pagebuf_get_one(fin);
              
    } while (rc > 0);

    if (rc < 0)
       perror("error in reading p2m_szie"); 
    return rc;
}


#define RDEXACT(fd,buf,size) ( (rc = fread(buf,size,1,fd)) < 0 )  

#define PERROR(_m, _a...)   fprintf(stderr, "ERROR:"_m , ## _a)                     
#define DPRINTF printf

int pagebuf_get_one(FILE * fd)
{
   uint32_t t1;
   uint64_t t2;
   int count, countpages, oldcount, i;
   void* ptmp;
   int rc;
   unsigned long compbuf_size;
   static uint32_t brokenp = 0;
   static uint32_t invalidp = 0;
   static uint32_t allocp  = 0;
 
   if ( fread( &count, sizeof(count),1,fd)  < 0 ) {
       PERROR("Error when reading batch size");
       return -1;
   }
   // DPRINTF("reading batch of %d pages\n", count);
   switch ( count )
   {
   case 0:
       // DPRINTF("Last batch read\n");
       return 0;

   case XC_SAVE_ID_ENABLE_VERIFY_MODE:
       DPRINTF("Entering page verify mode\n");
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_VCPU_INFO:
       { 
           if ( RDEXACT(fd, &t1, sizeof(int)) ||
                   RDEXACT(fd, buf->vcpumap, vcpumap_sz(buf->max_vcpu_id)) ) {
               PERROR("Error when reading max_vcpu_id");
               return -1;
           }
           // DPRINTF("Max VCPU ID: %d, vcpumap: %llx\n", buf->max_vcpu_id, buf->vcpumap[0]);
           return pagebuf_get_one(fd);
       }
   case XC_SAVE_ID_HVM_IDENT_PT:
       /* Skip padding 4 bytes then read the EPT identity PT location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the address of the EPT identity map");
           return -1;
       }
       // DPRINTF("EPT identity map address: %llx\n", buf->identpt);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_PAGING_RING_PFN:
       /* Skip padding 4 bytes then read the paging ring location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the paging ring pfn");
           return -1;
       }
       // DPRINTF("paging ring pfn address: %llx\n", buf->paging_ring_pfn);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_ACCESS_RING_PFN:
       /* Skip padding 4 bytes then read the mem access ring location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the access ring pfn");
           return -1;
       }
       // DPRINTF("access ring pfn address: %llx\n", buf->access_ring_pfn);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_SHARING_RING_PFN:
       /* Skip padding 4 bytes then read the sharing ring location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the sharing ring pfn");
           return -1;
       }
       // DPRINTF("sharing ring pfn address: %llx\n", buf->sharing_ring_pfn);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_VM86_TSS:
       /* Skip padding 4 bytes then read the vm86 TSS location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the address of the vm86 TSS");
           return -1;
       }
       // DPRINTF("VM86 TSS location: %llx\n", buf->vm86_tss);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_TMEM:
       DPRINTF("xc_domain_restore start tmem\n");
       if ( xc_tmem_restore(fd) ) {
           PERROR("error reading/restoring tmem");
           return -1;
       }
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_TMEM_EXTRA:
       if ( xc_tmem_restore_extra(fd) ) {
           PERROR("error reading/restoring tmem extra");
           return -1;
       }
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_TSC_INFO: 
    {
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) ||
            RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t1, sizeof(uint32_t)) ) {
           PERROR("error reading/restoring tsc info");
           return -1;
       }
       return pagebuf_get_one(fd);
    }

   case XC_SAVE_ID_HVM_CONSOLE_PFN :
       /* Skip padding 4 bytes then read the console pfn location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the address of the console pfn");
           return -1;
       }
       // DPRINTF("console pfn location: %llx\n", buf->console_pfn);
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_LAST_CHECKPOINT:
       // DPRINTF("last checkpoint indication received");
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION:
       /* Skip padding 4 bytes then read the acpi ioport location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the acpi ioport location");
           return -1;
       }
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_HVM_VIRIDIAN:
       /* Skip padding 4 bytes then read the acpi ioport location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the viridian flag");
           return -1;
       }
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_TOOLSTACK:
       {
           uint32_t len;
           uint8_t * data;
           RDEXACT(fd, &len, sizeof(len));
           data = (uint8_t*) malloc(len*sizeof(uint8_t));
           if ( data == NULL )
           {
               PERROR("error memory allocation");
               return -1;
           }
           RDEXACT(fd, data,len);
           free(data);
           return pagebuf_get_one(fd);
       }

   case XC_SAVE_ID_ENABLE_COMPRESSION:
       /* We cannot set compression flag directly in pagebuf structure,
        * since this pagebuf still has uncompressed pages that are yet to
        * be applied. We enable the compression field in pagebuf structure
        * after receiving the first tailbuf.
        */
       printf("compression flag received\n");
       return pagebuf_get_one(fd);

   case XC_SAVE_ID_COMPRESSED_DATA:
       { 
        unsigned long compbuf_size;
       /* read the length of compressed chunk coming in */
       if ( RDEXACT(fd, &compbuf_size, sizeof(unsigned long)) ) {
           PERROR("Error when reading compbuf_size");
           return -1;
       }
       /*if (!compbuf_size) return 1;

       buf->compbuf_size += compbuf_size;
       if (!(ptmp = realloc(buf->pages, buf->compbuf_size))) {
           ERROR("Could not (re)allocate compression buffer");
           return -1;
       }
       buf->pages = ptmp;

       if ( RDEXACT(fd, buf->pages + (buf->compbuf_size - compbuf_size),
                    compbuf_size) ) {
           PERROR("Error when reading compression buffer");
           return -1;
       }*/
            printf("we dont want compression");
            return -1;
       }
   case XC_SAVE_ID_HVM_GENERATION_ID_ADDR:
       /* Skip padding 4 bytes then read the generation id buffer location. */
       if ( RDEXACT(fd, &t1, sizeof(uint32_t)) ||
            RDEXACT(fd, &t2, sizeof(uint64_t)) )
       {
           PERROR("error read the generation id buffer location");
           return -1;
       }
       DPRINTF("read generation id buffer address");
       return pagebuf_get_one(fd);

   default:
       if ( (count > MAX_BATCH_SIZE) || (count < 0) ) {
           PERROR("Max batch size exceeded (%d). Giving up.", count);
            return -1;
        }
        break;
    }
    
    oldcount = buf->nr_pages;
    buf->nr_pages += count;
    if (!buf->pfn_types) {
        if (!(buf->pfn_types = malloc(buf->nr_pages * sizeof(*(buf->pfn_types))))) {
            PERROR("Could not allocate PFN type buffer");
            return -1;
        }
    } else {
        if (!(ptmp = realloc(buf->pfn_types, buf->nr_pages * sizeof(*(buf->pfn_types))))) {
            PERROR("Could not reallocate PFN type buffer");
            return -1;
        }
        buf->pfn_types = ptmp;
    }
    if ( RDEXACT(fd, buf->pfn_types + oldcount, count * sizeof(*(buf->pfn_types)))) {
        PERROR("Error when reading region pfn types");
        return -1;
    }

    countpages = count;
    for (i = oldcount; i < buf->nr_pages; ++i)
    {
        unsigned long pagetype;

        pagetype = buf->pfn_types[i] & XEN_DOMCTL_PFINFO_LTAB_MASK;
        if (pagetype == XEN_DOMCTL_PFINFO_XTAB) {
            invalidp++; 
            --countpages;
        }
                    
        if(pagetype == XEN_DOMCTL_PFINFO_BROKEN) {
            brokenp++;
            --countpages;
        }

        
        if(pagetype == XEN_DOMCTL_PFINFO_XALLOC) {
            allocp++;
            --countpages;
        }
            
    }

    if (!countpages)
        return count;
    

    /* If Remus Checkpoint Compression is turned on, we will only be
     * receiving the pfn lists now. The compressed pages will come in later,
     * following a <XC_SAVE_ID_COMPRESSED_DATA, compressedChunkSize> tuple.
     */
    if (buf->compressing)
        return pagebuf_get_one(fd);

    oldcount = buf->nr_physpages;
    buf->nr_physpages += countpages;
    
    printf("pfn no %u , invalid %u , broken %u, xalloc  %u \n",buf->nr_physpages,
                                    invalidp,brokenp,allocp);

    if (!buf->pages) {
        if (!(buf->pages = malloc(buf->nr_physpages * PAGE_SIZE))) {
            PERROR("Could not allocate page buffer");
            return -1;
        }
    } else {
        if (!(ptmp = realloc(buf->pages, buf->nr_physpages * PAGE_SIZE))) {
            PERROR("Could not reallocate page buffer");
            return -1;
        }
        buf->pages = ptmp;
    }
    if ( RDEXACT(fd, buf->pages + oldcount * PAGE_SIZE, countpages * PAGE_SIZE) ) {
        PERROR("Error when reading pages");
        return -1;
    }
    
    return count;
}


int xc_tmem_restore(FILE* io_fd)
{
    uint32_t save_version;
    uint32_t this_max_pools, this_version;
    uint32_t pool_id;
    uint32_t minusone;
    uint32_t weight, cap, flags;
    int checksum = 0;
    int rc;

    if ( RDEXACT(io_fd, &this_version, sizeof(this_version)) )
        return -1;
    if ( RDEXACT(io_fd, &this_max_pools, sizeof(this_max_pools)) )
        return -1;
    /* FIXME check here to ensure no version mismatch or maxpools mismatch */
    if ( RDEXACT(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    if ( minusone != -1 )
        return -1;
    if ( RDEXACT(io_fd, &flags, sizeof(flags)) )
        return -1;
    if ( RDEXACT(io_fd, &weight, sizeof(weight)) )
        return -1;
    if ( RDEXACT(io_fd, &cap, sizeof(cap)) )
        return -1;
    if ( RDEXACT(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    while ( RDEXACT(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
    {
        uint64_t uuid[2];
        uint32_t n_pages;
        char *buf = NULL;
        int bufsize = 0, pagesize;
        int j;

        if ( RDEXACT(io_fd, &flags, sizeof(flags)) )
            return -1;
        if ( RDEXACT(io_fd, &n_pages, sizeof(n_pages)) )
            return -1;
        if ( RDEXACT(io_fd, &uuid, sizeof(uuid)) )
            return -1;
        if ( n_pages <= 0 )
            continue;

        pagesize = 1 << (((flags >> TMEM_POOL_PAGESIZE_SHIFT) &
                              TMEM_POOL_PAGESIZE_MASK) + 12);
        if ( pagesize > bufsize )
        {
            bufsize = pagesize;
            if ( (buf = realloc(buf,bufsize)) == NULL )
                return -1;
        }
        for ( j = n_pages; j > 0; j-- )
        {
            struct tmem_oid oid;
            uint32_t index;
            int rc;
            if ( RDEXACT(io_fd, &oid, sizeof(oid)) )
                return -1;
            if ( oid.oid[0] == -1L && oid.oid[1] == -1L && oid.oid[2] == -1L )
                break;
            if ( RDEXACT(io_fd, &index, sizeof(index)) )
                return -1;
            if ( RDEXACT(io_fd, buf, pagesize) )
                return -1;
        }
    }
    return 0;
}

/* only called for live migration, must be called after suspend */
int xc_tmem_restore_extra(FILE* io_fd)
{
    uint32_t pool_id;
    struct tmem_oid oid;
    uint32_t index;
    int count = 0;
    int checksum = 0;
    int rc;

    while ( RDEXACT(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
    {
        if ( RDEXACT(io_fd, &oid, sizeof(oid)) )
            return -1;
        if ( RDEXACT(io_fd, &index, sizeof(index)) )
            return -1;
        count++;
        checksum += pool_id + oid.oid[0] + oid.oid[1] + oid.oid[2] + index;
    }

    return 0;
}
