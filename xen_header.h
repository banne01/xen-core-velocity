#ifndef _XEN_HEADER_H
#define _XEN_HEADER_H

#define XC_SAVE_ID_ENABLE_VERIFY_MODE -1 /* Switch to validation phase. */
#define XC_SAVE_ID_VCPU_INFO          -2 /* Additional VCPU info */
#define XC_SAVE_ID_HVM_IDENT_PT       -3 /* (HVM-only) */
#define XC_SAVE_ID_HVM_VM86_TSS       -4 /* (HVM-only) */
#define XC_SAVE_ID_TMEM               -5
#define XC_SAVE_ID_TMEM_EXTRA         -6
#define XC_SAVE_ID_TSC_INFO           -7
#define XC_SAVE_ID_HVM_CONSOLE_PFN    -8 /* (HVM-only) */
#define XC_SAVE_ID_LAST_CHECKPOINT    -9 /* Commit to restoring after completion of current iteration. */
#define XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION -10
#define XC_SAVE_ID_HVM_VIRIDIAN       -11
#define XC_SAVE_ID_COMPRESSED_DATA    -12 /* Marker to indicate arrival of compressed data */
#define XC_SAVE_ID_ENABLE_COMPRESSION -13 /* Marker to enable compression logic at receiver side */
#define XC_SAVE_ID_HVM_GENERATION_ID_ADDR -14
/* Markers for the pfn's hosting these mem event rings */
#define XC_SAVE_ID_HVM_PAGING_RING_PFN  -15
#define XC_SAVE_ID_HVM_ACCESS_RING_PFN  -16
#define XC_SAVE_ID_HVM_SHARING_RING_PFN -17
#define XC_SAVE_ID_TOOLSTACK          -18 /* Optional toolstack specific info */

/*
** We process save/restore/migrate in batches of pages; the below
** determines how many pages we (at maximum) deal with in each batch.
*/
#define MAX_BATCH_SIZE 1024   /* up to 1024 pages (4MB) at a time */

/* When pinning page tables at the end of restore, we also use batching. */
#define MAX_PIN_BATCH  1024

/* Maximum #VCPUs currently supported for save/restore. */
#define XC_SR_MAX_VCPUS 4096
#define vcpumap_sz(max_id) (((max_id)/64+1)*sizeof(uint64_t))


struct toolstack_data_t {
    uint8_t *data;
    uint32_t len;
};


typedef struct {
    void* pages;
    /* pages is of length nr_physpages, pfn_types is of length nr_pages */
    unsigned int nr_physpages, nr_pages;

    /* checkpoint compression state */
    int compressing;
    unsigned long compbuf_pos, compbuf_size;

    /* Types of the pfns in the current region */
    unsigned long* pfn_types;

    int verify;

    int new_ctxt_format;
    int max_vcpu_id;
    uint64_t vcpumap[XC_SR_MAX_VCPUS/64];
    uint64_t identpt;
    uint64_t paging_ring_pfn;
    uint64_t access_ring_pfn;
    uint64_t sharing_ring_pfn;
    uint64_t vm86_tss;
    uint64_t console_pfn;
    uint64_t acpi_ioport_location;
    uint64_t viridian;
    uint64_t vm_generationid_addr;

    struct toolstack_data_t tdata;
} pagebuf_t;

struct tmem_oid {
   uint64_t oid[3];
};

#define XEN_DOMCTL_PFINFO_LTAB_SHIFT 28
#define XEN_DOMCTL_PFINFO_NOTAB   (0x0U<<28)
#define XEN_DOMCTL_PFINFO_L1TAB   (0x1U<<28)
#define XEN_DOMCTL_PFINFO_L2TAB   (0x2U<<28)
#define XEN_DOMCTL_PFINFO_L3TAB   (0x3U<<28)
#define XEN_DOMCTL_PFINFO_L4TAB   (0x4U<<28)
#define XEN_DOMCTL_PFINFO_LTABTYPE_MASK (0x7U<<28)
#define XEN_DOMCTL_PFINFO_LPINTAB (0x1U<<31)
#define XEN_DOMCTL_PFINFO_XTAB    (0xfU<<28) /* invalid page */
#define XEN_DOMCTL_PFINFO_XALLOC  (0xeU<<28) /* allocate-only page */
#define XEN_DOMCTL_PFINFO_BROKEN  (0xdU<<28) /* broken page */
#define XEN_DOMCTL_PFINFO_LTAB_MASK (0xfU<<28)


#define TMEM_SPEC_VERSION          1
/* Commands to HYPERVISOR_tmem_op() */
#define TMEM_CONTROL               0
#define TMEM_NEW_POOL              1
#define TMEM_DESTROY_POOL          2
#define TMEM_NEW_PAGE              3
#define TMEM_PUT_PAGE              4
#define TMEM_GET_PAGE              5
#define TMEM_FLUSH_PAGE            6
#define TMEM_FLUSH_OBJECT          7
#define TMEM_READ                  8
#define TMEM_WRITE                 9
#define TMEM_XCHG                 10

/* Privileged commands to HYPERVISOR_tmem_op() */
#define TMEM_AUTH                 101
#define TMEM_RESTORE_NEW          102

/* Subops for HYPERVISOR_tmem_op(TMEM_CONTROL) */
#define TMEMC_THAW                   0
#define TMEMC_FREEZE                 1
#define TMEMC_FLUSH                  2
#define TMEMC_DESTROY                3
#define TMEMC_LIST                   4
#define TMEMC_SET_WEIGHT             5
#define TMEMC_SET_CAP                6
#define TMEMC_SET_COMPRESS           7
#define TMEMC_QUERY_FREEABLE_MB      8
#define TMEMC_SAVE_BEGIN             10
#define TMEMC_SAVE_GET_VERSION       11
#define TMEMC_SAVE_GET_MAXPOOLS      12
#define TMEMC_SAVE_GET_CLIENT_WEIGHT 13
#define TMEMC_SAVE_GET_CLIENT_CAP    14
#define TMEMC_SAVE_GET_CLIENT_FLAGS  15
#define TMEMC_SAVE_GET_POOL_FLAGS    16
#define TMEMC_SAVE_GET_POOL_NPAGES   17
#define TMEMC_SAVE_GET_POOL_UUID     18
#define TMEMC_SAVE_GET_NEXT_PAGE     19
#define TMEMC_SAVE_GET_NEXT_INV      20
#define TMEMC_SAVE_END               21
#define TMEMC_RESTORE_BEGIN          30
#define TMEMC_RESTORE_PUT_PAGE       32
#define TMEMC_RESTORE_FLUSH_PAGE     33

/* Bits for HYPERVISOR_tmem_op(TMEM_NEW_POOL) */
#define TMEM_POOL_PERSIST          1
#define TMEM_POOL_SHARED           2
#define TMEM_POOL_PRECOMPRESSED    4
#define TMEM_POOL_PAGESIZE_SHIFT   4
#define TMEM_POOL_PAGESIZE_MASK  0xf
#define TMEM_POOL_VERSION_SHIFT   24
#define TMEM_POOL_VERSION_MASK  0xff
#define TMEM_POOL_RESERVED_BITS  0x00ffff00

/* Bits for client flags (save/restore) */
#define TMEM_CLIENT_COMPRESS       1
#define TMEM_CLIENT_FROZEN         2

/* Special errno values */
#define EFROZEN                 1000
#define EEMPTY                  1001

#endif
