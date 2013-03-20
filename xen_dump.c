#include<stdio.h>
#include<stdint.h>
#include<inttypes.h>
#include<errno.h>
#include<stdlib.h>
#include"dump_header.h"
#include <string.h>
#include<sys/stat.h>
#define PAGE_SIZE 4096

//list: ['Win2008SP1x86', 'Win7SP1x64', 'Win7SP0x64', 'Win2003SP2x86', 'Win2008R2SP1x64', 'WinXPSP3x86', 'Win2008SP2x64', 'Win2008SP1x64', 'Win2008R2SP0x64', 'Win7SP1x86', 'VistaSP1x86', 'VistaSP2x64', 'VistaSP2x86', 'Win2008SP2x86', 'Win2003SP1x86', 'Win2003SP2x64', 'Win7SP0x86', 'VistaSP0x64', 'VistaSP1x64', 'VistaSP0x86', 'Win2003SP0x86', 'Win2003SP1x64', 'WinXPSP2x64', 'WinXPSP1x64', 'WinXPSP2x86']
	

//KDGBScan {'Win2008SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win7SP1x64': '\x00\xf8\xff\xffKDBG@\x03', 'Win2003SP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2008R2SP1x64': '\x00\xf8\xff\xffKDBG@\x03', 'WinXPSP3x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02', 'Win2008SP2x64': '\x00\xf8\xff\xffKDBG0\x03', 'Win2008SP1x64': '\x00\xf8\xff\xffKDBG0\x03', 'Win2008R2SP0x64': '\x00\xf8\xff\xffKDBG@\x03', 'Win7SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG@\x03', 'VistaSP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'VistaSP2x64': '\x00\xf8\xff\xffKDBG0\x03', 'WinXPSP2x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'VistaSP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win2008SP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG0\x03', 'Win2003SP1x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2003SP2x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'Win7SP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG@\x03', 'VistaSP0x64': '\x00\xf8\xff\xffKDBG(\x03', 'Win7SP0x64': '\x00\xf8\xff\xffKDBG@\x03', 'VistaSP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG(\x03', 'Win2003SP0x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03', 'Win2003SP1x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'VistaSP1x64': '\x00\xf8\xff\xffKDBG0\x03', 'WinXPSP1x64': '\x00\xf8\xff\xffKDBG\x18\x03', 'WinXPSP2x86': '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02'}

#define WinXPSP3x86 "\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x90\x02"
//
//struct _DBGKD_DEBUG_DATA_HEADER64 { /* size 24 id 159 */
//  uint64 Flink; /* bitsize 64, bitpos 0 */
//  uint64 Blink; /* bitsize 64, bitpos 64 */
//  uint32 OwnerTag; /* bitsize 32, bitpos 128 */ ---> this is KDBG
//  uint32 Size; /* bitsize 32, bitpos 160 */
//};


#define PAGE_SHIFT 


int main(int argc, char*argv[])
{
    FILE* fin = fopen64(argv[1],"r");
    FILE* fout = fopen64(argv[2],"w");
    
    if(!fin) {
       printf(" input file error \n %s", argv[1]);    
       perror("error");
       exit(1);
    }
    
    if(!fout) {
       printf(" output file error \n %s", argv[1]);    
       perror("error");
       exit(1);
    }   
   uint8_t page_buf[4096]; 
   int read; 
   //uint8_t* prefix; 
   //uint8_t* suffix; 
   uint64_t num_pages = 0;
   uint8_t* p = NULL;
   int offset = 0;
   uint64_t kdbg_loc =0 ;
   uint64_t file_size = 0;
   int i;

   /*Look in the dump*/
   KDDEBUGGER_DATA64  kdbg_data ;
   WinDbg_Header32    header;
 
    /*read from the ram_dump
    * this is the dumbest algorithm
    * but we are just testing for one OS
    * */

   while(( read = fread(page_buf,PAGE_SIZE,1,fin)) > 0) {
        
       p = memmem(page_buf,PAGE_SIZE,WinXPSP3x86,14); 
       if (!p){ 
           num_pages++ ;    
       }      
       else {
           offset = p - page_buf ; // hard coded 
           break; 
       } 
   } 
   if(p!= NULL){

       kdbg_loc = num_pages*4096 + (uint64_t)offset -8 ; 
       printf("\n found at %"PRIx64,kdbg_loc);  
   }
   else {
       printf("Not Found");  
       exit(1); 
   }
    /*Now we have the KDBG location
     * All we need is to fill dump header  
     *
     * */
    fseeko64(fin,kdbg_loc,SEEK_SET);
    fread(&kdbg_data,sizeof(kdbg_data),1,fin);

    printf("\n KDD_DATA module list %"PRIx64,kdbg_data.PsLoadedModuleList);
    printf("\n kernel base %"PRIx64,kdbg_data.KernBase);
    printf("\n KDD_DATA pae %"PRIx16,kdbg_data.PaeEnabled);
    printf("\n KDD_DATA owner TAg %"PRIx32,kdbg_data.Header.OwnerTag);
    printf("\n KDD_DATA KPRorcessorBlock %"PRIx64,kdbg_data.KiProcessorBlock);

    /*Fill the signature*/
    
    char *signautre = &header;
    for (i = 0 ; i < sizeof(header); i= i + 4) {
        memcpy(signautre + i, "PAGE", 4); // filler
    }
    signautre = &header;
    memcpy(signautre,"PAGEDUMP",8);
    
    

    header.MajorVersion =  0x0f;//kdbg_data.MajorVersion
    header.MinorVersion =  0x0a28;//kdbg_data.MinorVersion
    header.DirectoryTableBase =  0x6f3000;//vspace.dtb We need to fill this for the CR3
    header.PfnDataBase =kdbg_data.MmPfnDatabase;
    header.PsLoadedModuleList = kdbg_data.PsLoadedModuleList;
    header.PsActiveProcessHead = kdbg_data.PsActiveProcessHead;
    header.MachineImageType =  0x14c; //kdbg_data.MachineType
    //14c for x86 and 8664 for x64
    header.PaeEnabled = kdbg_data.PaeEnabled;

    header.KdDebuggerDataBlock = kdbg_loc + 0x80000000; // virutal address offset
        
    printf("\n KDD_DATA KDDDATABLOCK %"PRIx64,header.KdDebuggerDataBlock);

    // Find the number of processors
    header.NumberProcessors = 1; //Again this is from KDD/save_image


    header.BugCheckCode = 0x00000000;
    header.BugCheckParameter[0] = 0x00000000;
    header.BugCheckParameter[1] = 0x00000000;
    header.BugCheckParameter[2] = 0x00000000;
    header.BugCheckParameter[3] = 0x00000000;
    
    memset(&(header.Regs),0, (char * )(&(header.DumpType)) - (char *)(&(header.Regs)));
    
    fseeko64(fin, 0L, SEEK_END);
     
    struct stat st;
    stat(argv[1], &st);
    file_size = st.st_size;
    num_pages = file_size/PAGE_SIZE;
    printf("\n num pages %"PRIx64,num_pages);
    printf("\n File Size %"PRIu64,file_size);
    
    header.NumberOfRuns = 0x00000001;
    header.NumberOfPages = num_pages;
    header.PhysMemRun[0].BasePage = 0x0000000000000000;
    header.PhysMemRun[0].PageCount = num_pages;
    header.RequiredDumpSpace = (num_pages + 2) *PAGE_SIZE; // header size is 2 page
   
    fwrite(&header,sizeof(header),1,fout);
    
    
    /*There is some bug in the rewind code 
     * So read again
     * */
    //fseeko64(fin,0L,SEEK_SET);
    fclose(fin);
    fin = fopen64(argv[1],"r");

   /*while(( read = fread(page_buf,PAGE_SIZE,1,fin)) > 0) {

      if(read = (fwrite(page_buf,PAGE_SIZE,1,fout)) < 0) {
            perror("error writing file");
            exit(1);
      }
    }*/

     while ((i = fread(page_buf, sizeof(char), PAGE_SIZE, fin)) > 0)
    {
        if (fwrite(page_buf, sizeof(char), i, fout) != i) {
                perror("write failed\n");
                 
            }
    }

return 0;
}


