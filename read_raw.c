#include<stdio.h>
#include<stdint.h>
#include<errno.h>
#include<stdlib.h>

#define PAGE_SIZE 4096
int main(int argc, char*argv[])
{
    FILE* fin = fopen64(argv[1],"r");
    
    if(!fin) {
       printf(" input file error \n %s", argv[1]);    
       perror("error"); 
    }
    FILE* fout = fopen64(argv[2],"w");
    
    if(!fout) {
       printf(" out file error %s \n ",argv[2]);    
    }
   
   if(fseek(fin,0x3000,SEEK_SET) < 0) {
       printf(" seek input file error \n ");    
   }   
   char page_buf[4096]; 
    
   uint64_t sec_size = 0xffff4000;
   int num_page =  (sec_size/PAGE_SIZE);
   size_t read; 
   while(num_page) {
        num_page--; 
        if((read = fread(page_buf,PAGE_SIZE,1,fin)) < 0) {
         printf("Error reading page %d ",read);
         exit(1);
        }
            
        if((fwrite(page_buf,PAGE_SIZE,1,fout)) < 0) {
         perror("Error writing page");
         exit(1);
        }
   } 
}
