//
//  mpfr.c
//  Mach-O Prettifier
//
//  Copyright (c) 2014 Cai, Zhi-Wei. All rights reserved.
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// -----------------------------------------------------------------------
//
// To compile: clang mpfr.c -O2 -o mpfr
//

#define VERSION "0.1"

#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct sectionInfo {
    struct section *location;
    struct section section;
};

struct sectionInfo_64 {
    struct section_64 *location64;
    struct section_64 section64;
};

int main(int argc, char *argv[]) {
    
    printf("\n"
           "\n\t"
           " ███▄ ▄███▓ ▄▄▄       ▄████▄   ██░ ██  ▒█████                            \n\t"
           "▓██▒▀█▀ ██▒▒████▄    ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒       Version %s        \n\t"
           "▓██    ▓██░▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒                          \n\t"
           "▒██    ▒██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░    Copyright © 2014      \n\t"
           "▒██▒   ░██▒ ▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░                          \n\t"
           "░ ▒░   ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░       Cai, Zhi-Wei        \n\t"
           "░  ░      ░  ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░  ░ ▒ ▒░                           \n\t"
           "░      ░     ░   ▒   ░         ░  ░░ ░░ ░ ░ ▒      - http://one.vg/ -    \n\t"
           "       ░         ░  ░░ ░       ░  ░  ░    ░ ░                            \n\t"
           "                     ░                                                   \n\t"
           " ██▓███   ██▀███  ▓█████▄▄▄█████▓▄▄▄█████▓ ██▓  █████▒██▓▓█████  ██▀███  \n\t"
           "▓██░  ██▒▓██ ▒ ██▒▓█   ▀▓  ██▒ ▓▒▓  ██▒ ▓▒▓██▒▓██   ▒▓██▒▓█   ▀ ▓██ ▒ ██▒\n\t"
           "▓██░ ██▓▒▓██ ░▄█ ▒▒███  ▒ ▓██░ ▒░▒ ▓██░ ▒░▒██▒▒████ ░▒██▒▒███   ▓██ ░▄█ ▒\n\t"
           "▒██▄█▓▒ ▒▒██▀▀█▄  ▒▓█  ▄░ ▓██▓ ░ ░ ▓██▓ ░ ░██░░▓█▒  ░░██░▒▓█  ▄ ▒██▀▀█▄  \n\t"
           "▒██▒ ░  ░░██▓ ▒██▒░▒████▒ ▒██▒ ░   ▒██▒ ░ ░██░░▒█░   ░██░░▒████▒░██▓ ▒██▒\n\t"
           "▒▓▒░ ░  ░░ ▒▓ ░▒▓░░░ ▒░ ░ ▒ ░░     ▒ ░░   ░▓   ▒ ░   ░▓  ░░ ▒░ ░░ ▒▓ ░▒▓░\n\t"
           "░▒ ░       ░▒ ░ ▒░ ░ ░  ░   ░        ░     ▒ ░ ░      ▒ ░ ░ ░  ░  ░▒ ░ ▒░\n\t"
           "░░         ░░   ░    ░    ░        ░       ▒ ░ ░ ░    ▒ ░   ░     ░░   ░ \n\t"
           "            ░        ░  ░                  ░          ░     ░  ░   ░     \n\t"
           "                                                                         \n\t"
           "\n\n\n", VERSION);
    
    if (argc < 2) {
        
        printf("usage: mpfr target_file\n");
        
        return 0;
    }
    
    int                         fd;
    struct stat                 stat_buf;
    size_t                      size;
    
    char                        *addr           = NULL;
    struct fat_arch             *fa;
    struct fat_header           *fh;
    struct mach_header          *mh;
    struct mach_header_64       *mh64;
    struct load_command         *lc;
    
    uint32_t mm;
    uint32_t err;
    
    fd   = open(argv[1], O_RDWR);
    fstat(fd, &stat_buf);
    size = stat_buf.st_size;
    addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
    mm   = *(uint32_t *)(addr);
    
    printf("* MH_MAGIC:      %04X\n", mm);
    
    switch(mm) {
        case MH_MAGIC:
            mh   = (struct mach_header *)addr;
            addr += sizeof(struct mach_header);
            
            printf("* Architecture:  i386\n");
            printf("* Load Commands: %d\n", mh->ncmds);
            
            for (int i = 0; i < mh->ncmds; i++) {
                lc = (struct load_command *)addr;
                
                if (lc->cmd == LC_SEGMENT) {
                    struct segment_command *segmentCommand = (struct segment_command *)(lc);
                    struct section *section                = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                    struct sectionInfo allsections[segmentCommand->nsects];
                    for (uint32_t x = 0; x < segmentCommand->nsects; x++) {
                        allsections[x].location = section;
                        memcpy(&allsections[x].section, section, sizeof(struct section));
                        section++;
                    }
                    
                    int k, j, n = segmentCommand->nsects;
                    struct sectionInfo tmp;
                    for (k = 1; k < n; k++) {
                        for (j = 0; j < n - k; j++) {
                            if(allsections[j].section.addr > allsections[j+1].section.addr) {
                                tmp              = allsections[j];
                                allsections[j]   = allsections[j+1];
                                allsections[j+1] = tmp;
                            }
                        }
                    }
                    
                    section                   = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                    for (uint32_t x           = 0; x < segmentCommand->nsects; x++) {
                        memcpy(section, &allsections[x].section, sizeof(struct section));
                        section++;
                    }

                    uint32_t entropy          = 0;
                    section                   = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                    struct section *section_b = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                    section_b++;
                    for (uint32_t x = 0; x < segmentCommand->nsects; x++) {
                        if (strncmp(segmentCommand->segname, SEG_TEXT, 16) == 0 || strncmp(segmentCommand->segname, SEG_DATA, 16) == 0) {
                            printf(" * Checking: %s:%s\n", section->segname, section->sectname);
                            if (strncmp(section->sectname, "__mod_init_func", 16) != 0) {
                                if (strncmp(section->segname, segmentCommand->segname, 16) != 0) {
                                    printf("      > Fix: Section\t \"%s\"\t -> \t\"%s\"\n", section->segname, segmentCommand->segname);
                                    memcpy(section->segname, segmentCommand->segname, 16);
                                }
                                entropy = section->addr - segmentCommand->vmaddr + segmentCommand-> fileoff;
                                entropy &= 0xffffffff;
                                if (entropy > 0x7fffffff) entropy = 0;
                                if((section->offset & 0xffffffff) != entropy) {
                                    printf("      > Fix: Offset\t 0x%016x\t -> \t0x%016x\n", section->offset, entropy);
                                    section->offset = entropy;
                                    if(x == segmentCommand->nsects - 1) {
                                        entropy = segmentCommand->fileoff + segmentCommand->filesize - section->addr;
                                    } else {
                                        entropy = section_b->addr - section->addr;
                                    }
                                    if (entropy > 0x7fffffff) entropy = 0;
                                    printf("      > Fix: Size\t 0x%016x\t -> \t0x%016x\n", section->size, entropy);
                                    section->size = entropy;
                                }
                            }
                        }
                        section++;
                        section_b++;
                    }
                }
                addr += lc->cmdsize;
            }
            msync(addr, size, MS_ASYNC);
            break;
        case MH_MAGIC_64:
            mh64 = (struct mach_header_64 *)addr;
            addr += sizeof(struct mach_header_64);
            
            printf("* Architecture:  x86_64\n");
            printf("* Load Commands: %d\n", mh64->ncmds);
            
            for (int i = 0; i < mh64->ncmds; i++) {
                lc = (struct load_command *)addr;
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *segmentCommand64 = (struct segment_command_64 *)(lc);
                    struct section_64 *section64                = (struct section_64 *)((uint8_t*)segmentCommand64 + sizeof(struct segment_command_64));
                    struct sectionInfo_64 allsections64[segmentCommand64->nsects];
                    for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                        allsections64[x].location64 = section64;
                        memcpy(&allsections64[x].section64, section64, sizeof(struct section_64));
                        section64++;
                    }
                    
                    int k, j, n = segmentCommand64->nsects;
                    struct sectionInfo_64 tmp;
                    for (k = 1; k < n; k++) {
                        for (j = 0; j < n - k; j++) {
                            if(allsections64[j].section64.addr > allsections64[j+1].section64.addr) {
                                tmp                = allsections64[j];
                                allsections64[j]   = allsections64[j+1];
                                allsections64[j+1] = tmp;
                            }
                        }
                    }
                    
                    section64 = (struct section_64 *)((uint8_t*)segmentCommand64 + sizeof(struct segment_command_64));
                    for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                        memcpy(section64, &allsections64[x].section64, sizeof(struct section_64));
                        section64++;
                    }
                    
                    uint32_t entropy = 0;
                    section64                      = (struct section_64 *)((char*)segmentCommand64 + sizeof(struct segment_command_64));
                    struct section_64 *section64_b = (struct section_64 *)((char*)segmentCommand64 + sizeof(struct segment_command_64));
                    section64_b++;
                    for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                        if (strncmp(segmentCommand64->segname, SEG_TEXT, 16) == 0 || strncmp(segmentCommand64->segname, SEG_DATA, 16) == 0) {
                            printf(" * Checking: %s:%s\n", section64->segname, section64->sectname);
                            if (strncmp(section64->sectname, "__mod_init_func", 16) != 0) {
                                if (strncmp(section64->segname, segmentCommand64->segname, 16) != 0) {
                                    printf("      > Fix: Section\t \"%s\"\t -> \t\"%s\"\n", section64->segname, segmentCommand64->segname);
                                    memcpy(section64->segname, segmentCommand64->segname, 16);
                                }
                                entropy = section64->addr - segmentCommand64->vmaddr + segmentCommand64-> fileoff;
                                entropy &= 0xffffffff;
                                if (entropy > 0x7fffffff) entropy = 0;
                                if((section64->offset & 0xffffffff) != entropy) {
                                    printf("      > Fix: Offset\t 0x%016x\t -> \t0x%016x\n", section64->offset, entropy);
                                    section64->offset = entropy;
                                    if(x == segmentCommand64->nsects - 1) {
                                        entropy = segmentCommand64->fileoff + segmentCommand64->filesize - section64->addr;
                                    } else {
                                        entropy = section64_b->addr - section64->addr;
                                    }
                                    if (entropy > 0x7fffffff) entropy = 0;
                                    printf("      > Fix: Size\t 0x%016llx\t -> \t0x%016x\n", section64->size, entropy);
                                    section64->size = entropy;
                                }
                            }
                        }
                        section64++;
                        section64_b++;
                    }
                }
                addr += lc->cmdsize;
            }
            msync(addr, size, MS_ASYNC);
            break;
        case FAT_CIGAM:
            fh = (struct fat_header *)addr;
            uint32_t i = 0, nfat_arch = OSSwapBigToHostInt32(fh->nfat_arch);
            
            printf("* Mach-O Type: Fat\n");
            printf("* Architectures: %x\n", nfat_arch);
            
            fa = (struct fat_arch *)(addr + sizeof(struct fat_header));
            for(;nfat_arch-- > 0; fa++) {
                
                uint32_t offset, cputype;
                cputype        = OSSwapBigToHostInt32(fa->cputype);
                offset         = OSSwapBigToHostInt32(fa->offset);
                char *addrTemp = NULL;
                
                switch(cputype) {
                    case 0x7: // 32bit
                        
                        addrTemp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
                        mh       = (struct mach_header *)(addrTemp + offset);
                        addrTemp += sizeof(struct mach_header) + offset;
                        
                        printf("* MH_MAGIC:      %04X\n\t", mh->magic);
                        printf("* Load Commands: %d\n\t", mh->ncmds);
                        
                        for (int i = 0; i < mh->ncmds; i++) {
                            lc = (struct load_command *)addrTemp;
                            if (lc->cmd == LC_SEGMENT) {
                                struct segment_command *segmentCommand = (struct segment_command *)(lc);
                                struct section *section                = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                                struct sectionInfo allsections[segmentCommand->nsects];
                                for (uint32_t x = 0; x < segmentCommand->nsects; x++) {
                                    allsections[x].location = section;
                                    memcpy(&allsections[x].section, section, sizeof(struct section));
                                    section++;
                                }
                                
                                int k, j, n = segmentCommand->nsects;
                                struct sectionInfo tmp;
                                for (k = 1; k < n; k++) {
                                    for (j = 0; j < n - k; j++) {
                                        if(allsections[j].section.addr > allsections[j+1].section.addr) {
                                            tmp              = allsections[j];
                                            allsections[j]   = allsections[j+1];
                                            allsections[j+1] = tmp;
                                        }
                                    }
                                }
                                
                                section = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                                for (uint32_t x = 0; x < segmentCommand->nsects; x++) {
                                    memcpy(section, &allsections[x].section, sizeof(struct section));
                                    section++;
                                }
                                
                                uint32_t entropy = 0;
                                section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                                struct section *section_b = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                                section_b++;
                                for (uint32_t x = 0; x < segmentCommand->nsects; x++) {
                                    if (strncmp(segmentCommand->segname, SEG_TEXT, 16) == 0 || strncmp(segmentCommand->segname, SEG_DATA, 16) == 0){
                                        printf(" * Checking: %s:%s\n", section->segname, section->sectname);
                                        if (strncmp(section->sectname, "__mod_init_func", 16) != 0) {
                                            if (strncmp(section->segname, segmentCommand->segname, 16) != 0) {
                                                printf("      > Fix: Section\t \"%s\"\t -> \t\"%s\"\n", section->segname, segmentCommand->segname);
                                                memcpy(section->segname, segmentCommand->segname, 16);
                                            }
                                            entropy = section->addr - segmentCommand->vmaddr + segmentCommand-> fileoff;
                                            entropy &= 0xffffffff;
                                            if (entropy > 0x7fffffff) entropy = 0;
                                            if((section->offset & 0xffffffff) != entropy) {
                                                printf("      > Fix: Offset\t 0x%016x\t -> \t0x%016x\n", section->offset, entropy);
                                                section->offset = entropy;
                                                if(x == segmentCommand->nsects - 1) {
                                                    entropy = segmentCommand->fileoff + segmentCommand->filesize - section->addr;
                                                } else {
                                                    entropy = section_b->addr - section->addr;
                                                }
                                                if (entropy > 0x7fffffff) entropy = 0;
                                                printf("      > Fix: Size\t 0x%016x\t -> \t0x%016x\n", section->size, entropy);
                                                section->size = entropy;
                                            }
                                        }
                                    }
                                    section++;
                                    section_b++;
                                }
                            }
                            addrTemp += lc->cmdsize;
                        }
                        break;
                    case 0x1000007: // 64bit
                        addrTemp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
                        mh64     = (struct mach_header_64 *)(addrTemp + offset);
                        addrTemp += sizeof(struct mach_header_64) + offset;
                        
                        printf("* MH_MAGIC_64:   %04X\n\t", mh64->magic);
                        printf("* Load Commands: %d\n\t", mh64->ncmds);
                        
                        for (int i = 0; i < mh64->ncmds; i++) {
                            lc = (struct load_command *)addrTemp;
                            if (lc->cmd == LC_SEGMENT_64) {
                                struct segment_command_64 *segmentCommand64 = (struct segment_command_64 *)(lc);
                                struct section_64 *section64                = (struct section_64 *)((uint8_t*)segmentCommand64 + sizeof(struct segment_command_64));
                                struct sectionInfo_64 allsections64[segmentCommand64->nsects];
                                for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                                    allsections64[x].location64 = section64;
                                    memcpy(&allsections64[x].section64, section64, sizeof(struct section_64));
                                    section64++;
                                }
                                
                                int k, j, n = segmentCommand64->nsects;
                                struct sectionInfo_64 tmp;
                                for (k = 1; k < n; k++) {
                                    for (j = 0; j < n - k; j++) {
                                        if(allsections64[j].section64.addr > allsections64[j+1].section64.addr) {
                                            tmp                = allsections64[j];
                                            allsections64[j]   = allsections64[j+1];
                                            allsections64[j+1] = tmp;
                                        }
                                    }
                                }
                                
                                section64 = (struct section_64 *)((uint8_t*)segmentCommand64 + sizeof(struct segment_command_64));
                                for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                                    memcpy(section64, &allsections64[x].section64, sizeof(struct section_64));
                                    section64++;
                                }
                                uint32_t entropy               = 0;
                                section64                      = (struct section_64 *)((char*)segmentCommand64 + sizeof(struct segment_command_64));
                                struct section_64 *section64_b = (struct section_64 *)((char*)segmentCommand64 + sizeof(struct segment_command_64));
                                section64_b++;
                                for (uint32_t x = 0; x < segmentCommand64->nsects; x++) {
                                    if (strncmp(segmentCommand64->segname, SEG_TEXT, 16) == 0 || strncmp(segmentCommand64->segname, SEG_DATA, 16) == 0) {
                                        printf(" * Checking: %s:%s\n", section64->segname, section64->sectname);
                                        if (strncmp(section64->sectname, "__mod_init_func", 16) != 0) {
                                            if (strncmp(section64->segname, segmentCommand64->segname, 16) != 0) {
                                                printf("      > Fix: Section\t \"%s\"\t -> \t\"%s\"\n", section64->segname, segmentCommand64->segname);
                                                memcpy(section64->segname, segmentCommand64->segname, 16);
                                            }
                                            
                                            entropy = section64->addr - segmentCommand64->vmaddr + segmentCommand64-> fileoff;
                                            entropy &= 0xffffffff;
                                            if (entropy > 0x7fffffff) entropy = 0;
                                            if((section64->offset & 0xffffffff) != entropy) {
                                                printf("      > Fix: Offset\t 0x%016x\t -> \t0x%016x\n", section64->offset, entropy);
                                                section64->offset = entropy;
                                                if(x == segmentCommand64->nsects - 1) {
                                                    entropy = segmentCommand64->fileoff + segmentCommand64->filesize - section64->addr;
                                                } else {
                                                    entropy = section64_b->addr - section64->addr;
                                                }
                                                if (entropy > 0x7fffffff) entropy = 0;
                                                printf("      > Fix: Size\t 0x%016llx\t -> \t0x%016x\n", section64->size, entropy);
                                                section64->size = entropy;
                                            }
                                        }
                                    }
                                    section64++;
                                    section64_b++;
                                }
                            }
                            addrTemp += lc->cmdsize;
                        }
                        break;
                }
                msync(addrTemp, size, MS_ASYNC);
                munmap(addrTemp, size);
            }
            break;
        default:
            printf("[ERROR] INVALID MACH-O BINARY.\n");
    }
    munmap(addr, size);
    close(fd);
    
    printf(" * All done. :)\n\n");
    
    return 0;
}
