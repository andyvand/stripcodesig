/*
 * instruction length decoder (written by kaitek, modified by mercurysquad)
 * voodoo xnu kernel
 *
 * based on code from AntiHookExec 1.00, Copyright (c) 2004 Chew Keong TAN
 * opcode tables based on documentation from http://www.sandpile.org/
 *
 *   todo:   * support for instruction set extensions newer than SSSE3
 *           * verify that VT instructions are correctly decoded
 * AnV - Added better opcode + SSE4.1 + SSE4.2 support
 */

#include "stripcodesig.h"

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef bool
#define bool unsigned char
#endif

#ifndef kern_return_t
#define kern_return_t int
#endif

#ifndef KERN_SUCCESS
#define KERN_SUCCESS 0
#endif

#ifndef KERN_FAILURE
#define KERN_FAILURE -1
#endif

/* note: the map_addr and map_size arguments are used only for error checking. */

kern_return_t remove_code_signature_32(uint8_t *data, bool swapped)
{
	struct mach_header *mh_32 = (struct mach_header *)data;
	struct load_command *tmplc = (struct load_command *)(data + sizeof(struct mach_header));
	uint32_t curlc = 0;
    uint32_t totlc = 0;
    if (swapped == true)
    {
        totlc = OSSwapInt32(mh_32->ncmds);
    } else {
        totlc = mh_32->ncmds;
    }
	uint32_t curoff = sizeof(struct mach_header);
	struct linkedit_data_command *cryptsiglc = (struct linkedit_data_command *)0;
    struct linkedit_data_command *cryptsigdrs = (struct linkedit_data_command *)0;
	uint8_t *cryptsigdata = (uint8_t *)0;
    uint8_t *cryptdrsdata = (uint8_t *)0;
	//uint32_t cryptsigdatasize = 0;
	uint32_t zeroeddata = 0;

	/* Get code signature load command + divide */
	while (curlc < totlc)
    {
        if (swapped == true)
        {
            if (OSSwapInt32(tmplc->cmd) == LC_CODE_SIGNATURE)
            {
                cryptsiglc = (struct linkedit_data_command *)(data + curoff);
            }
            
            if (OSSwapInt32(tmplc->cmd) == LC_DYLIB_CODE_SIGN_DRS)
            {
                cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
            }
            
            curoff += OSSwapInt32(tmplc->cmdsize);
            tmplc = (struct load_command *)(data + curoff);
            ++curlc;
        } else {
            if (tmplc->cmd == LC_CODE_SIGNATURE)
            {
                cryptsiglc = (struct linkedit_data_command *)(data + curoff);
            }
            
            if (tmplc->cmd == LC_DYLIB_CODE_SIGN_DRS)
            {
                cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
            }
            
            curoff += tmplc->cmdsize;
            tmplc = (struct load_command *)(data + curoff);
            ++curlc;

        }
    }

	/* Safety check */
	if ((cryptsiglc == 0) && (cryptsigdrs == 0))
	{
		printf("No code signature found, skipping patch\n");
		return KERN_FAILURE;
	}

    if (cryptsiglc)
    {
        if (swapped == true)
        {
            cryptsigdata = (uint8_t *)(data + OSSwapInt32(cryptsiglc->dataoff));
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < OSSwapInt32(cryptsiglc->datasize))
            {
                *cryptsigdata = 0;
                ++zeroeddata;
                ++cryptsigdata;
            }
        } else {
            cryptsigdata = (uint8_t *)(data + cryptsiglc->dataoff);
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < cryptsiglc->datasize)
            {
                *cryptsigdata = 0;
                ++zeroeddata;
                ++cryptsigdata;
            }
        }
        /* Reduce the number of load commands + load command size */
        //mh_32->ncmds -= 1;
        //mh_32->sizeofcmds -= cryptsiglc->cmdsize;

        /* Zero out load command of LC_CODE_SIGNATURE */
        //cryptsiglc->cmd = 0;
        //cryptsiglc->cmdsize = 0;
        //cryptsiglc->dataoff = 0;
        cryptsiglc->datasize = 0;

        printf("Code signature (SIG) removed succesfully (32bit)\n");
    }

    if (cryptsigdrs)
    {
        if (swapped == true)
        {
            cryptdrsdata = (uint8_t *)(data + OSSwapInt32(cryptsigdrs->dataoff));
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < OSSwapInt32(cryptsigdrs->datasize))
            {
                *cryptdrsdata = 0;
                ++zeroeddata;
                ++cryptdrsdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_32->ncmds = OSSwapInt32(OSSwapInt32(mh_32->ncmds) - 1);
            mh_32->sizeofcmds = OSSwapInt32(OSSwapInt32(mh_32->sizeofcmds) - OSSwapInt32(cryptsigdrs->cmdsize));
        } else {
            cryptdrsdata = (uint8_t *)(data + cryptsigdrs->dataoff);
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < cryptsigdrs->datasize)
            {
                *cryptdrsdata = 0;
                ++zeroeddata;
                ++cryptdrsdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_32->ncmds -= 1;
            mh_32->sizeofcmds -= cryptsigdrs->cmdsize;
        }
    
        /* Zero out load command of LC_CODE_SIGNATURE */
        cryptsigdrs->cmd = 0;
        cryptsigdrs->cmdsize = 0;
        cryptsigdrs->dataoff = 0;
        cryptsigdrs->datasize = 0;

        printf("Code signature (DRS) removed succesfully (32bit)\n");
    }

	return KERN_SUCCESS;
}

kern_return_t remove_code_signature_64(uint8_t *data, bool swapped)
{
	struct mach_header_64 *mh_64 = (struct mach_header_64 *)data;
	struct load_command *tmplc = (struct load_command *)(data + sizeof(struct mach_header_64));
	uint32_t curlc = 0;
    uint32_t totlc = 0;
    if (swapped == true)
    {
        totlc = OSSwapInt32(mh_64->ncmds);
    } else {
        totlc = mh_64->ncmds;
    }
	uint32_t curoff = sizeof(struct mach_header_64);
	struct linkedit_data_command *cryptsiglc = (struct linkedit_data_command *)0;
    struct linkedit_data_command *cryptsigdrs = (struct linkedit_data_command *)0;
	uint8_t *cryptsigdata = (uint8_t *)0;
    uint8_t *cryptdrsdata = (uint8_t *)0;
	//uint32_t cryptsigdatasize = 0;
	uint32_t zeroeddata = 0;
	
       /* Get code signature load command + divide */
        while (curlc < totlc)
        {
            if (swapped == true)
            {
                if (OSSwapInt32(tmplc->cmd) == LC_CODE_SIGNATURE)
                {
                    cryptsiglc = (struct linkedit_data_command *)(data + curoff);
                }
            
                if (OSSwapInt32(tmplc->cmd) == LC_DYLIB_CODE_SIGN_DRS)
                {
                    cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
                }
            
                curoff += OSSwapInt32(tmplc->cmdsize);
            } else {
                if (tmplc->cmd == LC_CODE_SIGNATURE)
                {
                    cryptsiglc = (struct linkedit_data_command *)(data + curoff);
                }
            
                if (tmplc->cmd == LC_DYLIB_CODE_SIGN_DRS)
                {
                    cryptsigdrs = (struct linkedit_data_command *)(data + curoff);
                }
            
            
                curoff += tmplc->cmdsize;
            }

            tmplc = (struct load_command *)(data + curoff);
            ++curlc;
        }

	/* Safety check */
	if ((cryptsiglc == 0) && (cryptsigdrs == 0))
	{
		printf("No code signature found, skipping patch\n");
		return KERN_FAILURE;
	}

    if (cryptsiglc)
    {
        if (swapped == true)
        {
            cryptsigdata = (uint8_t *)(data + OSSwapInt32(cryptsiglc->dataoff));
            
            /* Zero code signature... */
            while (zeroeddata < OSSwapInt32(cryptsiglc->datasize))
            {
                *cryptsigdata = 0;
                ++zeroeddata;
                ++cryptsigdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_64->ncmds = OSSwapInt32(OSSwapInt32(mh_64->ncmds) - 1);
            mh_64->sizeofcmds = OSSwapInt32(OSSwapInt32(mh_64->sizeofcmds) - OSSwapInt32(cryptsiglc->cmdsize));
        } else {
            cryptsigdata = (uint8_t *)(data + cryptsiglc->dataoff);
            
            /* Zero code signature... */
            while (zeroeddata < cryptsiglc->datasize)
            {
                *cryptsigdata = 0;
                ++zeroeddata;
                ++cryptsigdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_64->ncmds -= 1;
            mh_64->sizeofcmds -= cryptsiglc->cmdsize;
        }
	
        /* Zero out load command of LC_CODE_SIGNATURE */
        //cryptsiglc->cmd = 0;
        //cryptsiglc->cmdsize = 0;
        //cryptsiglc->dataoff = 0;
        cryptsiglc->datasize = 0;
	
        printf("Code signature (SIG) removed succesfully (64bit)\n");
    }

    if (cryptsigdrs)
    {
        if (swapped == true)
        {
            cryptdrsdata = (uint8_t *)(data + OSSwapInt32(cryptsigdrs->dataoff));
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < OSSwapInt32(cryptsigdrs->datasize))
            {
                *cryptdrsdata = 0;
                ++zeroeddata;
                ++cryptdrsdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_64->ncmds = OSSwapInt32(OSSwapInt32(mh_64->ncmds) - 1);
            mh_64->sizeofcmds = OSSwapInt32(OSSwapInt32(mh_64->sizeofcmds) - OSSwapInt32(cryptsigdrs->cmdsize));
        } else {
            cryptdrsdata = (uint8_t *)(data + cryptsigdrs->dataoff);
            
            zeroeddata = 0;
            
            /* Zero code signature... */
            while (zeroeddata < cryptsigdrs->datasize)
            {
                *cryptdrsdata = 0;
                ++zeroeddata;
                ++cryptdrsdata;
            }
            
            /* Reduce the number of load commands + load command size */
            mh_64->ncmds -= 1;
            mh_64->sizeofcmds -= cryptsigdrs->cmdsize;
        }
        
        /* Zero out load command of LC_CODE_SIGNATURE */
        cryptsigdrs->cmd = 0;
        cryptsigdrs->cmdsize = 0;
        cryptsigdrs->dataoff = 0;
        cryptsigdrs->datasize = 0;
        
    	printf("Code signature (DRS) removed succesfully (64bit)\n");
    }
    
	return KERN_SUCCESS;
}

#if defined(__ppc__) || defined(__ppc64__)
#define SWAPOFFSET32(X) X
#define SWAPOFFSET64(X) X
#define XSWAPOFFSET32(X) OSSwapInt32(X)
#define XSWAPOFFSET64(X) OSSwapInt64(X)
#else
#define SWAPOFFSET32(X) OSSwapInt32(X)
#define SWAPOFFSET64(X) OSSwapInt64(X)
#define XSWAPOFFSET32(X) X
#define XSWAPOFFSET64(X) X
#endif

void Usage(char *name)
{
	printf("stripcodesig V1.3\n");
	printf("Usage: %s <infile> <outfile>\n", name);
	printf("Copyright (C) 2010-2024 AnV Software\n");
}

int main(int argc, char **argv)
{
	FILE *f = NULL;
	uint8_t *buffer = NULL;
	uint8_t *archbuffer = NULL;
	//struct fat_header *univbin = NULL;
	struct fat_arch *archbin = NULL;
    struct fat_arch_64 *archbin64 = NULL;
	int filesize = 0;
	uint32_t current_bin = 0;
	uint32_t total_bins = 0;
	uint32_t total_patches = 0;

	if (argc != 3)
	{
		Usage(argv[0]);

		return(1);
	}

#if defined(_MSC_VER) && __STDC_WANT_SECURE_LIB__
	fopen_s(&f, argvW[1], "rb");
#else
	f = fopen(argv[1], "rb");
#endif

	if (!f)
	{
		printf("ERROR: Opening input file failed\n");

		return(-2);
	}

	fseek(f,0,SEEK_END);
	filesize = (int)ftell(f);
	fseek(f,0,SEEK_SET);

	buffer = (uint8_t *)malloc(filesize);

	fread((char *)buffer,filesize,1,f);

	fclose(f);

	if ((buffer[0] == 0xCE) && (buffer[1] == 0xFA) && (buffer[2] == 0xED) && (buffer[3] == 0xFE)) // Mach-O 32bit
	{
		total_patches = 1;
#if defined(__ppc__) || defined(__ppc64__)
        remove_code_signature_32(buffer, true);
#else
		remove_code_signature_32(buffer, false);
#endif
	} else if ((buffer[0] == 0xCF) && (buffer[1] == 0xFA) && (buffer[2] == 0xED) && (buffer[3] == 0xFE)) { // Mach-O 64bit
		total_patches = 1;
#if defined(__ppc__) || defined(__ppc64__)
        remove_code_signature_64(buffer, true);
#else
        remove_code_signature_64(buffer, false);
#endif
    } else if ((buffer[0] == 0xFE) && (buffer[1] == 0xED) && (buffer[2] == 0xFA) && (buffer[3] == 0xCF)) { // Swapped Mach-O 64bit
        total_patches = 1;
#if defined(__ppc__) || defined(__ppc64__)
        remove_code_signature_64(buffer, false);
#else
        remove_code_signature_64(buffer, true);
#endif
    } else if ((buffer[0] == 0xFE) && (buffer[1] == 0xED) && (buffer[2] == 0xFA) && (buffer[3] == 0xCE)) { // Swapped Mach-O 32bit
        total_patches = 1;
#if defined(__ppc__) || defined(__ppc64__)
        remove_code_signature_32(buffer, false);
#else
        remove_code_signature_32(buffer, true);
#endif
	} else if ((buffer[0] == 0xCA) && (buffer[1] == 0xFE) && (buffer[2] == 0xBA) && (buffer[3] == 0xBE)) { // Universal Binary 32 bit
		total_bins = buffer[7] + (buffer[6] << 8) + (buffer[5] << 16) + (buffer[4] << 24);

		printf ("Stripping codes signature from universal 32 bit binary (%d architectures)\n", total_bins);

		archbin = (struct fat_arch *)(buffer + 8);

		while (current_bin != total_bins)
        {
            if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_X86_64)
            {
                printf("Patching X86_64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, true);
#else
                remove_code_signature_64(archbuffer, false);
#endif
            } else if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_I386) {
                printf("Patching I386 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, true);
#else
                remove_code_signature_32(archbuffer, false);
#endif
            } else if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_ARM64) {
                printf("Patching ARM64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, true);
#else
                remove_code_signature_64(archbuffer, false);
#endif
            } else if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_ARM) {
                printf("Patching ARM32 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, true);
#else
                remove_code_signature_32(archbuffer, false);
#endif
            } else if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_POWERPC64) {
                printf("Patching PowerPC64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, false);
#else
                remove_code_signature_64(archbuffer, true);
#endif
            } else if (SWAPOFFSET32(archbin->cputype) == CPU_TYPE_POWERPC) {
                printf("Patching PowerPC32 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + SWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, false);
#else
                remove_code_signature_32(archbuffer, true);
#endif
            } else {
                printf("Skipping non-Intel/ARM/PPC architecture (%d)\n", current_bin);
            }
            
            ++current_bin;
            ++archbin;
        }
    } else if ((buffer[0] == 0xBE) && (buffer[1] == 0xBA) && (buffer[2] == 0xFE) && (buffer[3] == 0xCA)) { // Swapped Universal Binary 32 bit
        total_bins = (buffer[7] << 24) + (buffer[6] << 16) + (buffer[5] << 8) + (buffer[4]);

        printf ("Stripping codes signature from universal swapped 32 bit binary (%d architectures)\n", total_bins);

        archbin = (struct fat_arch *)(buffer + 8);

        while (current_bin != total_bins)
        {
            if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_X86_64)
            {
                printf("Patching X86_64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, true);
#else
                remove_code_signature_64(archbuffer, false);
#endif
            } else if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_I386) {
                printf("Patching I386 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, true);
#else
                remove_code_signature_32(archbuffer, false);
#endif
            } else if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_ARM64) {
                printf("Patching ARM64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, true);
#else
                remove_code_signature_64(archbuffer, false);
#endif
            } else if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_ARM) {
                printf("Patching ARM32 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, true);
#else
                remove_code_signature_32(archbuffer, false);
#endif
            } else if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_POWERPC64) {
                printf("Patching PowerPC64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_64(archbuffer, false);
#else
                remove_code_signature_64(archbuffer, true);
#endif
            } else if (XSWAPOFFSET32(archbin->cputype) == CPU_TYPE_POWERPC) {
                printf("Patching PowerPC32 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin->cputype), current_bin);
                
                archbuffer = buffer + XSWAPOFFSET32(archbin->offset);
                total_patches += 1;
                
#if defined(__ppc__) || defined(__ppc64__)
                remove_code_signature_32(archbuffer, false);
#else
                remove_code_signature_32(archbuffer, true);
#endif
            } else {
                printf("Skipping non-Intel/ARM/PowerPC architecture (%d)\n", current_bin);
            }
            
            ++current_bin;
            ++archbin;
        }
    } else if ((buffer[0] == 0xCA) && (buffer[1] == 0xFE) && (buffer[2] == 0xBA) && (buffer[3] == 0xBF)) { // Universal Binary 64 bit
            total_bins = buffer[7] + (buffer[6] << 8) + (buffer[5] << 16) + (buffer[4] << 24);
            
            printf ("Stripping codes signature from universal 64 bit binary (%d architectures)\n", total_bins);
            
            archbin64 = (struct fat_arch_64 *)(buffer + 8);
            
            while (current_bin != total_bins)
            {
                if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_X86_64)
                {
                    printf("Patching X86_64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, true);
#else
                    remove_code_signature_64(archbuffer, false);
#endif
                } else if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_I386) {
                    printf("Patching I386 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;
                    
#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, true);
#else
                    remove_code_signature_32(archbuffer, false);
#endif
                } else if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_ARM64) {
                    printf("Patching ARM64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, true);
#else
                    remove_code_signature_64(archbuffer, false);
#endif
                } else if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_ARM) {
                    printf("Patching ARM32 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;
                    
#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, true);
#else
                    remove_code_signature_32(archbuffer, false);
#endif
                } else if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_POWERPC64) {
                    printf("Patching PowerPC64 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, false);
#else
                    remove_code_signature_64(archbuffer, true);
#endif
                } else if (SWAPOFFSET32(archbin64->cputype) == CPU_TYPE_POWERPC) {
                    printf("Patching PowerPC32 part (processor %u, architecture %d)\n", SWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + SWAPOFFSET64(archbin64->offset);
                    total_patches += 1;
                    
#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, false);
#else
                    remove_code_signature_32(archbuffer, true);
#endif
                } else {
                    printf("Skipping non-Intel/ARM/PPC architecture (%d)\n", current_bin);
                }
                
                ++current_bin;
                ++archbin64;
            }
    } else if ((buffer[0] == 0xBF) && (buffer[1] == 0xBA) && (buffer[2] == 0xFE) && (buffer[3] == 0xCA)) { // Universal Binary 64 bit
            total_bins = (buffer[7] << 24) + (buffer[6] << 16) + (buffer[5] << 8) + (buffer[4]);
            
            printf ("Stripping codes signature from swapped universal 64 bit binary (%d architectures)\n", total_bins);
            
            archbin64 = (struct fat_arch_64 *)(buffer + 8);
            
            while (current_bin != total_bins)
            {
                if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_X86_64)
                {
                    printf("Patching X86_64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, true);
#else
                    remove_code_signature_64(archbuffer, false);
#endif
                } else if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_I386) {
                    printf("Patching I386 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;
                    
#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, true);
#else
                    remove_code_signature_32(archbuffer, false);
#endif
                } else if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_ARM64) {
                    printf("Patching ARM64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, true);
#else
                    remove_code_signature_64(archbuffer, false);
#endif
                } else if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_ARM) {
                    printf("Patching ARM32 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;
                    
#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, true);
#else
                    remove_code_signature_32(archbuffer, false);
#endif
                } else if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_POWERPC64) {
                    printf("Patching PowerPC64 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_64(archbuffer, false);
#else
                    remove_code_signature_64(archbuffer, true);
#endif
                } else if (XSWAPOFFSET32(archbin64->cputype) == CPU_TYPE_POWERPC) {
                    printf("Patching PowerPC32 part (processor %u, architecture %d)\n", XSWAPOFFSET32(archbin64->cputype), current_bin);
                    
                    archbuffer = buffer + XSWAPOFFSET64(archbin64->offset);
                    total_patches += 1;

#if defined(__ppc__) || defined(__ppc64__)
                    remove_code_signature_32(archbuffer, false);
#else
                    remove_code_signature_32(archbuffer, true);
#endif
                } else {
                    printf("Skipping non-Intel/ARM/PPC architecture (%d)\n", current_bin);
                }
                
                ++current_bin;
                ++archbin64;
            }
	} else {
		printf("ERROR: Unsupported or no Mach-O file\n");

		return(-1);
	}

	if (total_patches <= 0)
	{
		printf("No codesignatures found, not generating output file\n");
	} else {
#if defined(_MSC_VER) && __STDC_WANT_SECURE_LIB__
		fopen_s(&f, argv[2], "wb");
#else
		f = fopen(argv[2], "wb");
#endif

	        if (!f)
        	{
                	printf("ERROR: Opening output file failed\n");

                	return(-3);
        	}

		fwrite((char *)buffer,filesize,1,f);

		fclose(f);
	}

    	printf("Removed %d code signatures\n", total_patches);

	return(0);
}

