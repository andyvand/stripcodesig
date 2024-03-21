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

void Usage(char *name)
{
	printf("stripcodesig V1.5\n");
	printf("Usage: %s <infile> <outfile>\n", name);
	printf("Copyright (C) 2010-2024 AnV Software\n");
}

int main(int argc, char **argv)
{
	FILE *f = NULL;
	uint8_t *buffer = NULL;
	uint8_t *archbuffer = NULL;
	struct fat_header *fh = NULL;
	struct fat_arch *archbin = NULL;
    struct fat_arch_64 *archbin64 = NULL;
    struct mach_header *mh = NULL;
	int filesize = 0;
	uint32_t current_bin = 0;
	uint32_t total_bins = 0;
	uint32_t total_patches = 0;

	if (argc != 3)
	{
		Usage(argv[0]);

		return(1);
	}

#if (defined(_MSC_VER) || defined(__clang__)) && __STDC_WANT_SECURE_LIB__
	fopen_s(&f, argv[1], "rb");
#else
	f = fopen(argv[1], "rb");
#endif

	if (f == NULL)
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

    fh = (struct fat_header *)buffer;
    if (fh->magic == MH_MAGIC)
    {
        total_patches = 1;
        mh = (struct mach_header *)buffer;

        remove_code_signature_32(buffer, false);
        printf("Patching for processor 0x%X\n", mh->cputype);

        printf ("Stripping codes signature from Mach-O 32 bit binary\n");
    } else if (fh->magic == MH_CIGAM) {
        total_patches = 1;
        mh = (struct mach_header *)buffer;

        remove_code_signature_32(buffer, true);
        printf("Patching for processor 0x%X\n", OSSwapInt32(mh->cputype));

        printf ("Stripping codes signature from swapped Mach-O 32 bit binary\n");
    } else if (fh->magic == MH_MAGIC_64) {
        total_patches = 1;
        mh = (struct mach_header *)buffer;

        remove_code_signature_64(buffer, false);
        printf("Patching for processor 0x%X\n", mh->cputype);

        printf ("Stripping codes signature from Mach-O 64 bit binary\n");
    } else if (fh->magic == MH_CIGAM_64) {
        total_patches = 1;
        mh = (struct mach_header *)buffer;

        remove_code_signature_64(buffer, true);
        printf("Patching for processor 0x%X\n", OSSwapInt32(mh->cputype));

        printf ("Stripping codes signature from swapped Mach-O 64 bit binary\n");
    } else if (fh->magic == FAT_MAGIC) {
        total_bins = fh->nfat_arch;

        printf ("Stripping codes signature from universal 32 bit binary (%d architectures)\n", total_bins);

        archbin = (struct fat_arch *)(buffer + sizeof(struct fat_header));

        while (current_bin != total_bins)
        {
            printf("Patching for processor 0x%X, binary %d\n", archbin->cputype, current_bin);

            archbuffer = buffer + archbin->offset;
            total_patches += 1;
            mh = (struct mach_header *)archbuffer;

            if (mh->magic == MH_CIGAM)
            {
                printf ("Removing code signature from swapped 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, true);
            } else if (mh->magic == MH_CIGAM_64) {
                printf ("Removing code signature from swapped 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, true);
            } else if (mh->magic == MH_MAGIC) {
                printf ("Removing code signature from 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, false);
            } else if (mh->magic == MH_MAGIC_64) {
                printf ("Removing code signature from 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, false);
            } else {
                printf("Skipping file with wrong magic (0x%X)\n", mh->magic);
            }

            ++current_bin;
            ++archbin;
        }
    } else if (fh->magic == FAT_CIGAM) {
        total_bins = OSSwapInt32(fh->nfat_arch);
        
        printf ("Stripping codes signature from universal swapped 32 bit binary (%d architectures)\n", total_bins);

        archbin = (struct fat_arch *)(buffer + sizeof(struct fat_header));

        while (current_bin != total_bins)
        {
            printf("Patching for processor 0x%X, binary %d\n", OSSwapInt32(archbin->cputype), current_bin);

            archbuffer = buffer + OSSwapInt32(archbin->offset);
            total_patches += 1;
            mh = (struct mach_header *)archbuffer;
            
            if (mh->magic == MH_CIGAM)
            {
                printf ("Removing code signature from swapped 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, true);
            } else if (mh->magic == MH_CIGAM_64) {
                printf ("Removing code signature from swapped 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, true);
            } else if (mh->magic == MH_MAGIC) {
                printf ("Removing code signature from 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, false);
            } else if (mh->magic == MH_MAGIC_64) {
                printf ("Removing code signature from 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, false);
            } else {
                printf("Skipping file with wrong magic (0x%X)\n", mh->magic);
            }
            
            ++current_bin;
            ++archbin;
        }
    } else if (fh->magic == FAT_MAGIC_64) {
        total_bins = fh->nfat_arch;
        
        printf ("Stripping codes signature from universal 64 bit binary (%d architectures)\n", total_bins);

        archbin64 = (struct fat_arch_64 *)(buffer + sizeof(struct fat_header));

        while (current_bin != total_bins)
        {
            printf("Patching for processor 0x%X, binary %d\n", archbin64->cputype, current_bin);

            archbuffer = buffer + archbin64->offset;
            total_patches += 1;
            mh = (struct mach_header *)archbuffer;
            
            if (mh->magic == MH_CIGAM)
            {
                printf ("Removing code signature from swapped 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, true);
            } else if (mh->magic == MH_CIGAM_64) {
                printf ("Removing code signature from swapped 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, true);
            } else if (mh->magic == MH_MAGIC) {
                printf ("Removing code signature from 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, false);
            } else if (mh->magic == MH_MAGIC_64) {
                printf ("Removing code signature from 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, false);
            } else {
                printf("Skipping file with wrong magic (0x%X)\n", mh->magic);
            }
            
            ++current_bin;
            ++archbin64;
        }
    } else if (fh->magic == FAT_CIGAM_64) {
        total_bins = OSSwapInt32(fh->nfat_arch);
        
        printf ("Stripping codes signature from universal swapped 64 bit binary (%d architectures)\n", total_bins);

        archbin64 = (struct fat_arch_64 *)(buffer + sizeof(struct fat_header));

        while (current_bin != total_bins)
        {
            printf("Patching for processor 0x%X, binary %d\n", OSSwapInt32(archbin64->cputype), current_bin);

            archbuffer = buffer + OSSwapInt64(archbin64->offset);
            total_patches += 1;
            mh = (struct mach_header *)archbuffer;
            
            if (mh->magic == MH_CIGAM)
            {
                printf ("Removing code signature from swapped 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, true);
            } else if (mh->magic == MH_CIGAM_64) {
                printf ("Removing code signature from swapped 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, true);
            } else if (mh->magic == MH_MAGIC) {
                printf ("Removing code signature from 32 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_32(archbuffer, false);
            } else if (mh->magic == MH_MAGIC_64) {
                printf ("Removing code signature from 64 bit binary (0x%X)\n", mh->magic);
                remove_code_signature_64(archbuffer, false);
            } else {
                printf("Skipping file with wrong magic (0x%X)\n", mh->magic);
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
#if (defined(_MSC_VER) || defined(__clang__)) && __STDC_WANT_SECURE_LIB__
		fopen_s(&f, argv[2], "wb");
#else
		f = fopen(argv[2], "wb");
#endif

        if (f == NULL)
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

