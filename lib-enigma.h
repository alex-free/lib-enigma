/*
BSD 3-Clause License
Copyright (c) 2026, Alex Free
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef LIB_ENIGMA_H
#define LIB_ENIGMA_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Uncomment to enable more printfs about what is going on.
//#define DEBUG

// Structure of sector: sector_sync_header_len + sector_user_data_len + sector_edc_ecc_len.
#define SECTOR_SYNC_HEADER_LEN 0x18
#define SECTOR_USER_DATA_LEN 0x800
#define SECTOR_EDC_LEN 0x04
#define SECTOR_ECC_LEN 0x114
#define SECTOR_RAW_LEN 0x930
#define PREGAP 150

// Sector Read Funcs
int read_sector_raw(FILE *bin, unsigned int sector_number, unsigned char * sector_buf); // Read an entire 2352 byte sector into sector_buf. If requested sector does not exist (i.e. not enough sectors in disc image for sector requested), it returns 2. If it successfully reads the sector, it returns 1. If it fails to read the sector but the sector exists, it returns 0.

int read_sector_user_data(FILE *bin, unsigned int sector_number, unsigned char * sector_buf); // Read only the user data (real data) into sector_buf. This excludes sync header, EDC, or ECC. If requested sector does not exist (i.e. not enough sectors in disc image for sector requested), it returns 2. If it successfully reads the sector, it returns 1. If it fails to read the sector but the sector exists, it returns 0.

int read_sector_edc(FILE *bin, unsigned int sector_number, unsigned char * sector_buf); // Read only the edc data (checksum of the sector used by ECC during disc error repair attempts) into sector_buf. This excludes sync header, user data, or ECC. If requested sector does not exist (i.e. not enough sectors in disc image for sector requested), it returns 2. If it successfully reads the sector, it returns 1. If it fails to read the sector but the sector exists, it returns 0.

int read_sector_ecc(FILE *bin, unsigned int sector_number, unsigned char * sector_buf); // Read only the ecc data (repair data used during disc error repair attempts when EDC verification mismatches) into sector_buf. This excludes sync header, user data, or EDC. If requested sector does not exist (i.e. not enough sectors in disc image for sector requested), it returns 2. If it successfully reads the sector, it returns 1. If it fails to read the sector but the sector exists, it returns 0.

// Identification functions.
const char * get_psx_exe_gameid(FILE *bin, char *volume_creation_timestamp);
int is_ps_cd(FILE *bin); // returns 1 if `bin` is a PlayStation 1 or 2 CD image in MODE2/2352 format. Returns 0 if it is not. Should be called before any of the functions below.

void get_volume_creation_timestamp(FILE *bin, char *volume_creation_timestamp); // sets volume_creation_timestamp with value from bin file. Useful for identifying PSX.EXE boot file games that are not yet in the library's database and are not automatically identified using get_boot_file_name(). If get_boot_file_name() returns `PSX.EXE`, you can use this to identify it uniquely, as many discs are sharing that boot file name.

int get_boot_file_name(FILE *bin, char *bootfile); // Returns boot file name in `bin` as `char *boot_file`. Supports most if not all PSX.EXE games as well as all SYSTEM.CNF games. Returns 1 on success. Returns 0 on failure. Returns 2 if a PSX.EXE game was unable to be verified by the internal database.

int id_rev(FILE *bin, const unsigned int difference_offset, const unsigned char old_byte, const unsigned char new_byte); // Returns 0 if `bin` has `old_byte` at `difference_offset`. Returns 1 if `bin` has `new_byte` at `difference_offset`. Returns 2 if neither are found at `different_offset`.

// Size functions.

int cdr_minimum_requirement(FILE *bin); // Returns 0 if the bin file will fit on a 71 minute CD-R. Returns 1 if at least a 74 minute CD-R is required. Returns 2 if an 80 minute CD-R is required.

unsigned int total_number_of_sectors(FILE *bin); // Returns the number of sectors in a disc image.

// Patching functions.
void bin_patch(FILE *bin,
               const unsigned char *pattern,
               int pattern_len,

               bool contains_unmatchable_bytes,
               
               const unsigned char *unmatchable_byte_offsets,
               int unmatchable_byte_offsets_len,
               
               const unsigned char *patch,
               int patch_len,

               const unsigned char *unpatchable_byte_offsets,
               int unpatchable_byte_offsets_len); // Custom 'Lossy' Patching by myself. Applies lossy patch (no hardcoded offsets). Unmatchable bytes is optional, please see example 3 for implementation details: https://github.com/alex-free/lib-enigma/tree/master/example-3-piracy-patcher

void apply_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin); // Apply PlayStation Patch File patch from unsigned char array.

void undo_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin); // Apply PlayStation Patch File patch from unsigned char array.

#endif /* LIB_ENIGMA_H */
