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
#define SECTOR_EDC_ECC_LEN 0x118
#define SECTOR_RAW_LEN 0x930
#define PREGAP 150

// Identification.
const char * get_psx_exe_gameid(char *volume_creation_timestamp);
int is_ps_cd(FILE *bin);
void get_volume_creation_timestamp(FILE *bin, char *volume_creation_timestamp);
int get_boot_file_name(FILE *bin, char *bootfile);
int id_rev(FILE *bin, const unsigned int difference_offset, const unsigned char old_byte, const unsigned char new_byte);
int cdr_minimum_requirement(FILE *bin);

// Custom 'Lossy' Patching by myself.
void bin_patch(FILE *bin,
               const unsigned char *pattern,
               int pattern_len,

               bool contains_unmatchable_bytes,
               
               const unsigned char *unmatchable_byte_offsets,
               int unmatchable_byte_offsets_len,
               
               const unsigned char *patch,
               int patch_len,

               const unsigned char *unpatchable_byte_offsets,
               int unpatchable_byte_offsets_len);

// PlayStationPatchFile (PPF)
void apply_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin);
void undo_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin);

#endif /* LIB_ENIGMA_H */
