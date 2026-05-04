// Lossy patcher example for Lib-Enigma, by Alex Free
#include "../lib-enigma.h"

const unsigned char anti_piracy_v2_vc0_bypass_pattern[] = { // This was first seen in Dino Crisis? Does SCEX/GetTN/GetTD/ReadTOC but is standardized and very easy to bypass. Seems like all games after a certain point began copying in this code to add anti-piracy measures to their product.
    0x01, 0x00, 0x01, 0x03, // GetStat
    0x13, 0x00, 0x03, 0x03, // GetTN
    0x14, 0x01, 0x03, 0x03, // GetTD
    0x02, 0x03, 0x01, 0x03, // SetLoc
    0x16, 0x00, 0x01, 0x05, // SeekAudio
    0x0E, 0x01, 0x01, 0x03, // SetMode
    0x0A, 0x00, 0x01, 0x05, // Init
    0x0B, 0x00, 0x01, 0x03, // Mute
    0x03, 0x00, 0x01, 0x03, // Play
    0x19, 0x01, 0x01, 0x03, // Subfunq X (19'04) //37th
    0x19, 0x01, 0x02, 0x03, // Subfunq Y (19'05) //41st
    0x09, 0x00, 0x01, 0x05, // Pause
    0x1E, 0x00, 0x01, 0x05, // ReadTOC //49th
    0x1A, 0x00, 0x01, 0x05 // GetID
}; //52 byte pattern

const unsigned char anti_piracy_v2_vc0_bypass_patch[] = { // This was first seen in Dino Crisis? Does SCEX/GetTN/GetTD/ReadTOC but is standardized and very easy to bypass. Seems like all games after a certain point began copying in this code to add anti-piracy measures to their product.
    0x01, 0x00, 0x01, 0x03, // GetStat
    0x13, 0x00, 0x03, 0x03, // GetTN
    0x14, 0x01, 0x03, 0x03, // GetTD
    0x02, 0x03, 0x01, 0x03, // SetLoc
    0x16, 0x00, 0x01, 0x05, // SeekAudio
    0x0E, 0x01, 0x01, 0x03, // SetMode
    0x0A, 0x00, 0x01, 0x05, // Init
    0x0B, 0x00, 0x01, 0x03, // Mute
    0x03, 0x00, 0x01, 0x03, // Play
    0x19, 0x01, 0x01, 0x03, // Subfunq X (19'04) //36th
    0x19, 0x01, 0x02, 0x03, // Subfunq Y (19'05) //40
    0x09, 0x00, 0x01, 0x05, // Pause
    0x00, 0x00, 0x01, 0x05, // ReadTOC has been replaced by sync command to replicate vc0 cdrom controller which does not have this command, and has backdoor to force pass apv2 for non-chipped soft-modded consoles // 48th
    0x1A, 0x00, 0x01, 0x05 // GetID
}; //52 byte patch

// ICEPICK patch from TRSIMEDI, modified for aprip
const unsigned char libcrypt_1_medievil_icepick_based_patch_pattern[] = {
    0x0A, // 0
    0x00, // not a value checked // 1
    0x80, // 2
    0x14, // 3
    0x00, // not a value checked // 4
    0x00, // not a value checked // 5
    0x00, // not a value checked // 6
    0x00, // not a value checked // 7
    0x00, // not a value checked // 8
    0x00, // not a value checked // 9
    0xA3, // 10
    0x90, // 11
    0x02, // 12
    0x00, // not a value checked // 13
    0x02, // 14
    0x24, // 15
    0x06, // 16
    0x00, // not a value checked // 17
    0x62, // 18
    0x14, // 19
    0x0E, // 20
    0x80, // 21
    0x03, // 22
    0x3C, // 23
    0x04, // 24
    0x00, // not a value checked // 25
    0xA3, // 26
    0x90, // 27
    0x53, // 28
    0x00, // not a value checked // 29
    0x02, // 30
    0x24, // 31
    0x02, // 32
    0x00, // not a value checked // 33
    0x62, // 34
    0x14, // 35
    0x0E, // 36
    0x80, // 37
    0x03, // 38
    0x3C, // 39
    0x07, // 40
    0x00, // not a value checked // 41
    0xA4, // 42
    0x90, // 43
    0x00, // byte 2 of MW // 44
    0x00, // byte 1 of MW // 45
    0x00, // 46
    0x00 // 47
}; // 0x2F, 47 bytes

// ICEPICK patch from TRSIMEDI, modified for aprip
unsigned char libcrypt_1_medievil_icepick_based_patch[] = {
    0x00, // 0
    0x00, // not a value checked // 1
    0x00, // 2
    0x00, // 3
    0x00, // not a value checked // 4
    0x00, // not a value checked // 5
    0x00, // not a value checked // 6
    0x00, // not a value checked // 7
    0x00, // not a value checked // 8
    0x00, // not a value checked // 9
    0x00, // 10
    0x00, // 11
    0x00, // 12
    0x00, // not a value checked // 13
    0x00, // 14
    0x00, // 15
    0x00, // 16
    0x00, // not a value checked // 17
    0x00, // 18
    0x00, // 19
    0x00, // 20
    0x00, // 21
    0x00, // 22
    0x00, // 23
    0x00, // 24
    0x00, // not a value checked // 25
    0x00, // 26
    0x00, // 27
    0x00, // 28
    0x00, // not a value checked // 29
    0x00, // 30
    0x00, // 31
    0x00, // 32
    0x00, // not a value checked // 33
    0x00, // 34
    0x00, // 35
    0x00, // 36
    0x00, // 37
    0x00, // 38
    0x00, // 39
    0x00, // 40
    0x00, // not a value checked // 41
    0x00, // 42
    0x00, // 43
    0xAA, // byte 2 of MW // 44
    0x87, // byte 1 of MW // 45 // Magic word is AA87 for Europe. For other regions, change byte 44 and 45.
    0x04, // 46
    0x24 // 47
}; // 0x2F, 47 bytes

const unsigned char libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets[] = {
    1,
    4,
    5,
    6,
    7,
    8,
    9,
    13,
    17,
    25,
    29,
    33,
    41,
    44,
    45
};

const unsigned char libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets[] = {
    1,
    4,
    5,
    6,
    7,
    8,
    9,
    13,
    17,
    25,
    29,
    33,
    41
};

int main (int argc, const char * argv[]) 
{
    FILE *bin;
    char boot_file[12];
    
    if(argc != 2) 
    {
        printf("Error: incorrect number of arguments\n\nUsage:\npsxpiracyp <.bin file>\n");
        return 1;
    }

    bin = fopen(argv[1], "rb+");

    if(bin == NULL)
    {
        printf("Error: Can not open: %s\n", argv[1]);
        return 1;
    }
    
    int valid = is_ps_cd(bin);

    if(!valid)
    {
        printf("\nError: %s does not appears to be a PlayStation 1 or 2 CD image\n", argv[1]);
        fclose(bin);
        return 1;
    } else if(valid) {
        int got_boot_file = get_boot_file_name(bin, boot_file);
        //printf("boot file: %s\n", boot_file);
        unsigned int sector_count = total_number_of_sectors(bin);

        if(got_boot_file == 1) // Successfully found boot file.
        {            
            if((strncmp(boot_file, "SCES_003.11", 11) == 0)) 
            {// /MediEvil (Europe)
                // Magic word is 87AA: https://web.archive.org/web/20220710184013/https://www.psdevwiki.com/ps3/PS1_Custom_Patches. 
                // Magic word is already in patch.
                // Unpatched MD5: 6d222937049c7ef56caa0994b0246790
                // Patched MD5: 29589f79d81bf604cfac7f2c53b3f7ac
                printf("MediEvil (Europe) detected, patching LibCrypt v1 protection...\n");

                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                                
                                true,                                                     // contains_unmatchable_bytes
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                                
                                libcrypt_1_medievil_icepick_based_patch,                  // patch
                                sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets,
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets)
                                );
                }

            } else if((strncmp(boot_file, "SCES_014.92", 11) == 0)) {// MediEvil (France)
                // Magic word is D16A: https://web.archive.org/web/20220710184013/https://www.psdevwiki.com/ps3/PS1_Custom_Patches.
                // Need to update patch from MediEvil (Europe) magic word to MediEvil (France) magic word.
                libcrypt_1_medievil_icepick_based_patch[44] = 0x6A; 
                libcrypt_1_medievil_icepick_based_patch[45] = 0xD1; 
                // Unpatched MD5: 369d0141020d017fdb09b16b2c1900b7
                // Patched MD5: 31bbb0474e10bc0f69da4341eb9d7ea0
                printf("MediEvil (France) detected, patching LibCrypt v1 protection...\n");

                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                                
                                true,                                                     // contains_unmatchable_bytes
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                                
                                libcrypt_1_medievil_icepick_based_patch,                  // patch
                                sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets,
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets)
                                );
                }
           } else if((strncmp(boot_file, "SCES_014.93", 11) == 0)) {// MediEvil (Germany)
                // Magic word is 197A: https://web.archive.org/web/20220710184013/https://www.psdevwiki.com/ps3/PS1_Custom_Patches.
                // Need to update patch from MediEvil (Europe) magic word to MediEvil (Germany) magic word.
                libcrypt_1_medievil_icepick_based_patch[44] = 0x7A; 
                libcrypt_1_medievil_icepick_based_patch[45] = 0x19; 
                // Unpatched MD5: fa7e2bb143267bbb8f69983cf811d686
                // Patched MD5: c90fb57cdfce48b5e44d47947dd8d769
                printf("MediEvil (Germany) detected, patching LibCrypt v1 protection...\n");

                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                                
                                true,                                                     // contains_unmatchable_bytes
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                                
                                libcrypt_1_medievil_icepick_based_patch,                  // patch
                                sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets,
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets)
                                );
                }
           } else if((strncmp(boot_file, "SCES_014.94", 11) == 0)) {// MediEvil (Italy)
                // Magic word is AAA6: https://web.archive.org/web/20220710184013/https://www.psdevwiki.com/ps3/PS1_Custom_Patches.
                // Need to update patch from MediEvil (Europe) magic word to MediEvil (Italy) magic word.
                libcrypt_1_medievil_icepick_based_patch[44] = 0xA6; 
                libcrypt_1_medievil_icepick_based_patch[45] = 0xAA; 
                // Unpatched MD5: be429f46f83dfb55d51d45385ea92eee
                // Patched MD5: e3268ff369e87401480fefb6e9734628
                printf("MediEvil (Italy) detected, patching LibCrypt v1 protection...\n");

                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                                
                                true,                                                     // contains_unmatchable_bytes
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                                
                                libcrypt_1_medievil_icepick_based_patch,                  // patch
                                sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets,
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets)
                                );
                }
           } else if((strncmp(boot_file, "SCES_014.95", 11) == 0)) {// MediEvil (Spain)
                // Magic word is 0E57: https://web.archive.org/web/20220710184013/https://www.psdevwiki.com/ps3/PS1_Custom_Patches.
                // Need to update patch from MediEvil (Europe) magic word to MediEvil (Spain) magic word.
                libcrypt_1_medievil_icepick_based_patch[44] = 0x57; 
                libcrypt_1_medievil_icepick_based_patch[45] = 0x0E; 
                // Unpatched MD5: 6b0e7ececa92577ba2d775f7727c4adc
                // Patched MD5: 5c598c6ade8bc00998d9f390a093d364
                printf("MediEvil (Spain) detected, patching LibCrypt v1 protection...\n");

                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                                
                                true,                                                     // contains_unmatchable_bytes
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                                
                                libcrypt_1_medievil_icepick_based_patch,                  // patch
                                sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                                
                                libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets,
                                sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_ignored_offsets)
                                );
                }              
            } else { // Detect APv2 protection.
                printf("Searching for Anti-Piracy v2 (APv2) protection. If found this patch will ONLY allow stock consoles without a mod-chip that use a soft-mod to play them\n");
                
                
                for(unsigned int i = 0; i < sector_count; i++)
                {
                    sector_boundary_aware_find_and_replace(
                                bin,                                                      // FILE *
                                
                                i,                                                        // sector to check
                                
                                anti_piracy_v2_vc0_bypass_pattern,          // pattern
                                sizeof(anti_piracy_v2_vc0_bypass_pattern),  // pattern_len
                                
                                false,                                                     // contains_unmatchable_bytes
                                
                                0,  // unpatchable offsets len (unused in this example)
                                0, // unpatchable offsets_len (unused in this example)
                                
                                anti_piracy_v2_vc0_bypass_patch,                  // patch
                                sizeof(anti_piracy_v2_vc0_bypass_patch),           // patch_len
                                
                                0, // unpatchable offsets array (unused in this example)
                                0 // unpatchable offsets len (unused in this example)
                                );
                }
            }
        }

        fclose(bin);
    }
}