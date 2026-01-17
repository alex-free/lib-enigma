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
const unsigned char libcrypt_1_medievil_icepick_based_patch[] = {
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
    0x87, // byte 1 of MW // 45 // Magic word is AA87 for Europe
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

const unsigned char libcrypt_1_medievil_icepick_based_patch_pattern_unpatchable_offsets[] = {
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
        printf("Error: incorrect number of arguments\n\nUsage:\nmedip <MediEvil (Europe) .bin file>\n");
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

        if(got_boot_file == 1) // Successfully found boot file.
        {
            printf("MediEvil (Europe) detected, patching LibCrypt v1 protection...\n");
            if((strncmp(boot_file, "SCES_003.11", 11) == 0)) {// /MediEvil (Europe)
                // Pattern contains unmatchable bytes:
                // bin_patch(bin_file, pattern, 1, unmatchable_byte_offsets, patch, unpatchable_bytes, unpatchable_byte_offsets)
                // Pattern contains only matchable bytes:
                // bin_match(bin_file, pattern, 0, 0, patch, 0, 0)
                bin_patch(
                          bin,                                                      // FILE *
                          
                          libcrypt_1_medievil_icepick_based_patch_pattern,          // pattern
                          sizeof(libcrypt_1_medievil_icepick_based_patch_pattern),  // pattern_len
                          
                          true,                                                     // contains_unmatchable_bytes
                          
                          libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets,  // offsets
                          sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unmatchable_offsets), // offsets_len
                          
                          libcrypt_1_medievil_icepick_based_patch,                  // patch
                          sizeof(libcrypt_1_medievil_icepick_based_patch),           // patch_len
                          
                          libcrypt_1_medievil_icepick_based_patch_pattern_unpatchable_offsets,
                          sizeof(libcrypt_1_medievil_icepick_based_patch_pattern_unpatchable_offsets)
                          );
            } else { // Detect APv2 protection.
                printf("Searching for Anti-Piracy v2 (APv2) protection. If found this patch will ONLY allow stock consoles without a mod-chip that use a soft-mod to play them\n");
                bin_patch(
                          bin, // FILE *
                          
                          anti_piracy_v2_vc0_bypass_pattern,// pattern
                          sizeof(anti_piracy_v2_vc0_bypass_pattern),// pattern_len
                          
                          false,// contains_unmatchable_bytes
                          
                          0,  // offsets
                          0, // offsets_len
                          
                          anti_piracy_v2_vc0_bypass_patch, // patch
                          sizeof(anti_piracy_v2_vc0_bypass_patch), // patch_len
                          
                          0, // unpatchable offsets array
                          0 // unpatchable offsets len
                          );
            }
        }

        fclose(bin);
    }
}