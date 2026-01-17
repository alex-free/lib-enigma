// King's Field english translation patcher example for Lib-Enigma, by Alex Free
#include "../lib-enigma.h"
#include "kings-field-eng-translation-with-save-fix-with-undo.h"
//#include "kings-field-eng-translation-with-save-fix-without-undo.h"

int main (int argc, const char * argv[]) 
{
    FILE *bin;
    char boot_file[12];
    
    if(argc != 2) 
    {
        printf("Error: incorrect number of arguments\n\nUsage:\nkfeng <King's Field (Japan) .bin file>\n");
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
            if((strncmp(boot_file, "SLPS_000.17", 11) == 0)) // King's Field (Japan) - this is a PSX.EXE game but is supported by lib-enigma.
	        {
                printf("King's Field (Japan) detected.\n");
                
                // 0x00029F28 0x53 0x00
                int is_patched = id_rev(bin, 0x00029F28, 0x53, 0x00);
                                
                // Translates the original Japanese release of King's Field to english (https://www.romhacking.net/translations/1067/) with save fix (https://www.romhacking.net/translations/7308/). Since these were 2 seperate patches, I applied the english translation to a clean King's Field (Japan) bin file, then applied the save fix, then created a brand new single patch. I did one with undo support and one without.
                
                //apply_ppf(test_ppf30_without_undo, test_ppf30_without_undo_len, bin); // POST-PATCH MD5SUM: c56cfb36f19f2608d3c180c104ace9dd
                //undo_ppf(test_ppf30_without_undo, test_ppf30_without_undo_len, bin); // code catches that this does not support undo
                
                // While the King's Field patch was PPF3.0, it did not have undo support.  So I just re-did the patch with undo support to test both apply and undo type patches.
                if(!is_patched)
                {
                    apply_ppf(test_ppf30_with_undo, test_ppf30_with_undo_len, bin); // POST-PATCH MD5SUM: c56cfb36f19f2608d3c180c104ace9dd
                    printf("Applied English traanslation w/ save fix for King's Field (Japan).\n");
                } else {
                    undo_ppf(test_ppf30_with_undo, test_ppf30_with_undo_len, bin); // ORIGINAL/PRE-PATCH MD5SUM: c2b8b1652407c6c8107b0c93e20624a6
                    printf("Reverted English translation w/ save fix for King's Field (Japan).\n");
                }
            } else {
                printf("%s is not King's Field (Japan)\n", argv[1]);
            }
        }

        fclose(bin);
    }
}