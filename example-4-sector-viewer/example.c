// Sector Viewer example for Lib-Enigma, by Alex Free
#include "../lib-enigma.h"

int main (int argc, const char * argv[]) 
{
    FILE *bin;
    unsigned char raw_sector_buf[SECTOR_RAW_LEN];
    unsigned char user_data_sector_buf[SECTOR_USER_DATA_LEN];
    unsigned char edc_buf[SECTOR_EDC_LEN];
    unsigned char ecc_buf[SECTOR_ECC_LEN];

    int sector_read_ret;
    
    if(argc != 2) 
    {
        printf("Error: incorrect number of arguments\n\nUsage:\nsecview <psx .bin file>\n");
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
    }
    
    unsigned int input;

    printf("Enter sector number to display\n");
    if (scanf("%u", &input) != 1) 
    {
        printf("Error: invalid input\n");
        return 1;
    }

    sector_read_ret = read_sector_raw(bin, input, raw_sector_buf);

    if(sector_read_ret == 1) 
    {
        printf("\nSector %u raw data:\n--------------------------------\n", input);
        
        for (int i = 0; i < SECTOR_RAW_LEN; i++) 
        {
            printf("%02X ", raw_sector_buf[i]);
        }

    } else if(sector_read_ret == 2) {
        printf("Error: sector %u does not exist in input file\n", input);
        fclose(bin);
        return 1;
    } else if(sector_read_ret == 0) {
        printf("Error: can not read sector %u\n", input);
        fclose(bin);
        return 1;
    }

    sector_read_ret = read_sector_user_data(bin, input, user_data_sector_buf);

    if (sector_read_ret == 1) 
    {
        printf("\n\nSector %u user data:\n--------------------------------\n", input);
        
        for (int i = 0; i < SECTOR_USER_DATA_LEN; i++) 
        {
            printf("%02X ", user_data_sector_buf[i]);
        }

    } else if(sector_read_ret == 2) {
        printf("Error: sector %u does not exist in input file\n", input);
        fclose(bin);
        return 1;
    } else if(sector_read_ret == 0) {
        printf("Error: can not read sector %u\n", input);
        fclose(bin);
        return 1;
    }

    sector_read_ret = read_sector_edc(bin, input, edc_buf);

    if (sector_read_ret == 1)
    {
        printf("\n\nSector %u edc:\n--------------------------------\n", input);
        
        for (int i = 0; i < SECTOR_EDC_LEN; i++) 
        {
            printf("%02X ", edc_buf[i]);
        }

    } else if(sector_read_ret == 2) {
        printf("Error: sector %u does not exist in input file\n", input);
        fclose(bin);
        return 1;
    } else if(sector_read_ret == 0) {
        printf("Error: can not read sector %u\n", input);
        fclose(bin);
        return 1;
    }

    sector_read_ret = read_sector_ecc(bin, input, ecc_buf);

    if (sector_read_ret == 1)
    {
        printf("\n\nSector %u ecc:\n--------------------------------\n", input);
        
        for (int i = 0; i < SECTOR_ECC_LEN; i++) 
        {
            printf("%02X ", ecc_buf[i]);
        }

    } else if(sector_read_ret == 2) {
        printf("Error: sector %u does not exist in input file\n", input);
        fclose(bin);
        return 1;
    } else if(sector_read_ret == 0) {
        printf("Error: can not read sector %u\n", input);
        fclose(bin);
        return 1;
    }
    printf("\n");

    fclose(bin);
}