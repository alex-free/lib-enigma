// PlayStation 1 and 2 CD Image Identification/Patching Library (LIB ENIGMA) by Alex Free (3-BSD license)

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

#include "lib-enigma.h"

unsigned int total_number_of_sectors(FILE *bin)
{
    fseek(bin, 0, SEEK_END);
    unsigned int bin_file_size = ftell(bin);
    unsigned int total_number_of_sectors = (bin_file_size / SECTOR_RAW_LEN);
    fseek(bin, 0, SEEK_SET);
    return total_number_of_sectors;
}

int read_sector_raw(FILE *bin, unsigned int sector_number, unsigned char * sector_buf)
{
    unsigned int sector_sum = total_number_of_sectors(bin);

    if(sector_sum < sector_number)
    {
        return 2;
    }

    unsigned int sector_offset = (SECTOR_RAW_LEN * sector_number);
    fseek(bin, sector_offset, SEEK_SET);
    unsigned int ret = fread(sector_buf, 1, SECTOR_RAW_LEN, bin); // Not big endian safe.
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.
    
    if(ret == SECTOR_RAW_LEN)
    {
        return 1;
    } else {
        return 0;
    }
}

int read_sector_user_data(FILE *bin, unsigned int sector_number, unsigned char * sector_buf)
{
    unsigned int sector_sum = total_number_of_sectors(bin);

    if(sector_sum < sector_number)
    {
        return 2;
    }

    unsigned int sector_offset = (SECTOR_RAW_LEN * sector_number) + SECTOR_SYNC_HEADER_LEN;
    fseek(bin, sector_offset, SEEK_SET);
    unsigned int ret = fread(sector_buf, 1, SECTOR_USER_DATA_LEN, bin); // Not big endian safe.
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.

    if(ret == SECTOR_USER_DATA_LEN)
    {
        return 1;
    } else {
        return 0;
    }
}

int read_sector_edc(FILE *bin, unsigned int sector_number, unsigned char * sector_buf)
{
    unsigned int sector_sum = total_number_of_sectors(bin);

    if(sector_sum < sector_number)
    {
        return 2;
    }

    unsigned int sector_offset = (SECTOR_RAW_LEN * sector_number) + (SECTOR_SYNC_HEADER_LEN + SECTOR_USER_DATA_LEN);
    fseek(bin, sector_offset, SEEK_SET);
    unsigned int ret = fread(sector_buf, 1, SECTOR_EDC_LEN, bin); // Not big endian safe.
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.
    
    if(ret == SECTOR_EDC_LEN)
    {
        return 1;
    } else {
        return 0;
    }
}

int read_sector_ecc(FILE *bin, unsigned int sector_number, unsigned char * sector_buf)
{
    unsigned int sector_sum = total_number_of_sectors(bin);

    if(sector_sum < sector_number)
    {
        return 2;
    }

    unsigned int sector_offset = (SECTOR_RAW_LEN * sector_number) + (SECTOR_SYNC_HEADER_LEN + SECTOR_USER_DATA_LEN + SECTOR_EDC_LEN);
    fseek(bin, sector_offset, SEEK_SET);
    unsigned int ret = fread(sector_buf, 1, SECTOR_ECC_LEN, bin); // Not big endian safe.
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.
    
    if(ret == SECTOR_ECC_LEN)
    {
        return 1;
    } else {
        return 0;
    }
}

int write_sector_user_data(FILE *bin, unsigned int sector_number, unsigned char * sector_buf)
{
    unsigned int sector_sum = total_number_of_sectors(bin);

    if(sector_sum < sector_number)
    {
        return 2;
    }

    unsigned int sector_offset = (SECTOR_RAW_LEN * sector_number) + SECTOR_SYNC_HEADER_LEN;
    fseek(bin, sector_offset, SEEK_SET);
    unsigned int ret = fwrite(sector_buf, 1, SECTOR_USER_DATA_LEN, bin); // Not big endian safe.
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.

    if(ret == SECTOR_USER_DATA_LEN)
    {
        return 1;
    } else {
        return 0;
    }
}

int sector_boundary_aware_find_and_replace(FILE *bin,
    unsigned int sector_to_scan, // Sector to start pattern match at.

    const unsigned char *pattern, // Unsigned char array of bytes to be matched.
    int pattern_len, // Length of unsigned char array of bytes to be matched.

    bool contains_unmatchable_bytes, // (Optional) boolean, allows the unsigned char array of bytes to be matched to ignore some offsets. These bytes may still be patched, but they don't have to match.

    const unsigned char *unmatchable_byte_offsets, // (Optional) list of offsets in the unsigned char array of bytes to be matched that must be ignored because they can not be reliably identified. These bytes may still be patched, but they don't have to match.
    int unmatchable_byte_offsets_len, // (Optional) Length of the list of offsets in the unsigned char array of bytes to be matched that must be ignored because they can not be reliably identified. These bytes may still be patched, but they don't have to match.
    
    const unsigned char *patch, // Unsigned char array of bytes that will replace the pattern unsigned char array.
    int patch_len, // Length of unsigned char array of bytes that will replace the pattern unsigned char array.

    const unsigned char *ignored_byte_offsets, // (Optional) list of bytes that will not be modified by the patch but are matched by the pattern.
    int ignored_byte_offsets_len) // (Optional) lenght of of list of bytes that will not be modified by the patch but are matched by the pattern.
{

/*
    The pattern related could possibly start on the end of a sector and end at the beginning of the next sector. Each RAW sector is 0x930 bytes. The first 0x18 bytes are to be ignored as they are just header data. The next 0x800 bytes contains actual data we want to scan through.
    Start at 0. Skip to 0x18. Read the next 0x800 bytes. Skip to a total of 0x930 bytes (one whole raw sector). Skip 0x18 bytes again and then read the next 0x800 bytes. We now have 2 sectors worth of straight up data in a buffer of 0x1000 bytes
    Run search functions on the 0x1000 byte sized buffer.
*/

    #ifdef DEBUG
        printf("\nDEBUG: INPUT PATTERN:\n");
        for (int i = 0; i < pattern_len; i++) {
            printf("02%x\n", pattern[i]);
        }

        printf("\nDEBUG: INPUT PATTERN UNMATCHABLE OFFSETS:\n");

        for (int i = 0; i < unmatchable_byte_offsets_len; i++) {
            printf("%d\n", unmatchable_byte_offsets[i]);
        }

        printf("\nDEBUG: INPUT PATCH:\n");

        for (int i = 0; i < patch_len; i++) {
            printf("%d\n", patch[i]);
        }

        printf("\nDEBUG: INPUT PATCH IGNORED BYTE OFFSETS:\n");

        for (int i = 0; i < ignored_byte_offsets_len; i++) {
            printf("%d\n", ignored_byte_offsets[i]);
        }
    #endif

    // Sanity checks
    unsigned int sector_count = total_number_of_sectors(bin);

    if(sector_to_scan > sector_count)
    {
        return 2; // Sector doesn't exist.
    }

    if(pattern_len > SECTOR_USER_DATA_LEN)
    {
        return 3; // Pattern is too large
    }

    unsigned char ignored_byte = 0;
    unsigned int patched_sector; // Tells us what sector/LBA pattern/patch was applied to.
    unsigned char sectors_buf[(SECTOR_USER_DATA_LEN * 2)]; // Buffer max size is two user datas stitched together.
    int pattern_search_size = 0;
    int pattern_match_count = 0; // If it is greater then 1 by the end this func returns 1 for success. If it is still 0 return 0.

    if(sector_to_scan >= sector_count - 1) // Is the last sector.
    {
        read_sector_user_data(bin, sector_to_scan, sectors_buf);
        pattern_search_size = SECTOR_USER_DATA_LEN;
    } else {
        pattern_search_size = (SECTOR_USER_DATA_LEN * 2);
        read_sector_user_data(bin, sector_to_scan, sectors_buf);
        read_sector_user_data(bin, (sector_to_scan + 1), &sectors_buf[SECTOR_USER_DATA_LEN]); // Put it at 0x800
    }

// So now we have 2 user data portions of consecutive sectors, or just one. Either way, we can just scan through it without worrying about sync headers, EDC, or ECC boundaries messing up a pattern match.

    for(int sector_byte_offset = 0; sector_byte_offset <= (pattern_search_size - pattern_len); sector_byte_offset++)
    {
        bool matched_pattern = true; // Set to false if no match is found.

        for(int pattern_byte_offset = 0; pattern_byte_offset < pattern_len; pattern_byte_offset++) // For length of pattern.
        {                
            if(pattern[pattern_byte_offset] != sectors_buf[sector_byte_offset + pattern_byte_offset]) // Did not match pattern, check if this is an unmatchable byte we want to ignore.
            {
                if(contains_unmatchable_bytes) // Optional unmatchable bytes flag set.
                {
                    bool is_unmatchable_byte = false;

                    for(int unmatchable_byte_offset = 0; unmatchable_byte_offset < unmatchable_byte_offsets_len; unmatchable_byte_offset++) // Go through unmatchable byte pattern.
                    {
                        if(pattern_byte_offset == unmatchable_byte_offsets[unmatchable_byte_offset]) // If this offset is an unmatchable byte offset (offset starts at first byte of pattern to match with, that always lines up).
                        {
                            is_unmatchable_byte = true; // We are not going to say the match failed since this byte was specified to be unmatchable.
                            break;
                        }
                    }

                    if(!is_unmatchable_byte) // The only thing that could have saved this match is if it was unmatchable
                    {
                        matched_pattern = false;
                    }
                } else { // The begining if statement has this as a non-match.
                    matched_pattern = false;
                }
            }
        }

        if(matched_pattern)
        {
            if(sector_byte_offset < SECTOR_USER_DATA_LEN) // We are in the 1st sector's user data.
            {
                patched_sector = sector_to_scan;
            } else { // We are in the second sector's user data.
                patched_sector = (sector_to_scan + 1);
            }
            
            printf("\rGot a pattern code match starting in sector %d (LBA: %u)\n", patched_sector, (patched_sector + PREGAP));

            int ignored_byte_offset_counter = 0;

            for(int i = 0; i < patch_len; i++)
            {                
                if(contains_unmatchable_bytes && 
                ignored_byte_offset_counter < ignored_byte_offsets_len &&
                i == ignored_byte_offsets[ignored_byte_offset_counter])
                {
                    // Skip this byte as it doesn't need to be patched.
                    ignored_byte_offset_counter++;
                } else {
                    sectors_buf[sector_byte_offset + i] = patch[i]; // patch normally
                }
            }

            pattern_match_count++;
        }
    }

    #ifdef DEBUG
        printf("\nDEBUG: sector search complete.\n");
    #endif

    // Write it back.
    if(pattern_search_size == SECTOR_USER_DATA_LEN) // Last sector.
    {
        write_sector_user_data(bin, sector_to_scan, sectors_buf);
    } else {
        unsigned char first_sector_patched_data[SECTOR_USER_DATA_LEN]; // Need to split this up.

        for(int i = 0; i < SECTOR_USER_DATA_LEN; i++)
        {
            first_sector_patched_data[i] = sectors_buf[i];
        }

        write_sector_user_data(bin, sector_to_scan, first_sector_patched_data);
        write_sector_user_data(bin, (sector_to_scan + 1), &sectors_buf[SECTOR_USER_DATA_LEN]); // Last 0x800 bytes in sectors_buf.
    }

    // Return
    if(pattern_match_count > 0)
    {
        return 1;
    } else {
        return 0;
    }

    fseek(bin, 0, SEEK_SET);
}

// Now begin get_psx_exe_gameid(). Note because this is a 'parser' function it doesn't seek the file at all right now. If there were to ever arrise a volume_creation_timestamp conflict, then id_rev() could be used to destingush the file since we already require FILE *bin as first argument in lib-enigma mode. In that case, fpos would be reset to initial 0 before returing the game id for each game.

// Uncomment for Tonyhax International behavior of get_psx_exe_gameid().
//#define IS_FOR_GAME_ID

// Used by get_psx_gameid() and get_boot_file().
bool is_scps = false;
// We need to specify this as an intenral global var since we call it internally from get_boot_file().
char volume_creation_timestamp[17];

#if defined IS_FOR_GAME_ID
    const char * get_psx_exe_gameid(char *volume_creation_timestamp)
#else
    const char * get_psx_exe_gameid(FILE *bin, char *volume_creation_timestamp)
#endif
{
    /*
    Special handling for PSX.EXE games with memcardpro. Currently this library support games that meet the below crtera:
    * An officially licensed discs with a PSX.EXE bootfile (or some variant of it, i.e. psx.exe). Betas, Alphas, or unreleased games usually don't have a common sense product code/serial to send to the memcardpro and are currently not implemented.
    * The game Has features that actively utilize a memory card. If there is no saving functionality in the game, then why waste executable space for it?
    
    Japanese PSX games from launch day (12/3/1994) to 7/12/1995 (the date of the below memo found in the Sony BBS archive: http://psx.arthus.net/sdk/Psy-Q/DOCS/BBS/scea_bbs.pdf)  did not consistently follow the bootfile name format:
    ======================================================================
    7/12/95 10:43 AM
    URGENT!! CD mastering information
    Thomas Boyd
    News
    Late Late Breaking News from Japan: ---------------------------------------------------- Do not name your
    executable PSX.EXE Name your executable after the following convention:
    Use your product code (AAAA-XXXXX) and turn it into a file name by inserting a period after
    the eighth character.
    Example: AAAA-XXXXX = SLUS-12345
    Product code: SLUS-12345 Executable name on CD: SLUS-123.45;1
    To run the main file, build SYSTEM.CNF and put it in your root directory. SYSTEM.CNF should
    look like this:
    BOOT=cdrom:\AAAA-XXX.XX;1 (in the example this TCB=4 would
    be SLUS-123.45;1) EVENT=10 STACK=801fff00

    ======================================================================

    Some Japanese PSX games were released not following the bootfile name format even after the memo. It appears to myself that by October 1995, it got a lot more consistant with following the bootfile name format.

    All PSX games have an serial product code, even the ones that don't make the product code the bootfile name. This is what needs to be sent as the game id to the memcardpro for games that don't follow the bootfile name format.

    In order to find such games, I used the redump,org search functionality to search for the "PSX.EXE" and "PSXEXE" comments on the redump pages of all PlayStation games. This doesn't get you all such games as leaving a comment on a redump upload mentioning the PSX.EXE boot file are left inconstantly by different up-loaders. There were also some false positives with these searches:

    * http://redump.org/discs/quicksearch/PSX.EXE/comments/only
    * http://redump.org/discs/quicksearch/PSXEXE/comments/only

    
    In order to find the remaining games, I decided to search through all disc images from SLPS_00001 to SLPS_00152. While the product serial codes are not perfectly sequential in regards to release date, by time you get to SLPS_00152 your in at least late 1995 for most release dates of games. At that point most games are following the correct bootfile format.

    ======================================================================
    Implementation Notes:
    
    1) Read Sector 16. From NO$PSX SPX (https://problemkaputt.de/psx-spx.htm#cdromisovolumedescriptors), sector 16 contains:

    ======================================================================
    Primary Volume Descriptor (sector 16 on PSX disks)

    000h 1    Volume Descriptor Type        (01h=Primary Volume Descriptor)
    001h 5    Standard Identifier           ("CD001")
    006h 1    Volume Descriptor Version     (01h=Standard)
    007h 1    Reserved                      (00h)
    008h 32   System Identifier             (a-characters) ("PLAYSTATION")
    028h 32   Volume Identifier             (d-characters) (max 8 chars for PSX?)
    048h 8    Reserved                      (00h)
    050h 8    Volume Space Size             (2x32bit, number of logical blocks)
    058h 32   Reserved                      (00h)
    078h 4    Volume Set Size               (2x16bit) (usually 0001h)
    07Ch 4    Volume Sequence Number        (2x16bit) (usually 0001h)
    080h 4    Logical Block Size in Bytes   (2x16bit) (usually 0800h) (1 sector)
    084h 8    Path Table Size in Bytes      (2x32bit) (max 800h for PSX)
    08Ch 4    Path Table 1 Block Number     (32bit little-endian)
    090h 4    Path Table 2 Block Number     (32bit little-endian) (or 0=None)
    094h 4    Path Table 3 Block Number     (32bit big-endian)
    098h 4    Path Table 4 Block Number     (32bit big-endian) (or 0=None)
    09Ch 34   Root Directory Record         (see next chapter)
    0BEh 128  Volume Set Identifier         (d-characters) (usually empty)
    13Eh 128  Publisher Identifier          (a-characters) (company name)
    1BEh 128  Data Preparer Identifier      (a-characters) (empty or other)
    23Eh 128  Application Identifier        (a-characters) ("PLAYSTATION")
    2BEh 37   Copyright Filename            ("FILENAME.EXT;VER") (empty or text)
    2E3h 37   Abstract Filename             ("FILENAME.EXT;VER") (empty)
    308h 37   Bibliographic Filename        ("FILENAME.EXT;VER") (empty)
    32Dh 17   Volume Creation Timestamp     ("YYYYMMDDHHMMSSFF",timezone)
    33Eh 17   Volume Modification Timestamp ("0000000000000000",00h)
    34Fh 17   Volume Expiration Timestamp   ("0000000000000000",00h)
    360h 17   Volume Effective Timestamp    ("0000000000000000",00h)
    371h 1    File Structure Version        (01h=Standard)
    372h 1    Reserved for future           (00h-filled)
    373h 141  Application Use Area          (00h-filled for PSX and VCD)
    400h 8    CD-XA Identifying Signature   ("CD-XA001" for PSX and VCD)
    408h 2    CD-XA Flags (unknown purpose) (00h-filled for PSX and VCD)
    40Ah 8    CD-XA Startup Directory       (00h-filled for PSX and VCD)
    412h 8    CD-XA Reserved                (00h-filled for PSX and VCD)
    41Ah 345  Application Use Area          (00h-filled for PSX and VCD)
    573h 653  Reserved for future           (00h-filled)
    ======================================================================
    Volume Descriptor Timestamps
    The various timestamps occupy 17 bytes each, in form of

    "YYYYMMDDHHMMSSFF",timezone
    "0000000000000000",00h         ;empty timestamp

    The first 16 bytes are ASCII Date and Time digits (Year, Month, Day, Hour, Minute, Second, and 1/100 Seconds. The last byte is Offset from Greenwich Mean Time in number of 15-minute steps from -48 (West) to +52 (East); or actually: to +56 when recursing Kiribati's new timezone.
    Note: PSX games manufactured in year 2000 were accidentally marked to be created in year 0000.
    ======================================================================

    2) We use the Volume Creation Timestamp at offset 0x32D to identify what game we have. So far there have been no conflicts between games, this value is unique enough.

    3) We send back the serial as SLPS by default. In order to signify it is SCPS we set a boolean to true.

    ======================================================================

    4) You need to rebuild the full serial number (this is because we only send back unique parts of the string that will be sent as the final GameID to save executable space). See 'secondary.c' for the implementation of this.
    */

    // Ordered by serial number.
    
    // Begin SLPS.

    if(strcmp( (char *)volume_creation_timestamp, "1994111009000000") == 0) { // Ridge Racer (Japan) - http://redump.org/disc/2679/.
        return "000.01"; // Uses 1 MC block - https://psxdatacenter.com/games/J/R/SLPS-00001.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994110702000000") == 0) { // Gokujou Parodius Da! Deluxe Pack (Japan) - http://redump.org/disc/5337/.
        return "000.02"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00002.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994102615231700") == 0) { // Tama: Adventurous Ball in Giddy Labyrinth (Japan) - http://redump.org/disc/6980/.
        return "000.03"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00003.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1994110218594700") == 0) || // A Ressha de Ikou 4: Evolution (Japan) (Rev 0) - http://redump.org/disc/21858/.
    (strcmp( (char *)volume_creation_timestamp, "1995030218052000") == 0) // A Ressha de Ikou 4: Evolution (Japan) (Rev 1) - http://redump.org/disc/21858/.
    ) {
        return "000.04"; // Uses 15 MC blocks - https://psxdatacenter.com/games/J/A/SLPS-00004.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1994110722360400") == 0) || // Mahjong Station Mazin (Japan) (Rev 0) - http://redump.org/disc/63533/.
    (strcmp( (char *)volume_creation_timestamp, "1994120610494900") == 0) // Mahjong Station Mazin (Japan) (Rev 1) - http://redump.org/disc/10881/.
    ) {
        return "000.05"; // Uses 1 MC blocks - https://psxdatacenter.com/games/J/M/SLPS-00005.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994110407000000") == 0) { // Nekketsu Oyako (Japan) - http://redump.org/disc/10088/.
        return "000.06"; // Uses 1 MC block -https://psxdatacenter.com/games/J/N/SLPS-00006.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994111419300000") == 0) { // Geom Cube (Japan) - http://redump.org/disc/14660/.
        return "000.07"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00007.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994121808190700") == 0) { // Metal Jacket (Japan) - http://redump.org/disc/5927/.
        return "000.08"; // Uses 2 MC blocks - https://psxdatacenter.com/games/J/M/SLPS-00008.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994121917000000") == 0) { // Cosmic Race (Japan) - http://redump.org/disc/16058/.
        return "000.09"; // Uses 7 MC blocks - https://psxdatacenter.com/games/J/C/SLPS-00009.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995052918000000") == 0) { // Falcata: Astran Pardma no Monshou (Japan) - http://redump.org/disc/1682/.
        return "000.10"; // Uses 4 MC blocks - https://psxdatacenter.com/games/J/F/SLPS-00010.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994110220020600") == 0) { // A Ressha de Ikou 4: Evolution (Japan) (Hatsubai Kinen Gentei Set) - http://redump.org/disc/70160/.
        return "000.11"; // Uses 15 MC blocks - https://psxdatacenter.com/games/J/A/SLPS-00011.html.
    } else if

    // SLPS_00012 (https://psxdatacenter.com/games/J/S/SLPS-00012.html) bootfile is 'START.EXE' with a SYSTEM.CNF. This is the discs Space Griffon VF-9 (Japan) (Rev 0) - http://redump.org/disc/5914/ and Space Griffon VF-9 (Japan) (Rev 1) - http://redump.org/disc/45998/.

    (strcmp( (char *)volume_creation_timestamp, "1994121518000000") == 0) { // Raiden Project (Japan) - http://redump.org/disc/3774/.
        return "000.13"; // Uses 1 MC block - https://psxdatacenter.com/games/J/R/SLPS-00013.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994103000000000") == 0) { // Mahjong Gokuu Tenjiku (Japan) - http://redump.org/disc/17392/.
        return "000.14"; // Uses 4 MC blocks - https://psxdatacenter.com/games/J/M/SLPS-00014.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994101813262400") == 0) { // TwinBee Taisen Puzzle-dama (Japan) - http://redump.org/disc/22905/.
        return "000.15"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00015.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1994112617300000") == 0) || // Jikkyou Powerful Pro Yakyuu '95 (Japan) (Rev 0) - http://redump.org/disc/9552/.
    (strcmp( (char *)volume_creation_timestamp, "1994121517300000") == 0) // // Jikkyou Powerful Pro Yakyuu '95 (Japan) (Rev 1) - http://redump.org/disc/27931/.
    ) {
        return "000.16"; // Uses 3 MC blocks - https://psxdatacenter.com/games/J/J/SLPS-00016.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994111013000000") == 0) { // King's Field (Japan) - http://redump.org/disc/7072/.
        return "000.17"; // Uses 5 MC blocks - https://psxdatacenter.com/games/J/K/SLPS-00017.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994111522183200") == 0) { // Twin Goddesses (Japan) - http://redump.org/disc/7885/.
        return "000.18"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00018.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994112918000000") == 0) { // Kakinoki Shougi (Japan) - http://redump.org/disc/22869/.
        return "000.19"; // Uses 4 MC blocks - https://psxdatacenter.com/games/J/K/SLPS-00019.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994111721302100") == 0) { // Houma Hunter Lime: Special Collection Vol. 1 (Japan) - http://redump.org/disc/18606/.
        return "000.20"; // Uses 1 MC block - https://psxdatacenter.com/games/J/H/SLPS-00020.html
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994100617242100") == 0) { // Kikuni Masahiko Jirushi: Warau Fukei-san Pachi-Slot Hunter (Japan) - http://redump.org/disc/33816/.
        return "000.21"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00021.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995030215000000") == 0) { //Starblade Alpha (Japan) - http://redump.org/disc/4664/.
        return "000.22"; // Uses 1 MC block - https://psxdatacenter.com/games/J/S/SLPS-00022.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994122718351900") == 0) { //CyberSled (Japan) - http://redump.org/disc/7879/.
        return "000.23"; // Uses 1 MC block - https://psxdatacenter.com/games/J/C/SLPS-00023.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994092920284600") == 0) { // Myst (Japan) (Rev 0) - http://redump.org/disc/4786/ / Myst (Japan) (Rev 1)  - http://redump.org/disc/33887/ /  Myst (Japan) (Rev 2)  - http://redump.org/disc/1488/.
        return "000.24"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00024.html.
    } else if  

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1994113012000000") == 0) || // Toushinden (Japan) (Rev 0) - http://redump.org/disc/1560/.
    (strcmp( (char *)volume_creation_timestamp, "1995012512000000") == 0) // Toushinden (Japan) (Rev 1) - http://redump.org/disc/23826/.
    ) { // We don't care about revision differences!
        return "000.25"; // Uses 1 MC block - https://psxdatacenter.com/games/J/B/SLPS-00025.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995041921063500") == 0) { // Rayman (Japan) - http://redump.org/disc/33719/.
        return "000.26"; // Uses 3 MC blocks - https://psxdatacenter.com/games/J/R/SLPS-00026.html.
    } else if  

    (strcmp( (char *)volume_creation_timestamp, "1994121500000000") == 0) { // Kileak, The Blood (Japan) - http://redump.org/disc/14371/.
        return "000.27"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00027.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1994121017582300") == 0) { // Jigsaw World (Japan) - http://redump.org/disc/14455/.
        return "000.28"; // Uses 1 MC block - https://psxdatacenter.com/games/J/J/SLPS-00028.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995022623000000") == 0) { // Idol Janshi Suchie-Pai Limited (Japan) - http://redump.org/disc/33789/.
        return "000.29"; // Uses 1 MC block - https://psxdatacenter.com/games/J/I/SLPS-00029.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1995050116000000") == 0) || // Game no Tatsujin (Japan) (Rev 0) - http://redump.org/disc/36035/.
    (strcmp( (char *)volume_creation_timestamp, "1995060613000000") == 0) // Game no Tatsujin (Japan) (Rev 1) - http://redump.org/disc/37866/.
    ) {
        return "000.30"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00030.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995021802000000") == 0) { // Kyuutenkai (Japan) - http://redump.org/disc/37548/.
        return "000.31"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00031.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995021615022900") == 0) { // Uchuu Seibutsu Flopon-kun P! (Japan) - http://redump.org/disc/18814/.
        return "000.32"; // Uses 1 MC block - https://psxdatacenter.com/games/J/U/SLPS-00032.html.
    } else if

    (
    (strcmp( (char *)volume_creation_timestamp, "1995100209000000") == 0) || // Boxer's Road (Japan) (Rev 1) - http://redump.org/disc/6537/.
    (strcmp( (char *)volume_creation_timestamp, "1995080809000000") == 0) // Boxer's Road (Japan) (Rev 0) - http://redump.org/disc/2765/.
    ) {
        return "000.33"; // Serial from Rev 0 CD case. Rev 1 serial is SLPS-91007. Uses 7 MC blocks - https://psxdatacenter.com/games/J/B/SLPS-00033.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995071821394900") == 0) { // Zeitgeist (Japan) - http://redump.org/disc/16333/.
        return "000.34"; // Uses 1 MC block - https://psxdatacenter.com/games/J/Z/SLPS-00034.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995042506300000") == 0) { // Mobile Suit Gundam (Japan) - http://redump.org/disc/3080/.
        return "000.35"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00035.html.
    } else if

    // SLPS_000.36 has a proper bootfile: http://redump.org/disc/6599/

    (strcmp( (char *)volume_creation_timestamp, "1995011411551700") == 0) { // Pachio-kun: Pachinko Land Daibouken (Japan) - http://redump.org/disc/36504/.
        return "000.37"; // Uses 2 MC block - https://psxdatacenter.com/games/J/P/SLPS-00037.html.
    } else if  

    (strcmp( (char *)volume_creation_timestamp, "1995041311392800") == 0) { // Nichibutsu Mahjong: Joshikou Meijinsen (Japan) - http://redump.org/disc/35101/.
        return "000.38"; // Uses 1 MC block - https://psxdatacenter.com/games/J/N/SLPS-00038.html.
    } else if

    // SLPS_00039 Metamor Panic: Doki Doki Youma Busters!! (Japan) - http://redump.org/disc/34086/ has a proper bootfile name 'SLPS_000.39'.

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1995031205000000") == 0) || // Tekken (Japan) (Rev 0) - http://redump.org/disc/671/.
    (strcmp( (char *)volume_creation_timestamp, "1995061612000000") == 0) // Tekken (Japan) (Rev 1) - http://redump.org/disc/1807/.
    ) { // We don't care about revision differences!
        return "000.40"; // Using CD case serial.
        //debug_write("Tekken (Japan) (Rev 0) / (Rev 1)"); // 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00040.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995040509000000") == 0) { // Gussun Oyoyo (Japan) - http://redump.org/disc/11336/.
        return "000.41"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00041.html.
    } else if

    // SLPS_00042 DOESN't EXIST??!! - https://github.com/julianxhokaxhiu/iPoPS/blob/master/PSXListOFGames.txt.

    (strcmp( (char *)volume_creation_timestamp, "1995052612000000") == 0) { // Mahjong Ganryuu-jima (Japan) - http://redump.org/disc/33772/
        return "000.43"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00043.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995042500000000") == 0) { // Hebereke Station Popoitto (Japan) - http://redump.org/disc/36164/
        return "000.44"; // Uses 1 MC block - https://psxdatacenter.com/games/J/H/SLPS-00044.html.
    } else if

    // SLPS_00045 DOESN't EXIST??!! - https://github.com/julianxhokaxhiu/iPoPS/blob/master/PSXListOFGames.txt.

    // SLPS_00046 Universal Virtua Pachi-Slot: Hisshou Kouryakuhou (Japan) - http://redump.org/disc/36344/ has a proper bootfile 'PACH.EXE'.

    (strcmp( (char *)volume_creation_timestamp, "1995033100003000") == 0) { // Missland (Japan) - http://redump.org/disc/10869/.
        return "000.47"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00047.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995041400000000") == 0) { // Gokuu Densetsu: Magic Beast Warriors (Japan) - http://redump.org/disc/24258/.
        return "000.48"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00048.html.
    } else if

    // SLPS_00049 DOESN't EXIST??!! - https://github.com/julianxhokaxhiu/iPoPS/blob/master/PSXListOFGames.txt.

    (strcmp( (char *)volume_creation_timestamp, "1995050413421800") == 0) { // Night Striker (Japan) - http://redump.org/disc/10931/.
        return "000.50"; // Uses 1 MC block - https://psxdatacenter.com/games/J/N/SLPS-00050.html.
    } else if  

    (strcmp( (char *)volume_creation_timestamp, "1995040509595900") == 0) { // Entertainment Jansou: That's Pon! (Japan) - http://redump.org/disc/34808/.
        return "000.51"; // Uses 2 MC blocks - https://psxdatacenter.com/games/J/T/SLPS-00051.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995030103150000") == 0) { //Kanazawa Shougi '95 (Japan) - http://redump.org/disc/34246/.
        return "000.52"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00052.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995100409235300") == 0) { //Thoroughbred Breeder II Plus (Japan) - http://redump.org/disc/33282/.
        return "000.53"; // Uses 5 MC block - https://psxdatacenter.com/games/J/T/SLPS-00053.html.
    } else if

    // SLPS_00054 Yaoi Jun'ichi Gokuhi Project: UFO o Oe!! (Japan) - http://redump.org/disc/28631/ has proper bootfile 'SLPS_000.54'.

    #if defined IS_FOR_GAME_ID
        // We need one GameID sent so that all discs can acccess the same memory card image.

        ( 
        (strcmp( (char *)volume_creation_timestamp, "1995060504013600") == 0) || // Cyberwar (Japan) (Disc 1) - http://redump.org/disc/30637/.
        (strcmp( (char *)volume_creation_timestamp, "1995060319142200") == 0) || // Cyberwar (Japan) (Disc 2) - http://redump.org/disc/30638/.
        (strcmp( (char *)volume_creation_timestamp, "1995060402110800") == 0) // Cyberwar (Japan) (Disc 3) - http://redump.org/disc/30639/.
        ) {
            return "000.55"; // Using Disc 1 CD case serial: http://redump.org/disc/30637/. All CDs assigned to same memory card. SLPS_00056 is Disc 2, and SLPS_00057 is Disc 3. Uses 1 MC block - https://psxdatacenter.com/games/J/C/SLPS-00055.html.
        } else if

    #else

        (strcmp((char *)volume_creation_timestamp, "1995060504013600") == 0) { // Cyberwar (Japan) (Disc 1) - http://redump.org/disc/.
            return "000.55"; // Uses 1 MC block.
        } else if

        (strcmp((char *)volume_creation_timestamp, "1995060319142200") == 0) { // Cyberwar (Japan) (Disc 2) - http://redump.org/disc/30638/.
            return "000.56"; // Uses 1 MC block.
        } else if

        (strcmp((char *)volume_creation_timestamp, "1995060402110800") == 0) { // Cyberwar (Japan) (Disc 3) - http://redump.org/disc/30639/.
            return "000.57"; // Uses 1 MC block.
        } else if

    #endif
    
    // SLPS_0058 Ide Yousuke no Mahjong Kazoku (Japan) (Rev 0) - http://redump.org/disc/34169/ and Ide Yousuke no Mahjong Kazoku (Japan) (Rev 1) - http://redump.org/disc/33562/ have a proper bootfile 'SLPS_000.58'.

    (strcmp( (char *)volume_creation_timestamp, "1995081612000000") == 0) { // Taikyoku Shougi: Kiwame (Japan) - http://redump.org/disc/35288/.
        return "000.59"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00059.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995051201000000") == 0) { // Aquanaut no Kyuujitsu (Japan) - http://redump.org/disc/16984/.
        return "000.60"; // Uses 4 MC block - https://psxdatacenter.com/games/J/A/SLPS-00060.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995051700000000") == 0) { // Ace Combat (Japan) - http://redump.org/disc/1691/.
        return "000.61"; // Uses 1 MC block - https://psxdatacenter.com/games/J/A/SLPS-00061.html.
    } else if

    // SLPS_00062 Hyper Formation Soccer (Japan) - http://redump.org/disc/2602/ has a proper bootfile 'SLPS_00062'.

    (strcmp( (char *)volume_creation_timestamp, "1995051002471900") == 0) { // Keiba Saishou no Housoku '95 (Japan) - http://redump.org/disc/22944/
        return "000.63"; // Uses 15 MC blocks - https://psxdatacenter.com/games/J/K/SLPS-00063.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1995083112000000") == 0) || // Tokimeki Memorial: Forever with You (Japan) (Rev 1) - http://redump.org/disc/6789/ / Tokimeki Memorial: Forever with You (Japan) (Shokai Genteiban) (Rev 1) - http://redump.org/disc/6788/.
    (strcmp( (char *)volume_creation_timestamp, "1995111700000000") == 0) // Tokimeki Memorial: Forever with You (Japan) (Rev 2) - http://redump.org/disc/33338/.
        // Tokimeki Memorial: Forever with You (Japan) (PlayStation The Best) - http://redump.org/disc/8876/ has it's own different serial and proper bootfile name, so already works with mcpro!
    ) {
        return "000.64"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00064.html
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1996033100000000") == 0) { // Tokimeki Memorial: Forever with You (Japan) (Rev 4) - http://redump.org/disc/6764/.
        return "000.65"; // Why it is different from the above? No clue. Not a typo though. Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00065.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995051816000000") == 0) { // Kururin Pa! (Japan) - http://redump.org/disc/33413/.
        return "000.66"; // Serial from CD case.
        //debug_write("Kururin Pa! (Japan)"); // 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00066.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995061418000000") == 0) { // Jikkyou Powerful Pro Yakyuu '95: Kaimakuban (Japan) - http://redump.org/disc/14367/.
        return "000.67"; // Uses 3 MC blocks - https://psxdatacenter.com/games/J/J/SLPS-00067.html.
    } else if

    ( 
    (strcmp( (char *)volume_creation_timestamp, "1995061911303400") == 0) || // J.League Jikkyou Winning Eleven (Japan) (Rev 0) - http://redump.org/disc/6740/.
    (strcmp( (char *)volume_creation_timestamp, "1995072800300000") == 0) // // J.League Jikkyou Winning Eleven (Japan) (Rev 1) - http://redump.org/disc/2848/.
    ) {
        return "000.68"; // Uses 1 MC block - https://psxdatacenter.com/games/J/J/SLPS-00068.html.
    } else if

    (
    (strcmp( (char *)volume_creation_timestamp, "1995061207000000") == 0) || // King's Field II (Japan) - http://redump.org/disc/5892/.
    (strcmp( (char *)volume_creation_timestamp, "1995061806364400") == 0) // King's Field II (Japan) (PlayStation The Best) (Rev 0) - http://redump.org/disc/7073/ / King's Field II (Japan) (PlayStation The Best) (Rev 1) - http://redump.org/disc/13338/.
    ) {
        return "000.69"; // Uses 2-15 MC blocks - https://psxdatacenter.com/games/J/K/SLPS-00069.html.
    } else if
    
    // King's Field II (Japan) (PlayStation the Best) (Rev 0) - http://redump.org/disc/7073/ and King's Field II (Japan) (PlayStation the Best) (Rev 1) - http://redump.org/disc/13338/ have a proper bootfile 'SLPS_910.03'.

    (strcmp( (char *)volume_creation_timestamp, "1995062922000000") == 0) { //Street Fighter: Real Battle on Film (Japan) - http://redump.org/disc/26158/
        return "000.70"; // Uses 1 MC block - https://psxdatacenter.com/games/J/S/SLPS-00070.html.
    } else if

    #if defined IS_FOR_GAME_ID
        // We need one GameID sent so that all discs can acccess the same memory card image. With lib-enigma that isn't useful and we instead want to identify each disc.
        
        (strcmp( (char *)volume_creation_timestamp, "1995040719355400") == 0) { // 3x3 Eyes: Kyuusei Koushu (Disc 1) (Japan) - http://redump.org/disc/7881/ / 3x3 Eyes: Kyuusei Koushu (Disc 2) (Japan) http://redump.org/disc/7880/.
            return "000.71"; // Using disc 1 CD case serial: http://redump.org/disc/7881/. Disc 2 serial is SLPS_00072. All CDs assigned to same memory card. Uses 1 MC block - https://psxdatacenter.com/games/J/0-9/SLPS-00071.html.
        } else if

    #else

        (strcmp((char *)volume_creation_timestamp, "1995040719355400") == 0) { // 3x3 Eyes - Kyuusei Koushu (Japan) (Disc 1) - http://redump.org/disc/7881/
            return "000.71"; // Uses 1 MC block - https://psxdatacenter.com/games/J/0-9/SLPS-00071.html.
        } else if

        (strcmp((char *)volume_creation_timestamp, "1995040719355400") == 0) { // 3x3 Eyes - Kyuusei Koushu (Japan) (Disc 2) -  http://redump.org/disc/7880/
            return "000.72"; // Uses 1 MC block - https://psxdatacenter.com/games/J/0-9/SLPS-00072.html.
        } else if

    #endif

    (strcmp( (char *)volume_creation_timestamp, "1995061806364400") == 0) { // Dragon Ball Z: Ultimate Battle 22 (Japan) - http://redump.org/disc/10992/.
        return "000.73"; // Uses 1 MC block - https://psxdatacenter.com/games/J/D/SLPS-00073.html.
    } else if

    // SLPS_00074 Sparrow Garden: Namco Mahjong (Japan) - http://redump.org/disc/35289/ has a proper bootfile 'SLPS_000.74"

    // SLPS_00075 World Stadium EX (Japan) (Rev 0) - http://redump.org/disc/10903/ and  SLPS_00075 World Stadium EX (Japan) (Rev 1) - http://redump.org/disc/10904/ have a proper bootfile 'SLPS_000.75".

    // SLPS_00076 doesn't exist - https://github.com/julianxhokaxhiu/iPoPS/blob/master/PSXListOFGames.txt.

    (strcmp( (char *)volume_creation_timestamp, "1995051015300000") == 0) { // Douga de Puzzle da! Puppukupuu (Japan) - http://redump.org/disc/11935/
        return "000.77"; // Uses 13 MC blocks - https://psxdatacenter.com/games/J/D/SLPS-00077.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995070302000000") == 0) { // Gakkou no Kowai Uwasa: Hanako-san ga Kita!! (Japan) - http://redump.org/disc/11935/
        return "000.78"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00078.html.
    } else if

    // SLPS_00079E J.League Soccer: Prime Goal EX (Japan) (Lawson Station) - http://redump.org/disc/67854/ and  SLPS_00079 J.League Soccer: Prime Goal EX (Japan) - http://redump.org/disc/67854/ have a proper bootfile 'SLPS_000.79".

    // SLPS_00080 Street Fighter II Movie (Disc 1) (Japan) - http://redump.org/disc/18429/ has a proper bootfile 'SLPS_000.80".

    // SLPS_00081 Street Fighter II Movie (Disc 2) (Japan) - http://redump.org/disc/18430/ has a proper bootfile 'SLPS_000.81".

    // SLPS_00082 Shichuu Suimei Pitagraph (Japan) - http://redump.org/disc/33850/ has a proper bootfile 'SLPS_000.82".

    (strcmp( (char *)volume_creation_timestamp, "1995070523450000") == 0) { // Zero Divide (Japan) - http://redump.org/disc/99925/.
        return "000.83"; // Uses 1 MC block - https://psxdatacenter.com/games/J/Z/SLPS-00083.html.
    } else if

    // SLPS_00084 Shin Nihon Pro Wrestling: Toukon Retsuden (Japan) - http://redump.org/disc/12635/ has a proper bootfile 'SLPS_000.84".

    (strcmp( (char *)volume_creation_timestamp, "1995072522004900") == 0) { // Houma Hunter Lime: Special Collection Vol. 2 (Japan) - http://redump.org/disc/18607/.
        return "000.85"; // Uses 1 MC block - https://psxdatacenter.com/games/J/I/SLPS-00029.html.
    } else if

    // SLPS_00086 Kaitei Daisensou: In the Hunt (Japan) - http://redump.org/disc/9478/ has a proper bootfile 'SLPS_000.86".

    // SLPS_00087 The Perfect Golf (Japan) - http://redump.org/disc/11332/ has a proper bootfile 'SLPS_000.87".

    (strcmp( (char *)volume_creation_timestamp, "1995070613170000") == 0) { // Ground Stroke: Advanced Tennis Game (Japan) - http://redump.org/disc/33778/
        return "000.88"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00088.html
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995082517551900") == 0) { // The Oni Taiji!!: Mezase! Nidaime Momotarou (Japan) - http://redump.org/disc/33948/
        return "000.89"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00089.html
    } else if  

    // The Oni Taiji!!: Mezase! Nidaime Momotarou (Japan) (Major Wave) - http://redump.org/disc/70837/ has a proper bootfile 'SLPM_869.89'.

    (strcmp( (char *)volume_creation_timestamp, "1995082109402500") == 0) { // Eisei Meijin (Japan) (Rev 1) - http://redump.org/disc/37494/
        return "000.90"; // Uses 3 MC blocks - https://psxdatacenter.com/games/J/E/SLPS-00090.html.
    } else if  

    // Eisei Meijin (Japan) (Rev 0) has never been dumped because it may not exist: http://wiki.redump.org/index.php?title=Sony_PlayStation_-_Asia_Undumped_Discs#Undumped_Revisions. 

    (strcmp( (char *)volume_creation_timestamp, "1995053117000000") == 0) { // Exector (Japan) - http://redump.org/disc/2814/.
        return "000.91"; // Uses 1 MC block - https://psxdatacenter.com/games/J/E/SLPS-00091.html.
    } else if 

    (strcmp( (char *)volume_creation_timestamp, "1995081100000000") == 0) { // King of Bowling (Japan) - http://redump.org/disc/34727/.
        return "000.92"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-00092.html.
    } else if  

    (strcmp( (char *)volume_creation_timestamp, "1995071011035200") == 0) { // Oh-chan no Oekaki Logic (Japan) - http://redump.org/disc/7882/.
        return "000.93"; // Uses 1 MC block - https://psxdatacenter.com/games/J/O/SLPS-00093.html.
    } else if

    #if defined IS_FOR_GAME_ID
        //We need one GameID sent so that all discs can acccess the same memory card image. With lib-enigma that isn't useful and we instead want to identify each disc.

        ( 
        (strcmp( (char *)volume_creation_timestamp, "1995090510000000") == 0) || // Thunder Storm & Road Blaster (Disc 1) (Thunder Storm) (Japan) - http://redump.org/disc/6740/.
        (strcmp( (char *)volume_creation_timestamp, "1995083123000000") == 0) // Thunder Storm & Road Blaster (Disc 2) (Road Blaster) (Japan) - http://redump.org/disc/8551/.
        ) {
            return "000.94"; // Serial from Disc 1 CD case. Disc 2 serial is SLPS_00095. Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00094.html.
        } else if
    
    #else

        (strcmp((char *)volume_creation_timestamp, "1995090510000000") == 0) { // Thunder Storm & Road Blaster (Japan) (Disc 1) (Thunder Storm)
            return "000.94"; // Serial from Disc 1 CD case. Disc 2 serial is SLPS_00095. Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00094.html.
        } else if


        (strcmp((char *)volume_creation_timestamp, "1995083123000000") == 0) { // Thunder Storm & Road Blaster (Japan) (Disc 2) (Road Blaster)
            return "000.95"; // Serial from Disc 1 CD case. Disc 2 serial is SLPS_00095. Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00094.html.
        } else if

    #endif

    
    // SLPS_00096 Game no Tetsujin: The Shanghai (Japan) - http://redump.org/disc/36470/ has a proper bootfile 'SLPS_000.96".

    // SLPS_00097 Gensou Suikoden (Japan) - http://redump.org/disc/7461/ has a proper bootfile 'SLPS_000.97".

    // SLPS_00098 Ray Tracers (Japan) - http://redump.org/disc/34232/ has a proper bootfile 'SLPS_000.98".

    (strcmp( (char *)volume_creation_timestamp, "1995100601300000") == 0) { // Moero!! Pro Yakyuu '95: Double Header (Japan) - http://redump.org/disc/34818/.
        return "000.99"; // Uses 6 MC blocks - https://psxdatacenter.com/games/J/M/SLPS-00099.html.
    } else if

    // SLPS_00100 Detana Twinbee Yahoo! Deluxe Pack (Japan) - http://redump.org/disc/5336/ has a proper bootfile 'SLPS_001.00'.

    (strcmp( (char *)volume_creation_timestamp, "1995081001450000") == 0) { // Universal-ki Kanzen Kaiseki: Pachi-Slot Simulator (Japan) - http://redump.org/disc/36304/.
        return "001.01"; // Uses 2 MC block - https://psxdatacenter.com/games/J/U/SLPS-00101.html.
    } else if

    // SLPS_00102 Twilight Syndrome: Tansaku-hen (Japan) - http://redump.org/disc/6840/ has a proper bootfile 'SLPS_001.02'.

    (strcmp( (char *)volume_creation_timestamp, "1995080316000000") == 0) { // V-Tennis (Japan) - http://redump.org/disc/22684/.
        return "001.03"; // Uses 1 MC block - https://psxdatacenter.com/games/J/V/SLPS-00103.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995081020000000") == 0) { // Gouketsuji Ichizoku 2: Chotto dake Saikyou Densetsu (Japan) - http://redump.org/disc/12680/.
        return "001.04"; // Uses 1 MC block - https://psxdatacenter.com/games/J/G/SLPS-00104.html.
    } else if

    // SLPS_00105 Total Eclipse Turbo (Japan) - http://redump.org/disc/27059/ has a proper bootfile 'SLPS_00105'.

    // SLPS_00106 Nobunaga no Yabou: Haouden (Japan) - http://redump.org/disc/8443/ has a proper bootfile 'SLPS_00106'.

    // SLPS_00107 Namco Museum Vol. 1 (Japan) - http://redump.org/disc/8443/ has a proper bootfile 'SLPS_00107'.

    (strcmp( (char *)volume_creation_timestamp, "1995090722000000") == 0) { // Darkseed (Japan) - http://redump.org/disc/1640/.
        return "001.08"; // Uses 1 MC block - https://psxdatacenter.com/games/J/D/SLPS-00108.html.
    } else if

    // SLPS_00109 AI Shougi (Japan) - http://redump.org/disc/62297/ has a proper bootfile 'SLPS_001.09'.

    // SLPS_00110 Miracle World: Fushigi no Kuni no IQ Meiro (Japan) - http://redump.org/disc/36181/ has a proper bootfile 'SLPS_001.10'.

    // SLPS_00111 Night Head: The Labyrinth (Japan) - http://redump.org/disc/39266/ has a proper bootfile 'SLPS_00111'.

    // SLPS_00112 Hissatsu Pachinko Station (Japan) -http://redump.org/disc/42584/ has a proper bootfile 'SLPS_00112'.

    (strcmp( (char *)volume_creation_timestamp, "1995090516062841") == 0) { // Sotsugyou II: Neo Generation (Japan) - http://redump.org/disc/7885/.
        return "001.13"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00040.html.
    } else if

    // SLPS_00114 Sangokushi IV (Japan) (Rev 0) - http://redump.org/disc/24772/ and Sangokushi IV (Japan) (Rev 1) - http://redump.org/disc/24772/have a proper bootfile 'SLPS_00114'.

    // SLPS_00115 Kuma no Pooh-tarou: Sora wa Pink da! Zen'in Shuugou!! (Japan) - http://redump.org/disc/62666/ has a proper bootfile 'SLPS_001.15'.

    // SLPS_00117 Emit Value Pack (Disc 1) (Vol. 1: Toki no Maigo) (Japan) - http://redump.org/disc/22411/ has a proper bootfile 'SLPS_001.17'.

    // SLPS_00118 Emit Value Pack (Disc 2) (Vol. 2: Inochigake no Tabi) (Japan) - http://redump.org/disc/22412/ has a proper bootfile 'SLPS_001.18'.

    // SLPS_00119 Emit Value Pack (Disc 3) (Vol. 3: Watashi ni Sayonara wo) (Japan) - http://redump.org/disc/22413/ has a proper bootfile 'SLPS_001.19'.

    // SLPS_00120 Creature Shock (Disc 1) (Japan) - http://redump.org/disc/38429/ has a proper bootfile 'slps_001.20'.

    // SLPS_00121 Creature Shock (Disc 2) (Japan) - http://redump.org/disc/38430/ has a proper bootfile 'slps_001.21'.

    // SLPS_00122 Off-World Interceptor Extreme (Japan) - http://redump.org/disc/15373/ has a proper bootfile 'SLPS_001.22'.

    // SLPS_00123 TIZ: Tokyo Insect Zoo (Japan) - http://redump.org/disc/7886/ has a proper bootfile 'SLPS_001.23'.

    // SLPS_00124 Sento Monogatari: Sono I (Japan) - http://redump.org/disc/39503/ has a proper bootfile 'SLPS_001.24'.

    // SLPS_00125 A Ressha de Ikou 4: Evolution Global (Japan) (Rev 0) - http://redump.org/disc/8493/ has a proper bootfile 'SLPS_001.25'. A Ressha de Ikou 4: Evolution Global (Japan) (Rev 1) - http://redump.org/disc/8444/ has a proper bootfile 'SLPS_910.19'.

    // SLPS_000126 is apparently FEDA - https://github.com/julianxhokaxhiu/iPoPS/blob/master/PSXListOFGames.txt but http://wiki.redump.org/index.php?title=Sony_PlayStation_-_Asia_Undumped_Discs argues it doesn't exist and or wasn't released.

    // SLPS_00127 Striker: World Cup Premiere Stage (Japan) - http://redump.org/disc/34589/ has a proper bootfile 'SLPS_001.27'.

    (strcmp( (char *)volume_creation_timestamp, "1995082016003000") == 0) { // Makeruna! Makendou 2 (Japan) - http://redump.org/disc/37537/
        return "001.28"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00128.html
    } else if

    // SLPS_0129 Break Thru! (Japan) - http://redump.org/disc/29931/ has a proper bootfile 'SLPS_001.29'.

    // SLPS_0130 Dokiou-ki (Japan) - http://redump.org/disc/3982/ has a proper bootfile 'SLPS_001.30'.

    // SLPS_0131 Two-Ten Kaku (Japan) - http://redump.org/disc/10238/ has a proper bootfile 'SLPS_001.31'.

    // SLPS_0132 Gionbana (Japan) - http://redump.org/disc/33539/ has a proper bootfile 'SLPS_001.32'.

    #if defined IS_FOR_GAME_ID
        // We need one GameID sent so that all discs can acccess the same memory card image. With lib-enigma that isn't useful and we instead want to identify each disc.

        ( 
        (strcmp( (char *)volume_creation_timestamp, "1995102101350000") == 0) || // D no Shokutaku: Complete Graphics (Japan) (Disc 1) - http://redump.org/disc/763/.
        (strcmp( (char *)volume_creation_timestamp, "1995102102521200") == 0) || // D no Shokutaku: Complete Graphics (Japan) (Disc 2) - http://redump.org/disc/764/.
        (strcmp( (char *)volume_creation_timestamp, "1995102105003200") == 0) // D no Shokutaku: Complete Graphics (Japan) (Disc 3) - http://redump.org/disc/765/.
        ) {
            return "001.33"; // Using disc 1 CD case serial: http://redump.org/disc/763/. Disc 2 serial is SLPS_00134. Disc 3 serial is SLPS_0135 All CDs assigned to same memory card. Use 1 MC blocks - https://psxdatacenter.com/games/J/D/SLPS-00133.html.
        } else if     

    #else

        (strcmp( (char *)volume_creation_timestamp, "1995102101350000") == 0) { // D no Shokutaku: Complete Graphics (Japan) (Disc 1) - http://redump.org/disc/763/.
            return "001.33"; // Uses 1 MC block.
        } else if

        (strcmp( (char *)volume_creation_timestamp, "1995102102521200") == 0) { // D no Shokutaku: Complete Graphics (Japan) (Disc 2) - http://redump.org/disc/764/.
            return "001.34"; // Uses 1 MC block.
        } else if

        (strcmp( (char *)volume_creation_timestamp, "1995102105003200") == 0) { // D no Shokutaku: Complete Graphics (Japan) (Disc 3) - http://redump.org/disc/765/ .
            return "001.35"; // Uses 1 MC block.
        } else if

    #endif

    // SLPS_00136 Othello World II: Yume to Michi e no Chousen (Japan) - http://redump.org/disc/41764/ has a proper bootfile 'SLPS_001.36'.

    (strcmp( (char *)volume_creation_timestamp, "1995100910002200") == 0) { // Keiba Saishou no Housoku '96 Vol. 1 (Japan) - http://redump.org/disc/22945/.
        return "001.37"; // Uses 1 MC blocks- https://psxdatacenter.com/games/J/S/SLPS-00137.html.
    } else if

    // SLPS_00138 Galaxy Fight: Universal Warriors (Japan) - http://redump.org/disc/21626/ has a proper bootfile 'SLPS_001.38'.

    // SLPS_00139 Shougi Joryuu Meijin'isen (Japan) - http://redump.org/disc/46378/ has a proper bootfile 'SLPS_001.39'.

    // SLPS_00140 The Snowman (Japan) - http://redump.org/disc/36568/has a proper bootfile 'SLPS_001.40'.

    // SLPS_00141 Alone in the Dark 2 (Japan) - http://redump.org/disc/13174/ has a proper bootfile 'SLPS_001.41'.

    (strcmp( (char *)volume_creation_timestamp, "1995101801325900") == 0) { //  Senryaku Shougi (Japan) - http://redump.org/disc/61170/.
        return "001.42"; // Uses 1 MC block - https://psxdatacenter.com/games/J/S/SLPS-00142.html.
    } else if

    // SLPS_00143 Reverthion (Japan) - http://redump.org/disc/7887/ has a proper bootfile 'SLPS_001.43'.

    // SLPS_00144 J. B. Harold: Blue Chicago Blues (Disc 1) (Japan) - http://redump.org/disc/18647/ has a proper bootfile 'SLPS_001.44'.

    // SLPS_00145 J. B. Harold: Blue Chicago Blues (Disc 2) (Japan) - http://redump.org/disc/18646/ has a proper bootfile 'SLPS_001.45'.

    (strcmp( (char *)volume_creation_timestamp, "1995113010450000") == 0) { // Keiba Saishou no Housoku '96 Vol. 1 (Japan) - http://redump.org/disc/22945/.
        return "001.46"; // Uses 15 MC blocks - https://psxdatacenter.com/games/J/K/SLPS-00146.html.
    } else if

    // SLPS_00147 Floating Runner: 7-tsu no Suishou no Monogatari (Japan) - http://redump.org/disc/8582/ has a proper bootfile 'SLPS_001.47'.

    // SLPS_00148 The Firemen 2: Pete & Danny (Japan) - http://redump.org/disc/18950/ has a proper bootfile 'SLPS_001.48'.

    // SLPS_00149 Puppet Zoo Pilomy (Japan) - http://redump.org/disc/37618/ has a proper bootfile 'SLPS_001.49'.

    // SLPS_00150 Ridge Racer Revolution (Japan) (Rev 0) - http://redump.org/disc/2733/ and Ridge Racer Revolution (Japan) (Rev 1) - http://redump.org/disc/6209 have a proper bootfile 'SLPS_001.50'.

    // SLPS_00151 Carnage Heart (Japan) - http://redump.org/disc/1599/ has a proper bootfile 'SLPS_001.51'.

    (strcmp( (char *)volume_creation_timestamp, "1995092205430500") == 0) { // Yaku: Yuujou Dangi (Japan) - http://redump.org/disc/4668/.
        return "001.52"; // Uses 1 MC block - https://psxdatacenter.com/games/J/Y/SLPS-00152.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995051201000000") == 0) { // Aquanaut no Kyuujitsu (Japan) - http://redump.org/disc/16984/.
        return "000.60"; // Uses 4 MC blocks - https://psxdatacenter.com/games/J/A/SLPS-00060.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995061911303400") == 0) { // J.League Jikkyou Winning Eleven (Japan) - http://redump.org/disc/6740/.
        return "000.68"; // Uses 1 MC block - https://psxdatacenter.com/games/J/J/SLPS-00068.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995121620000000") == 0) { // Alnam no Kiba: Juuzoku Juuni Shinto Densetsu (Japan) - http://redump.org/disc/11199/
        return "001.73"; // Uses 1 MC block - https://psxdatacenter.com/games/J/A/SLPS-00173.html.
    } else if


    (strcmp((char *)volume_creation_timestamp, "1995081001450000") == 0) { // Universal-ki Kanzen Kaiseki - Pachi-Slot Simulator (Japan)
        return "001.01"; // Uses 2 MC blocks - https://psxdatacenter.com/games/J/U/SLPS-00101.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995080316000000") == 0) { // V-Tennis (Japan) - http://redump.org/disc/22684/.
        return "001.03"; // Uses 1 MC block - https://psxdatacenter.com/games/J/V/SLPS-00103.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995081020000000") == 0) { // Gouketsuji Ichizoku 2 - Chotto dake Saikyou Densetsu (Japan) - http://redump.org/disc/12680/.
        return "001.04";
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995090722000000") == 0) { // Darkseed (Japan) - http://redump.org/disc/1640/.
        return "001.08";
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995092205430500") == 0) { // Yaku - Yuujou Dangi (Japan) - http://redump.org/disc/4668/.
        return "001.52"; // Uses 1 MC block - https://psxdatacenter.com/games/J/Y/SLPS-00152.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995121620000000") == 0) { // Alnam no Kiba - Juuzoku Juuni Shinto Densetsu (Japan) - http://redump.org/disc/11199/.
        return "001.73"; // Uses 1 MC block - https://psxdatacenter.com/games/J/A/SLPS-00173.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995122811000000") == 0) { // Welcome House (Japan) - http://redump.org/disc/23332/.
        return "001.90"; // Uses 1 MC block - https://psxdatacenter.com/games/J/W/SLPS-00190.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995111622323000") == 0) { // Magical Drop (Japan) - http://redump.org/disc/24773/.
        return "002.01"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SLPS-00201.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995121418400300") == 0) { // CG Mukashi Banashi - Jiisan 2-do Bikkuri!! (Japan) - http://redump.org/disc/18884/
        return "002.30"; // Uses 1 MC block - https://psxdatacenter.com/games/J/C/SLPS-00230.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1996010800000000") == 0) { // Sotsugyou R: Graduation Real (Japan) - http://redump.org/disc/7892/
        return "002.61"; // Uses 2 MC blocks - https://psxdatacenter.com/games/J/S/SLPS-00261.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1996022700000000") == 0) { // Tetris X (Japan) - http://redump.org/disc/35855/.
        return "003.21"; // Uses 1 MC block - https://psxdatacenter.com/games/J/T/SLPS-00321.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1996020413401600") == 0) { // Sid Meier's Civilization: Shin Sekai Shichidai Bunmei (Japan) - http://redump.org/disc/5607/.
        return "003.36"; // Uses 1 MC block - https://psxdatacenter.com/games/J/C/SLPS-00336.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1996030619500500") == 0) { // Nobunaga Shippuuki - Kirameki (Japan) - http://redump.org/disc/30963/.
        return "003.37"; // Uses 1 MC block - https://psxdatacenter.com/games/J/N/SLPS-00337.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1996072211000000") == 0) { // DigiCro - Digital Number Crossword (Japan) - http://redump.org/disc/6400/.
        return "005.49"; // Uses 1 MC block - https://psxdatacenter.com/games/J/D/SLPS-00549.html.
    } else if

    #if !defined IS_FOR_GAME_ID
    
        (strcmp((char *)volume_creation_timestamp, "1997011500000000") == 0) { // Great Battle VI, The (Japan) - http://redump.org/disc/37406/.
            return "007.19"; // Does not have save functionality - https://psxdatacenter.com/games/J/T/SLPS-00719.html, https://tokusatsu.fandom.com/wiki/The_Great_Battle_VI.
        } else if
    
    #endif

    (strcmp((char *)volume_creation_timestamp, "1997031012200700") == 0) { // FIFA Soccer 97 (Japan) - http://redump.org/disc/34407/.
        return "008.78"; // Uses 1 MC block - https://psxdatacenter.com/games/J/F/SLPS-00878.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1997050817540700") == 0) { // Over Drivin' II (Japan) - http://redump.org/disc/2088/.
        return "008.95"; // Uses 1 MC block - https://psxdatacenter.com/games/J/O/SLPS-00895.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1998061000000000") == 0) { // Himitsu Kessha Q (Japan) - http://redump.org/disc/60635/.
        return "013.34"; // Uses 1-3 MC blocks - https://psxdatacenter.com/games/J/H/SLPS-01334.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1998040820350000") == 0) { // Crown Knights, The - Jaja-uma! Quartet - Mega Dream Destruction (Japan) - http://redump.org/disc/34399/.
        return "015.58"; // Uses 1 MC block - https://psxdatacenter.com/games/J/J/SLPS-01558.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1999111108000000") == 0) { // Koudelka (Japan) (Disc 1) - http://redump.org/disc/8364/.
        return "024.60"; // Uses 1 MC block - https://psxdatacenter.com/games/J/K/SLPS-02460.html.
    } else if

    // Begin SCPS.

    (strcmp((char *)volume_creation_timestamp, "1994112112000000") == 0) { // Motor Toon Grand Prix (Japan) - http://redump.org/disc/3834/.
        is_scps = true;
        return "100.01"; // Uses 1 MC block - https://psxdatacenter.com/games/J/M/SCPS-10001.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995030717020700") == 0) { // Victory Zone (Japan) - http://redump.org/disc/37010/.
        is_scps = true;
        return "100.02"; // Uses 2 MC blocks - https://psxdatacenter.com/games/J/V/SCPS-10002.html.
        // TESTING NOTE: Latest DuckStation as of 9/11/2024 doesn't work with this game, but v0.1-6292 does just fine.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1994103110000000") == 0) { // Crime Crackers (Japan) - http://redump.org/disc/5729/.
        is_scps = true;
        return "100.03"; // Uses 1 MC block - https://psxdatacenter.com/games/J/C/SCPS-10003.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995032500000000") == 0) { // Gunners Heaven (Japan) - http://redump.org/disc/3880/.
        is_scps = true;
        return "100.06"; // Uses 1 MC blocks - https://psxdatacenter.com/games/J/G/SCPS-10006.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995032400000000") == 0) { // Jumping Flash! Aloha Danshaku Funky Daisakusen no Maki (Japan) - http://redump.org/disc/4051/.
        is_scps = true;
        return "100.07"; // Uses 1-3 MC blocks - https://psxdatacenter.com/games/J/J/SCPS-10007.html.
    } else if

    (strcmp( (char *)volume_creation_timestamp, "1995052420065100") == 0) { // Arc the Lad (Japan) (Rev 0) - http://redump.org/disc/67966/ / Arc the Lad (Japan) (Rev 1) - http://redump.org/disc/1472/
        is_scps = true;
        return "100.08"; // Serial from Rev 0 CD case. Rev 1 serial is SLPS_00095. Uses 1 MC block - https://psxdatacenter.com/games/J/A/SCPS-10008.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995061723590000") == 0) { // Philosoma (Japan) - http://redump.org/disc/3778/.
        is_scps = true;
        return "100.09"; // Uses 1 MC block - https://psxdatacenter.com/games/J/P/SCPS-10009.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995080914422700") == 0) { // Wizardry VII - Guardia no Houju (Japan) - http://redump.org/disc/1438/.
        is_scps = true;
        return "100.10"; // Uses 4 MC blocks - https://psxdatacenter.com/games/J/W/SCPS-10010.html.
    } else if
    
    (strcmp((char *)volume_creation_timestamp, "1995071219364500") == 0) { // Hermie Hopperhead - Scrap Panic (Japan) - http://redump.org/disc/30748/.
        is_scps = true;
        return "100.12"; // Uses 1 MC block - https://psxdatacenter.com/games/J/H/SCPS-10012.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995092719000000") == 0) { // Beyond the Beyond - Haruka naru Kanaan e (Japan) - http://redump.org/disc/602/.
        is_scps = true;
        return "100.14"; // Uses 1-3 MC blocks - https://psxdatacenter.com/games/J/B/SCPS-10014.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1995103122331500") == 0) { // Horned Owl (Japan) - http://redump.org/disc/4667/.
        is_scps = true;
        return "100.16"; // Uses 1 MC block - https://psxdatacenter.com/games/J/H/SCPS-10016.html.
    } else if

    (strcmp((char *)volume_creation_timestamp, "1997082616350500") == 0) { // XI [sai] (Japan) (En,Ja) - http://redump.org/disc/5412/.
        is_scps = true;
        return "100.51"; // Uses 1 MC block - https://psxdatacenter.com/games/J/X/SCPS-10051.html.
    
    } else {
        return "0"; // If not known say its "0".
    }
 }

int cdr_minimum_requirement(FILE *bin)
{
    // 10584000 bytes per minute * 71 minutes (max officially supported for PS1 and PS2 CD-ROMs) = 751464000 bytes max / SECTOR_RAW_LEN bytes per sector = 319500 sector max
    // 10584000 bytes per minute * 74 minutes  = 783216000 bytes max / SECTOR_RAW_LEN bytes per sector = 333000 sector max
    // 10584000 bytes per minute * 80 minutes (max density read-able to any extent) = 846720000 bytes max / SECTOR_RAW_LEN bytes per sector = 360000 sector max

    fseek(bin, 0, SEEK_END);
    int bin_size = ftell(bin);
    
    if( (bin_size % SECTOR_RAW_LEN) > 319500) 
    {
        return 0;
    } else if( (bin_size % SECTOR_RAW_LEN) > 333000) {
        return 1;
    } else if( (bin_size % SECTOR_RAW_LEN) > 360000) {
        return 2;
    }
    
    fseek(bin, 0, SEEK_SET); // Always seek to initial fpos as per policy of this library.
}

int is_ps_cd(FILE *bin)
{
    int bin_size;

    fseek(bin, 0, SEEK_END);

    bin_size = ftell(bin);

    if(bin_size % SECTOR_RAW_LEN != 0) // Minimum expected for correctness of detection functions below - 22-25
    {
	    printf("Info: bin file is not in MODE2/SECTOR_RAW_LEN format\n");
        
        if(bin_size % SECTOR_USER_DATA_LEN == 0)
        {
            printf("Error: this is an ISO image, NOT a BIN file in MODE2/2352 format\n");
        }

		return 0;
    } else if(bin_size < (SECTOR_RAW_LEN * 26) ) { // Minimum expected for correctness of detection functions below - 22-25 for directory record sector + 1.
	    printf("Error: bin file is too small to be valid\n");
		return 0;
    }

    fseek(bin, 0x9320, SEEK_SET);
    unsigned char psx_string[12];
    fread(psx_string, 1, 12, bin);

    if (memcmp(psx_string, "PLAYSTATION ", 12) == 0) // space intentional. Both PSX and PS2 CD-ROMs have this here.
    {
		return 1;
    }

    return 0;
}

void get_volume_creation_timestamp(FILE *bin, char *volume_creation_timestamp)
{
/*
 
 Volume Descriptors (Sector 16 and up)
 Playstation disks usually have only two Volume Descriptors,
 Sector 16    - Primary Volume Descriptor
 Sector 17    - Volume Descriptor Set Terminator
 
 Primary Volume Descriptor (sector 16 on PSX disks)
 000h 1    Volume Descriptor Type        (01h=Primary Volume Descriptor)
 001h 5    Standard Identifier           ("CD001")
 006h 1    Volume Descriptor Version     (01h=Standard)
 007h 1    Reserved                      (00h)
 008h 32   System Identifier             (a-characters) ("PLAYSTATION")
 028h 32   Volume Identifier             (d-characters) (max 8 chars for PSX?)
 048h 8    Reserved                      (00h)
 050h 8    Volume Space Size             (2x32bit, number of logical blocks)
 058h 32   Reserved                      (00h)
 078h 4    Volume Set Size               (2x16bit) (usually 0001h)
 07Ch 4    Volume Sequence Number        (2x16bit) (usually 0001h)
 080h 4    Logical Block Size in Bytes   (2x16bit) (usually 0800h) (1 sector)
 084h 8    Path Table Size in Bytes      (2x32bit) (max 800h for PSX)
 08Ch 4    Path Table 1 Block Number     (32bit little-endian)
 090h 4    Path Table 2 Block Number     (32bit little-endian) (or 0=None)
 094h 4    Path Table 3 Block Number     (32bit big-endian)
 098h 4    Path Table 4 Block Number     (32bit big-endian) (or 0=None)
 09Ch 34   Root Directory Record         (see next chapter)
 0BEh 128  Volume Set Identifier         (d-characters) (usually empty)
 13Eh 128  Publisher Identifier          (a-characters) (company name)
 1BEh 128  Data Preparer Identifier      (a-characters) (empty or other)
 23Eh 128  Application Identifier        (a-characters) ("PLAYSTATION")
 2BEh 37   Copyright Filename            ("FILENAME.EXT;VER") (empty or text)
 2E3h 37   Abstract Filename             ("FILENAME.EXT;VER") (empty)
 308h 37   Bibliographic Filename        ("FILENAME.EXT;VER") (empty)
 32Dh 17   Volume Creation Timestamp     ("YYYYMMDDHHMMSSFF",timezone)
 33Eh 17   Volume Modification Timestamp ("0000000000000000",00h)
 34Fh 17   Volume Expiration Timestamp   ("0000000000000000",00h)
 360h 17   Volume Effective Timestamp    ("0000000000000000",00h)
 371h 1    File Structure Version        (01h=Standard)
 372h 1    Reserved for future           (00h-filled)
 373h 141  Application Use Area          (00h-filled for PSX and VCD)
 400h 8    CD-XA Identifying Signature   ("CD-XA001" for PSX and VCD)
 408h 2    CD-XA Flags (unknown purpose) (00h-filled for PSX and VCD)
 40Ah 8    CD-XA Startup Directory       (00h-filled for PSX and VCD)
 412h 8    CD-XA Reserved                (00h-filled for PSX and VCD)
 41Ah 345  Application Use Area          (00h-filled for PSX and VCD)
 573h 653  Reserved for future           (00h-filled) 
*/
    fseek(bin, ( (SECTOR_RAW_LEN * 16) + SECTOR_SYNC_HEADER_LEN + 0x32D), SEEK_SET);// 0x930 * 16 = 0x9300 (System Volume Descriptor) + 0x18 to skip sync header = 0x9318.
    // 32Dh 17   Volume Creation Timestamp     ("YYYYMMDDHHMMSSFF",timezone)
    fread(volume_creation_timestamp, 16, 1, bin);
    // Null terminate it son.
    volume_creation_timestamp[16] = '\0';

    // Reset fpos.
    fseek(bin, 0, SEEK_SET);
}

int get_boot_file_name(FILE *bin, char *boot_file) 
{
/*
info from https://problemkaputt.de/psx-spx.htm#hardwarenumbers

Software (CDROM Game Codes)
  SCES-NNNNN Sony Computer Europe Software
  SCED-NNNNN Sony Computer Europe Demo
  SLES-NNNNN Sony Licensed Europe Software
  SLED-NNNNN Sony Licensed Europe Demo
  SCPS-NNNNN Sony Computer Japan Software
  SLPS-NNNNN Sony Licensed Japan Software
  SLPM-NNNNN Sony Licensed Japan ... maybe promo/demo?
  SCUS-NNNNN Sony Computer USA Software
  SLUS-NNNNN Sony Licensed USA Software
  PAPX-NNNNN Demo ...?
  PCPX-NNNNN Club ...?
  LSP-NNNNNN Lightspan series (non-retail educational games)
Note: Multi-disc games have more than one game code. The game code for Disc 1 is also printed on the CD cover, and used in memory card filenames. The per-disk game codes are printed on the discs, and are used as boot-executable name in SYSTEM.CNF file. There is no fixed rule for the multi-disc numbering; some games are using increasing numbers of XNNNN or NNNNX (with X increasing from 0 upwards), and some are randomly using values like NNNXX and NNNYY for different discs.
*/
    bool match = false;
    bool no_system_cnf = false;
    int sector_byte;

    unsigned char possible_directory_record_sectors_buf[(SECTOR_USER_DATA_LEN * 3)];

    fseek(bin, ( (SECTOR_RAW_LEN * 22) + SECTOR_SYNC_HEADER_LEN), SEEK_SET);// 0x930 * 22 = 0xCA20 (Directory Record Sector) + 0x18 to skip sync header = 0xCA38. TODO: this is overkill, only read if the next sector really is a continuation of the root directory record.
            
    for(int directory_record_sector = 0; directory_record_sector < 3; directory_record_sector++)
    {
        //printf("\n\nDirectory Record Sector %d\n\n", directory_record_sector);        
        for(int i=0; i < SECTOR_USER_DATA_LEN; i++)
        {
            possible_directory_record_sectors_buf[i + (directory_record_sector * SECTOR_USER_DATA_LEN)] = fgetc(bin);
            //printf("%02X ", possible_directory_record_sectors_buf[i + (directory_record_sector * 0x800)]);
            //printf("Directory Sector Multi: %d\n", (directory_record_sector * 0x800)) ;
        }
        
        fseek(bin, (SECTOR_EDC_LEN + SECTOR_ECC_LEN + SECTOR_SYNC_HEADER_LEN), SEEK_CUR); // skip EDC/EEC/Header
    }
    
    //Go to root directory record sector (22). Sector 22 = 0x930 * 22 = 0xCA20 + 0x18 (sync header) = 0xCA38 (start of user data 
    // Example: This is Football (Italy)
    // BEFORE SYSTEM.CNF ASCII text (name of dir/file in listing)
    // 469E4500 00000000 00456309 0C140A02 24000000 01000001 0C (25 bytes)
    // LBA of SYSTEM.CNF SECTOR: 0x469E, to get actual position in file 0x469E * 0x930 = 0x288CBA0.
    // BEFORE FOOTBALL (directory INSIDE root that contains more files)
    // 469F0008 00000000 08006309 1C021E00 24020000 01000001 08 (25 bytes)
    // LBA of FOOTBALL: 0x469F * 0x930 = 0x288D4D0

    unsigned int system_cnf_lba;
    
    // subtract 13 since we are checking SYSTEM.CNF;1<null>.
    for(sector_byte = 0; sector_byte < ( (SECTOR_USER_DATA_LEN * 3) - 13); sector_byte++)
    {
        if(memcmp(possible_directory_record_sectors_buf + sector_byte, "SYSTEM.CNF;1", 12) == 0)
        {
            match = true;
            // Extract the LBA of SYSTEM.CNF (4 bytes len) which is -27 bytes BEFORE the filename. 
            
            memcpy(&system_cnf_lba, possible_directory_record_sectors_buf + (sector_byte - 27), sizeof(system_cnf_lba));
            // Byte swap, Big Endian value.
            system_cnf_lba = ((system_cnf_lba >> 24) & 0x000000FF) | // Move 1st to 4th.
            ((system_cnf_lba >> 8)  & 0x0000FF00) | // Move 2nd to 3rd.
            ((system_cnf_lba << 8)  & 0x00FF0000) | // Move 3rd to 2nd.
            ((system_cnf_lba << 24) & 0xFF000000);  // Move 4th to 1st.
            
            //printf("SYSTEM.CNF LBA: 0x%x\n", system_cnf_lba);
            system_cnf_lba = (system_cnf_lba * SECTOR_RAW_LEN);
            //printf("SYSTEM.CNF Sector file offset: 0x%x\n", system_cnf_lba);
            break;
        } else if(memcmp(possible_directory_record_sectors_buf + sector_byte, "PSX.EXE;1", 9) == 0) {
            no_system_cnf = true;
            break;
        }

    }
    
    unsigned char system_cnf_sector_buf[SECTOR_USER_DATA_LEN];

    if(!no_system_cnf)
    {
        // Seek to SYSTEM.CNF in bin file.        
        fseek(bin, (system_cnf_lba + SECTOR_SYNC_HEADER_LEN), SEEK_SET);

        // Read SYSTEM.CNF (only one sector in length) into buffer.
        for(int i=0; i < SECTOR_USER_DATA_LEN; i++)
        {
            system_cnf_sector_buf[i] = fgetc(bin);
        }
        
        match = false;
        
        for (sector_byte = 0; sector_byte < (SECTOR_USER_DATA_LEN - 5); sector_byte++)
        {
            // Found cdrom: in SYSTEM.CNF, so we are on the right line.
            if (memcmp(system_cnf_sector_buf + sector_byte, "cdrom:", 5) == 0)
            {                                
                // Get boot file end offset. Was using actual end of line marker (0x0D) but realized I can just use the ;, because in SYSTEM.CNF after the bootfile name it is followed by ;1 to specify v1 (not important what that means in the context of this, but it is consistant).
                int boot_file_end_offset = 0;
                
                for(int i = 0; i < (32 + 7); i++) // allow for 32 byte filepath after, note that it is 7 because cdrom: is 5 and it could have up to 2 \\ after the :.
                {
                    // Reached carriage return (EOL)
                    if( *(system_cnf_sector_buf + sector_byte + i) == 0x3B) // Match on ;.
                    {
                        boot_file_end_offset = (sector_byte + i); // Don't want to actually capture ; at the end.
                        //printf("Boot file end offset: 0x%x\n", boot_file_end_offset); 
                        break; // We got the end of boot file.
                    }
                }
                
                // Figure out boot file len.
                int boot_file_len = 0;
                int boot_file_start_offset = 0;
                
                for(int i = 0; i < (32 + 7); i++) // allow for 32 byte filepath after, note that it is 7 because cdrom: is 5 and it could have up to 2 \\ after the :.
                {
                    // Continuely subtract until we hit either a \ (0x5C in ASCII) (example cdrom:\\XXXX_XXX.XX;1 or cdrom:\XXXX_XXX.XX;1 both are covered) or a : (0x3A in ASCII) (cdrom:XXXX_XXX.XX;1).
                    if( ( *(system_cnf_sector_buf + (boot_file_end_offset - i) ) == 0x5C) || ( *(system_cnf_sector_buf + (boot_file_end_offset - i) ) == 0x3A) )
                    {
                        boot_file_start_offset = (boot_file_end_offset - i + 1);
                        //printf("Boot file start offset: 0x%x\n", boot_file_start_offset);
                        boot_file_len = (boot_file_end_offset - boot_file_start_offset);
                        //printf("Boot file len: %d\n", boot_file_len);
                        break; // We got the starting offset of the boot file.
                    }
                }
                
                // Get boot file.
                for(int i = 0; i < boot_file_len; i++)
                {
                    boot_file[i] = *(system_cnf_sector_buf + (boot_file_start_offset + i) );
                }
                // Set null termination (variable sized string possible).
                boot_file[boot_file_len] = '\0';
                
                // WAIT! This could be a PSX.EXE boot file, yes istg there are official games Sony signed off on that use a SYSTEM.CNF file to point to a PSX.EXE (maybe for custom event/tcb/other things, but why would you name your boot file the old way in the new early 1995+ "REQUIRED" format, and then WHY would the company enforcing said policy sign off on it and print millions of said disc??).
                if((strncmp(boot_file, "PSX.EXE", 7) == 0))
                {
                    get_volume_creation_timestamp(bin, volume_creation_timestamp);

                }
                
                return 1; // We got the boot file.
            }
        }
    } else {
        get_volume_creation_timestamp(bin, volume_creation_timestamp);
        //printf("Volume Creation TimeStamp (Unique Identifier):\n%s\n", volume_creation_timestamp);

        // Attempt to figure out what PSX.EXE game this is based off of volume_creation_timestamp.
        const char * serial = get_psx_exe_gameid(bin, volume_creation_timestamp);
        //printf("Serial: %s\n", serial);
        
        if(strcmp(serial, "0") == 0) 
        { // The library sends back a literal string containing '0' for no match.
            //printf("Unknown PSX.EXE ID, unique GameID unavailable.\n"); // As a last resort, we send PSX.EXE for gameid.
            //printf("Volume Creation TimeStamp (Unique Identifier):\n%s\n", volume_creation_timestamp);
            const char *psx_exe_filename = "PSX.EXE";
            strcpy((char *)boot_file, psx_exe_filename);
            return 2;
        }

        // Build full bootfile.
        if(is_scps) { // Since there are so few SCPS PSX.EXE games in comparison to the massive amount of SLPS, we default to SLPS unless we are told not to.
            sprintf(boot_file, "SCPS_%s", serial);
        } else {
            sprintf(boot_file, "SLPS_%s", serial);
        }
        
        return 1;
    }

    // Reset fpos.
    fseek(bin, 0, SEEK_SET);
}

int id_rev(FILE *bin, const unsigned int difference_offset, const unsigned char old_byte, const unsigned char new_byte)
{
    unsigned char ver_check_val;
	// <Address with first difference> <original byte> <different byte from original at same address>
	fseek(bin, difference_offset, SEEK_SET);
	ver_check_val = fgetc(bin);
	fseek(bin, 0, SEEK_SET);

	if(ver_check_val == old_byte)
	{
	    return 0; // version containing old byte
	} else if(ver_check_val == new_byte) {
        return 1; // version containing new byte
    } else {
    	printf("Unknown version\n");
        return 2;
	}    
}

/*
 *     ApplyPPF3.c (Linux Version)
 *     written by Icarus/Paradox
 *
 *     Big Endian support by Hu Kares.
 *
 *     Applies PPF1.0, PPF2.0 & PPF3.0 Patches (including PPF3.0 Undo support)
 *     Feel free to use this source in and for your own
 *     programms.
 *
 *     To compile enter:
 *     gcc -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE applyppf3_linux.c
 * 
 */

// NOTE: I have commented out but KEPT all the old code that has been changed and or is no longer necessary, for reference - Alex Free. This is a modification of the original paradox code to do something else. Instead of files and being a patcher, it's unsigned char arrays in the executable itself self-contained.

/*
#if defined(__APPLE__) || defined (MACOSX)

//////////////////////////////////////////////////////////////////////
// fseeko is already 64 bit for Darwin/MacOS X!
// fseeko64 undefined for Darwin/MacOS X!

#define	fseeko64		fseeko

//////////////////////////////////////////////////////////////////////
// ftellko is already 64 bit for Darwin/MacOS X!
// ftello64 undefined for Darwin/MacOS X!

#define	ftello64		ftello

//////////////////////////////////////////////////////////////////////
// "off_t" is already 64 bit for Darwin/MacOS X!
// "__off64_t" undefined for Darwin/MacOS X!

typedef	off_t			__off64_t;

#endif */ /* __APPLE__ || MACOSX */

//////////////////////////////////////////////////////////////////////
// Macros for little to big Endian conversion.

#ifdef __BIG_ENDIAN__

#define Endian16_Swap(value)	(value = (((((unsigned short) value) << 8) & 0xFF00)  | \
                                          ((((unsigned short) value) >> 8) & 0x00FF)))

#define Endian32_Swap(value)    (value = (((((unsigned long) value) << 24) & 0xFF000000)  | \
                                          ((((unsigned long) value) <<  8) & 0x00FF0000)  | \
                                          ((((unsigned long) value) >>  8) & 0x0000FF00)  | \
                                          ((((unsigned long) value) >> 24) & 0x000000FF)))

#define Endian64_Swap(value)	(value = (((((unsigned long long) value) << 56) & 0xFF00000000000000ULL)  | \
                                          ((((unsigned long long) value) << 40) & 0x00FF000000000000ULL)  | \
                                          ((((unsigned long long) value) << 24) & 0x0000FF0000000000ULL)  | \
                                          ((((unsigned long long) value) <<  8) & 0x000000FF00000000ULL)  | \
                                          ((((unsigned long long) value) >>  8) & 0x00000000FF000000ULL)  | \
                                          ((((unsigned long long) value) >> 24) & 0x0000000000FF0000ULL)  | \
                                          ((((unsigned long long) value) >> 40) & 0x000000000000FF00ULL)  | \
                                          ((((unsigned long long) value) >> 56) & 0x00000000000000FFULL)))

#else

#define	Endian16_Swap(value)
#define	Endian32_Swap(value)
#define	Endian64_Swap(value)

#endif /* __BIG_ENDIAN__ */

//////////////////////////////////////////////////////////////////////
// Used global variables.
//FILE *ppf, *bin;
char binblock[1024], ppfblock[1024];
unsigned char ppfmem[512];
#define APPLY 1
#define UNDO 2

//////////////////////////////////////////////////////////////////////
// Used prototypes.
//int	PPFVersion(FILE *ppf);
//int PPFVersion(const unsigned char ppf[])
//int	OpenFiles(char* file1, char* file2);
//int	ShowFileId(FILE *ppf, int ppfver);
int	ShowFileId(const unsigned char ppf[], unsigned int ppf_len, int ppfver);
//void	ApplyPPF1Patch(FILE *ppf, FILE *bin);
//void	ApplyPPF2Patch(FILE *ppf, FILE *bin);
//void	ApplyPPF3Patch(FILE *ppf, FILE *bin, char mode);
//void	ApplyPPF1Patch(const unsigned char ppf[], FILE *bin);
//void	ApplyPPF2Patch(const unsigned char ppf[], FILE *bin);
//void	ApplyPPF3Patch(const unsigned char ppf[], FILE *bin, char mode);

/*
int main(int argc, char **argv){
	int x;
	printf("ApplyPPF v3.0 by =Icarus/Paradox= %s\n", __DATE__);
#ifdef __BIG_ENDIAN__
        printf("Big Endian support by =Hu Kares=\n\n");			// <Hu Kares> sum credz
#endif */ /* __BIG_ENDIAN__ */     
/*   
	if(argc!=4){
		printf("Usage: ApplyPPF <command> <binfile> <patchfile>\n");
		printf("<Commands>\n");
		printf("  a : apply PPF1/2/3 patch\n");
		printf("  u : undo patch (PPF3 only)\n");

		printf("\nExample: ApplyPPF.exe a game.bin patch.ppf\n");
		return(0);
	}

	switch(*argv[1]){
			case 'a'	:	if(OpenFiles(argv[2], argv[3])) return(0);
							x=PPFVersion(ppf);
							if(x){
								if(x==1){ ApplyPPF1Patch(ppf, bin); break; }
								if(x==2){ ApplyPPF2Patch(ppf, bin); break; }
								if(x==3){ ApplyPPF3Patch(ppf, bin, APPLY); break; }
							} else{ break; }
							break;
			case 'u'	:	if(OpenFiles(argv[2], argv[3])) return(0);
							x=PPFVersion(ppf);
							if(x){
								if(x!=3){
									printf("Undo function is supported by PPF3.0 only\n");
								} else {
									ApplyPPF3Patch(ppf, bin, UNDO);
								}
							} else{ break; }
							break;
			default		:
							printf("Error: unknown command: \"%s\"\n",argv[1]);
							return(0);
							break;
	}

	fclose(bin);
	fclose(ppf);
	return(0);
}
*/
//////////////////////////////////////////////////////////////////////
// Applies a PPF1.0 patch.
//void ApplyPPF1Patch(FILE *ppf, FILE *bin){
void ApplyPPF1Patch(const unsigned char ppf[], unsigned int ppf_len, FILE *bin) {
	//char desc[50];
	char desc[51]; // old bug fixed
	unsigned int pos;
	unsigned int count, seekpos;
	unsigned char anz;


	//fseeko64(ppf, 6,SEEK_SET);  /* Read Desc.line */
	
	//printf("PPF Byte 1: %02X\n", ppf[0]);
	//printf("PPF Byte 1: %02X\n", ppf[1]);
	//printf("PPF Byte 1: %02X\n", ppf[2]);

	for(int i = 0; i < 50; i++)
	{
		desc[i] = ppf[i + 6];
#if defined DEBUG
		printf("Desc Byte %02X\n", desc[i]);
#endif
	}
	desc[50]=0; // terminate


	//fread(&desc, 1, 50, ppf); desc[50]=0;
	//printf("Patchfile is a PPF1.0 patch. Patch Information:\n");
	printf("PPF1.0 patch information:\n");
	printf("Description : %s\n", desc);
	printf("File_id.diz : no\n");

	printf("Patching... "); fflush(stdout);
	//fseeko64(ppf, 0, SEEK_END);
	
	//count=ftell(ppf);
	count = ppf_len;
	//printf("PPF count: %X", count);
	
	count-=56;
	seekpos=56;

	do{
		printf("reading...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);
		//fseeko64(ppf, seekpos, SEEK_SET);

		pos = ppf[seekpos] + (ppf[seekpos + 1] << 8) + (ppf[seekpos + 2] << 16) + (ppf[seekpos + 3] << 24);
		//printf("PPF POS Byte 0: %02X\n", ppf[seekpos]);
		//printf("PPF POS Byte 1: %02X\n", ppf[seekpos + 1]);
		//printf("PPF POS Byte 2: %02X\n", ppf[seekpos + 2]);
		//printf("PPF POS Byte 3: %02X\n", ppf[seekpos + 3]);
#if defined DEBUG
		printf("POS: %08X\n", pos);
#endif
		//fread(&pos, 1, 4, ppf);
        Endian32_Swap (pos);			// <Hu Kares> little to big endian
		
		anz = ppf[seekpos + 4];
		//fread(&anz, 1, 1, ppf);
#if defined DEBUG
		printf("ANZ: %02X\n", anz);
#endif
		for(int i = 0; i < anz; i++)
		{
			ppfmem[i] = ppf[i + seekpos + 4 + 1];
#if defined DEBUG
			printf("PPFMEM: %02X\n", ppfmem[i]);
#endif
		}
		//fread(&ppfmem, 1, anz, ppf);

		//fseeko64(bin, pos, SEEK_SET);
		fseeko(bin, pos, SEEK_SET); // -D_FILE_OFFSET_BITS=64 allows us to use fseeko
		//printf("writing...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);
		fwrite(&ppfmem, 1, anz, bin);
		seekpos=seekpos+5+anz;
		count=count-5-anz;
#if defined DEBUG
		printf("Count %08X\n", count);
#endif

	} while(count!=0);

	printf("successful.\n");
}

//////////////////////////////////////////////////////////////////////
// Applies a PPF2.0 patch.
void ApplyPPF2Patch(const unsigned char ppf[], unsigned int ppf_len, FILE *bin){
		//char desc[50], in;
		char desc[51], in; // old bug fixed
		unsigned int binlen, obinlen, count, seekpos;
		int idlen, pos;
		unsigned char anz;

		//fseeko64(ppf, 6,SEEK_SET);
		//fread(&desc, 1, 50, ppf); desc[50]=0;
		for(int i = 0; i < 50; i++)
		{
			desc[i] = ppf[i + 6];
#if defined DEBUG
			printf("Desc Byte %02X\n", desc[i]);
#endif
		}
		desc[50]=0; // terminate

		//printf("Patchfile is a PPF2.0 patch. Patch Information:\n");
		printf("PPF2.0 patch information:\n");
		printf("Description : %s\n",desc);
		printf("File_id.diz : ");
		idlen=ShowFileId(ppf, ppf_len, 2);
		if(!idlen) printf("not available\n");
			//fseeko64(ppf, 56, SEEK_SET);
			//fread(&obinlen, 1, 4, ppf);
 			obinlen = ppf[56] + (ppf[56 + 1] << 8) + (ppf[56 + 2] << 16) + (ppf[56 + 3] << 24); // NOT BIG-ENDIAN SAFE    
			Endian32_Swap (obinlen);		// <Hu Kares> little to big endian
        	// fseeko64(bin, 0, SEEK_END);
			fseeko(bin, 0, SEEK_END); // -D_FILE_OFFSET_BITS=64 allows us to use fseeko
        	binlen=ftell(bin);
        	if(obinlen!=binlen){
			printf("The size of the bin file isn't correct, continue ? (y/n): "); fflush(stdout);
			in=getc(stdin);
		
			if(in!='y'&&in!='Y'){
				printf("Aborted...\n");
				return;
			}
		}

		fflush(stdin);
		//fseeko64(ppf, 60, SEEK_SET);
		//fread(&ppfblock, 1, 1024, ppf);
		for(int i = 0; i < 1024; i++)
		{
			ppfblock[i] = ppf[60 + i];
		}
		
		//fseeko64(bin, 0x9320, SEEK_SET); 
		fseeko(bin, 0x9320, SEEK_SET); // -D_FILE_OFFSET_BITS=64 allows us to use fseeko

		//fread(&binblock, 1, 1024, bin);
		if(fread(&binblock, 1, 1024, bin) != 1024)
		{
			printf("Error: Can not read bin block\n");
			return;
		}
		
		in=memcmp(ppfblock, binblock, 1024);
		if(in!=0){
			printf("Binblock/Patchvalidation failed. continue ? (y/n): "); fflush(stdout);

#if defined(__APPLE__) || defined (MACOSX)

                        if(obinlen!=binlen) {		// <Hu Kares> required, since fflush doesn't flush '\n'!
                            in=getc(stdin);
                        }

#endif /* __APPLE__ || MACOSX */
			in=getc(stdin);
			if(in!='y'&&in!='Y'){
				printf("Aborted...\n");
				return;
			}
		}

		printf("Patching... "); fflush(stdout);
		//fseeko64(ppf, 0, SEEK_END);
		//count=ftell(ppf);
		count = ppf_len;
		seekpos=1084;
		count-=1084;
		if(idlen) count-=idlen+38;

        do{
			printf("reading...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);
			//fseeko64(ppf, seekpos, SEEK_SET);
			
			//fread(&pos, 1, 4, ppf);
			//pos = ppf[seekpos] + (ppf[seekpos + 1] << 8) + (ppf[seekpos + 2] << 16) + (ppf[seekpos + 3] << 24); // NOT BIG-ENDIAN SAFE    

			memcpy(&pos, &ppf[seekpos], 4);
            Endian32_Swap (pos);		// <Hu Kares> little to big endian
#if defined DEBUG
			printf("POS: %08X\n", pos);
#endif
			//fread(&anz, 1, 1, ppf);
			anz = ppf[seekpos + 4];
#if defined DEBUG
			printf("ANZ: %02X\n", anz);
#endif
			//fread(&ppfmem, 1, anz, ppf);
			for(int i = 0; i < anz; i++)
			{
				ppfmem[i] = ppf[i + seekpos + 4 + 1];
#if defined DEBUG				
				printf("PPFMEM: %02X\n", ppfmem[i]);
#endif			
			}
			// fseeko64(bin, pos, SEEK_SET);
			fseeko(bin, pos, SEEK_SET); // -D_FILE_OFFSET_BITS=64 allows us to use fseeko

			printf("writing...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);
			fwrite(&ppfmem, 1, anz, bin);
			seekpos=seekpos+5+anz;
			count=count-5-anz;
#if defined DEBUG
			printf("Count %08X\n", count);
#endif
        } while(count!=0);

		printf("successful.\n");
}
//////////////////////////////////////////////////////////////////////
// Applies a PPF3.0 patch.
//void ApplyPPF3Patch(FILE *ppf, FILE *bin, char mode){
void ApplyPPF3Patch(const unsigned char ppf[], unsigned int ppf_len, FILE *bin, char mode){
	//char desc[50], imagetype=0, in;
    char desc[51], imagetype=0, in; // old bug fixed
	unsigned char	undo=0, blockcheck=0;
	int idlen;
	//__off64_t offset, count;			// <Hu Kares> count has to be 64 bit!
	off_t offset, count;
	unsigned int seekpos;
	unsigned char anz=0;

	//fseeko64(ppf, 6,SEEK_SET);  /* Read Desc.line */
	//fread(&desc, 1, 50, ppf); desc[50]=0;
	for(int i = 0; i < 50; i++)
	{
		desc[i] = ppf[i + 6];
#if defined DEBUG		
		printf("Desc Byte %02X\n", desc[i]);
#endif
	}
	desc[50]=0; // terminate

	//printf("Patchfile is a PPF3.0 patch. Patch Information:\n");
	printf("PPF3.0 patch information:\n");
	printf("Description : %s\n",desc);
	printf("File_id.diz : ");

	idlen=ShowFileId(ppf, ppf_len, 3);
	if(!idlen) printf("not available\n");

	//fseeko64(ppf, 56, SEEK_SET);
	//fread(&imagetype, 1, 1, ppf);
	imagetype = ppf[56];

	//fseeko64(ppf, 57, SEEK_SET);
	//fread(&blockcheck, 1, 1, ppf);
	blockcheck = ppf[57];
#if defined DEBUG	
	printf("Block Check: %02X\n", blockcheck);
#endif
	//fseeko64(ppf, 58, SEEK_SET);
	//fread(&undo, 1, 1, ppf);
	undo = ppf[58];
#if defined DEBUG	
	printf("Undo Support: %02x\n", undo);
#endif
	if(mode==UNDO){
		if(!undo){
			printf("Error: no undo data available\n");
			return;
		}
	}

	if(blockcheck){
		fflush(stdin);
		//fseeko64(ppf, 60, SEEK_SET);
		//fread(&ppfblock, 1, 1024, ppf);
		for(int i = 0; i < 1024; i++)
		{
			ppfblock[i] = ppf[60 + i];
		}
		
		if(imagetype){
			//fseeko64(bin, 0x80A0, SEEK_SET);
			fseeko(bin, 0x80A0, SEEK_SET);  // -D_FILE_OFFSET_BITS=64 allows us to use fseeko
		} else {
			//fseeko64(bin, 0x9320, SEEK_SET);
			fseeko(bin, 0x9320, SEEK_SET); //  -D_FILE_OFFSET_BITS=64 allows us to use fseeko
		}
		//fread(&binblock, 1, 1024, bin);
		
		if(fread(&binblock, 1, 1024, bin) != 1024)
		{
			printf("Error: Can not read bin block\n");
			return;
		}
		in=memcmp(ppfblock, binblock, 1024);
		if(in!=0){
			printf("Binblock/Patchvalidation failed. continue ? (y/n): "); fflush(stdout);
			in=getc(stdin);
			if(in!='y'&&in!='Y'){
				printf("Aborted...\n");
				return;
			}
		}
	}

	//fseeko64(ppf, 0, SEEK_END);
	//count=ftello64(ppf);				// <Hu Kares> 64 bit!
	count = ppf_len;
	//fseeko64(ppf, 0, SEEK_SET);
	
	if(blockcheck){
		seekpos=1084;
		count-=1084;
	} else {
		seekpos=60;
		count-=60;
	}

	if(idlen) count-=(idlen+18+16+2);
	

	printf("Patching ... ");
	//fseeko64(ppf, seekpos, SEEK_SET);
	do{
		printf("reading...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);
		//fread(&offset, 1, 8, ppf);
		memcpy(&offset, &ppf[seekpos], 8);
        Endian64_Swap(offset);			// <Hu Kares> little to big endian
#if defined DEBUG		
		printf("Offset: %jX\n", offset);
#endif
		//fread(&anz, 1, 1, ppf);
		anz = ppf[seekpos + 8];
#if defined DEBUG
		printf("ANZ: %02X\n", anz);
#endif

		if(mode==APPLY){
		//	fread(&ppfmem, 1, anz, ppf);

			for(int i = 0; i < anz; i++)
			{
				ppfmem[i] = ppf[i + seekpos + 8 + 1];
#if defined DEBUG
				printf("PPFMEM: %02X\n", ppfmem[i]);
#endif			
			}
			//if(undo) fseeko64(ppf, anz, SEEK_CUR);
		} else {
            if(mode==UNDO){
                //fseeko64(ppf, anz, SEEK_CUR);
                //fread(&ppfmem, 1, anz, ppf);
				for(int i = 0; i < anz; i++)
				{
					ppfmem[i] = ppf[i + seekpos + 8 + 1 + anz];
#if defined DEBUG					
					printf("PPFMEM: %02X\n", ppfmem[i]);
#endif				
				}
            }
        }
    
		printf("writing...\b\b\b\b\b\b\b\b\b\b"); fflush(stdout);		
		//fseeko64(bin, offset, SEEK_SET);
		fseeko(bin, offset, SEEK_SET);

		fwrite(&ppfmem, 1, anz, bin);
		count-=(anz+9);

		if(undo)
		{
			seekpos=seekpos+5+4+anz+anz;
		} else {
			seekpos=seekpos+5+4+anz;
		}

		if(undo) count-=anz;

#if defined DEBUG
		printf("Count %jX\n", count);
#endif
	} while(count!=0);

		printf("successful.\n");
}

//////////////////////////////////////////////////////////////////////
// Shows File_Id.diz of a PPF2.0 / PPF3.0 patch.
// Input: 2 = PPF2.0
// Input: 3 = PPF3.0
// Return 0 = Error/no fileid.
// Return>0 = Length of fileid.
//int ShowFileId(FILE *ppf, int ppfver);
int ShowFileId(const unsigned char ppf[], unsigned int ppf_len, int ppfver){
	char buffer2[3073];
	unsigned int idmagic;
	int lenidx=0, idlen=0, orglen=0;

	if(ppfver==2){
		lenidx=4;
	} else {
		lenidx=2;
	}

	//fseeko64(ppf,-(lenidx+4),SEEK_END);
	//fread(&idmagic, 1, 4, ppf);
	memcpy(&idmagic, &ppf[(ppf_len-(lenidx+4))], 4);
        Endian32_Swap (idmagic);			// <Hu Kares> little to big endian

	//printf("IDMagic: %08X\n", idmagic);

	//if(idmagic!='ZID.'){
	if(idmagic != 0x5A49442E)
	{
		return(0);
	} else {
		//fseeko64(ppf,-lenidx,SEEK_END);
		//fread(&idlen, 1, lenidx, ppf);
		memcpy(&idlen, &ppf[(ppf_len -lenidx)], lenidx);
        Endian32_Swap (idlen);			// <Hu Kares> little to big endian
		//printf("IDLen: %02X\n", idlen);
        orglen = idlen;
        if (idlen > 3072) {			// <Hu Kares> to be secure: avoid segmentation fault!
            idlen = 3072;
        }
		//fseeko64(ppf,-(lenidx+16+idlen),SEEK_END);
		//fread(&buffer2, 1, idlen, ppf);
		memcpy(&buffer2, &ppf[(ppf_len-(lenidx+16+idlen))], idlen);
		buffer2[idlen]=0;
		printf("available\n%s\n",buffer2);
	}

	return(orglen);
}

//////////////////////////////////////////////////////////////////////
// Check what PPF version we have.
// Return: 0 - File is no PPF.
// Return: 1 - File is a PPF1.0
// Return: 2 - File is a PPF2.0
// Return: 3 - File is a PPF3.0
//int PPFVersion(FILE *ppf){
int PPFVersion(const unsigned char ppf[])
{
	unsigned int magic;
	//fseeko64(ppf,0,SEEK_SET);
	//fread(&magic, 1, 4, ppf);
	
	magic = ppf[0] + (ppf[1] << 8) + (ppf[2] << 16) + (ppf[3] << 24); 

        Endian32_Swap (magic);				// <Hu Kares> little to big endian
#if defined DEBUG
		printf("PPF Version Magic: %08X\n", magic);
#endif

	switch(magic){
			//case '1FPP'		:	return(1);
			case 0x31465050		:	return(1);
			// case '2FPP'		:	return(2);
			case 0x32465050		:	return(2);
			// case '3FPP'		:	return(3);
			case 0x33465050		:	return(3);
			default			:   printf("Error: patchfile is no ppf patch\n"); break;
	}

	return(0);
}

void apply_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin)
{
	int x;
	x=PPFVersion(ppf);
	if(x==1)
	{ 
		ApplyPPF1Patch(ppf, ppf_len, bin);
	} else if(x==2) { 
		ApplyPPF2Patch(ppf, ppf_len, bin);
	} else if(x==3) { 
		printf("%c", APPLY);
		ApplyPPF3Patch(ppf, ppf_len, bin, APPLY);
	} else{ 
		printf("Error: Unknown PPF Patch version %d\n", x);
	}
}

void undo_ppf(const unsigned char ppf[], unsigned int ppf_len, FILE *bin)
{
	int x;
	x=PPFVersion(ppf);
	if(x==3) 
	{ 
		ApplyPPF3Patch(ppf, ppf_len, bin, UNDO);
	} else { 
		printf("Error: PPF Patch must be version 3.0 to use undo feature\n");
	}
}

//////////////////////////////////////////////////////////////////////
// Open all needed files.
// Return: 0 - Successful
// Return: 1 - Failed.
/*
int OpenFiles(char* file1, char* file2){

	bin=fopen(file1, "rb+");
	if(!bin){
		printf("Error: cannot open file '%s' ",file1);
		return(1);
	}

	ppf=fopen(file2,  "rb");
	if(!ppf){
		printf("Error: cannot open file '%s' ",file2);
		fclose(bin);
		return(1);
	}

	return(0);
}
*/
