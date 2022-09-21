/*
 * Copyright 2022 Praetorian Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <ntddk.h>

#define NT_DEVICE_NAME                  L"\\Device\\Ramdisk"
#define DOS_DEVICE_NAME                 L"\\DosDevices\\"

#define RAMDISK_TAG                     'DmaR'  // "RamD"
#define DOS_DEVNAME_LENGTH              (sizeof(DOS_DEVICE_NAME)+sizeof(WCHAR)*10)
#define DRIVE_LETTER_LENGTH             (sizeof(WCHAR)*10)

#define DRIVE_LETTER_BUFFER_SIZE        10
#define DOS_DEVNAME_BUFFER_SIZE         (sizeof(DOS_DEVICE_NAME) / 2) + 10

#define RAMDISK_MEDIA_TYPE              0xF8
#define DIR_ENTRIES_PER_SECTOR          16

#define DEFAULT_DISK_SIZE               (1024*1024)     // 1 MB
#define DEFAULT_ROOT_DIR_ENTRIES        512
#define DEFAULT_SECTORS_PER_CLUSTER     2
#define DEFAULT_DRIVE_LETTER            L"Z:"

#pragma pack(1)

typedef struct _BOOT_SECTOR_FAT32
{
	UCHAR BS_jmpBoot[3];
	UCHAR BS_OEMName[8];
	UCHAR BPB_BytsPerSec;
	UCHAR BPB_SecPerClus; 
	SHORT BPB_RsvdSecCnt;
	UCHAR BPB_NumFATs; 
	SHORT BPB_RootEntCnt;
	USHORT BPB_TotSec16;
	UCHAR BPB_Media; 
	USHORT BPB_FATSz16;
	USHORT BPB_SecPerTrk; 
	USHORT BPB_NumHeads;
	ULONG BPB_HiddSec; 
	ULONG BPB_TotSec32; 
	ULONG BPB_FATSz32;
	USHORT BPB_ExtFlags;
	USHORT BPB_FSVer;
	ULONG BPB_RootClus; 
	USHORT BPB_FSInfo; 
	USHORT BPB_BkBootSec; 
	UCHAR BPB_Reserved[12]; 
	UCHAR BS_DrvNum;
	UCHAR BS_Reserved1;
	UCHAR BS_BootSig;
	ULONG BS_VolID; 
	UCHAR BS_VolLab[11];
	UCHAR BS_FileSystemType[8];
	UCHAR BS_ReservedPadding[420];  
	UCHAR BS_Sigature[2];
} BOOT_SECTOR_FAT32, *PBOOT_SECTOR_FAT32;

typedef struct  _BOOT_SECTOR_FAT16
{
    UCHAR       bsJump[3];          // x86 jmp instruction, checked by FS
    CCHAR       bsOemName[8];       // OEM name of formatter
    USHORT      bsBytesPerSec;      // Bytes per Sector
    UCHAR       bsSecPerClus;       // Sectors per Cluster
    USHORT      bsResSectors;       // Reserved Sectors
    UCHAR       bsFATs;             // Number of FATs - we always use 1
    USHORT      bsRootDirEnts;      // Number of Root Dir Entries
    USHORT      bsSectors;          // Number of Sectors
    UCHAR       bsMedia;            // Media type - we use RAMDISK_MEDIA_TYPE
    USHORT      bsFATsecs;          // Number of FAT sectors
    USHORT      bsSecPerTrack;      // Sectors per Track - we use 32
    USHORT      bsHeads;            // Number of Heads - we use 2
    ULONG       bsHiddenSecs;       // Hidden Sectors - we set to 0
    ULONG       bsHugeSectors;      // Number of Sectors if > 32 MB size
    UCHAR       bsDriveNumber;      // Drive Number - not used
    UCHAR       bsReserved1;        // Reserved
    UCHAR       bsBootSignature;    // New Format Boot Signature - 0x29
    ULONG       bsVolumeID;         // VolumeID - set to 0x12345678
    CCHAR       bsLabel[11];        // Label - set to RamDisk
    CCHAR       bsFileSystemType[8];// File System Type - FAT12 or FAT16
    CCHAR       bsReserved2[448];   // Reserved
    UCHAR       bsSig2[2];          // Originial Boot Signature - 0x55, 0xAA
}   BOOT_SECTOR_FAT16, *PBOOT_SECTOR_FAT16;

typedef struct  _DIR_ENTRY
{
    UCHAR       deName[8];          // File Name
    UCHAR       deExtension[3];     // File Extension
    UCHAR       deAttributes;       // File Attributes
    UCHAR       deReserved;         // Reserved
    USHORT      deTime;             // File Time
    USHORT      deDate;             // File Date
    USHORT      deStartCluster;     // First Cluster of file
    ULONG       deFileSize;         // File Length
}   DIR_ENTRY, *PDIR_ENTRY;

#pragma pack()

//
// Directory Entry Attributes
//

#define DIR_ATTR_READONLY   0x01
#define DIR_ATTR_HIDDEN     0x02
#define DIR_ATTR_SYSTEM     0x04
#define DIR_ATTR_VOLUME     0x08
#define DIR_ATTR_DIRECTORY  0x10
#define DIR_ATTR_ARCHIVE    0x20

//
// Function Prototypes
//

NTSTATUS 
VFSFormatFAT16(
		PVFS_DEVICE_EXTENSION devExt
		);


