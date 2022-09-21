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

#include <ntddk.h>

#include "vfs.h"
#include "format.h"

NTSTATUS
VFSFormatFAT16(
    IN PVFS_DEVICE_EXTENSION VFSExtension
    )

/*++

  Routine Description:

  	This routine formats the new disk as a FAT16 filesystem

  Arguments:
  
  	DeviceObject - Supplies a pointer to the device object that represents
                   the device whose capacity is to be read.

  Return Value:
  
  	NTSTATUS (status of the formatting operation)

--*/

{

    PBOOT_SECTOR_FAT16 bootSector = (PBOOT_SECTOR_FAT16) VFSExtension->DiskImage;
    PUCHAR       firstFatSector;
    ULONG        rootDirEntries;
    ULONG        sectorsPerCluster;
    USHORT       fatEntries;     // Number of cluster entries in FAT
    USHORT       fatSectorCnt;   // Number of sectors for FAT
    PDIR_ENTRY   rootDir;        // Pointer to first entry in root dir

    PAGED_CODE();
    ASSERT(sizeof(BOOT_SECTOR_FAT16) == 512);
    ASSERT(VFSExtension->DiskImage != NULL);

    RtlZeroMemory(VFSExtension->DiskImage, VFSExtension->DiskSize);

    VFSExtension->DiskGeometry.BytesPerSector = 512;
    VFSExtension->DiskGeometry.SectorsPerTrack = 32;     // Using Ramdisk value
    VFSExtension->DiskGeometry.TracksPerCylinder = 2;    // Using Ramdisk value

    //
    // Calculate number of cylinders.
    //

    VFSExtension->DiskGeometry.Cylinders.QuadPart = VFSExtension->DiskSize / 512 / 32 / 2;

    //
    // Our media type is RAMDISK_MEDIA_TYPE
    //

    VFSExtension->DiskGeometry.MediaType = 0xF8;

    KdPrint(("Cylinders: %I64d\n TracksPerCylinder: %lu\n SectorsPerTrack: %lu\n BytesPerSector: %lu\n",
        VFSExtension->DiskGeometry.Cylinders.QuadPart, VFSExtension->DiskGeometry.TracksPerCylinder,
        VFSExtension->DiskGeometry.SectorsPerTrack, VFSExtension->DiskGeometry.BytesPerSector
    ));

    rootDirEntries = 224;
    sectorsPerCluster = 16;

    //
    // Round Root Directory entries up if necessary
    //

    if (rootDirEntries & (DIR_ENTRIES_PER_SECTOR - 1)) {
        rootDirEntries = (rootDirEntries + (DIR_ENTRIES_PER_SECTOR - 1)) & ~(DIR_ENTRIES_PER_SECTOR - 1);
    }

    KdPrint(("Root dir entries: %lu\n Sectors/cluster: %lu\n",
        rootDirEntries, sectorsPerCluster
    ));

    //
    // We need to have the 0xeb and 0x90 since this is one of the
    // checks the file system recognizer uses
    //

    bootSector->bsJump[0] = 0xeb;
    bootSector->bsJump[1] = 0x3c;
    bootSector->bsJump[2] = 0x90;

    //
    // Set OemName to "RajuRam "
    // NOTE: Fill all 8 characters, eg. sizeof(bootSector->bsOemName);
    //

    bootSector->bsOemName[0] = 'R';
    bootSector->bsOemName[1] = 'a';
    bootSector->bsOemName[2] = 'j';
    bootSector->bsOemName[3] = 'u';
    bootSector->bsOemName[4] = 'R';
    bootSector->bsOemName[5] = 'a';
    bootSector->bsOemName[6] = 'm';
    bootSector->bsOemName[7] = ' ';

    bootSector->bsBytesPerSec = (SHORT)VFSExtension->DiskGeometry.BytesPerSector;
    bootSector->bsResSectors  = 1;
    bootSector->bsFATs        = 1;
    bootSector->bsRootDirEnts = (USHORT)rootDirEntries;

    bootSector->bsSectors     = (USHORT)(VFSExtension->DiskSize / VFSExtension->DiskGeometry.BytesPerSector);
    bootSector->bsMedia       = (UCHAR)VFSExtension->DiskGeometry.MediaType;
    bootSector->bsSecPerClus  = (UCHAR)sectorsPerCluster;

    //
    // Calculate number of sectors required for FAT
    //

    fatEntries = (bootSector->bsSectors - bootSector->bsResSectors - bootSector->bsRootDirEnts / DIR_ENTRIES_PER_SECTOR) / bootSector->bsSecPerClus + 2;

    DbgPrint("[IG Driver:Ramdisk] FAT 16 SELECTED");

    fatSectorCnt = (fatEntries * 2 + 511) / 512;
    fatEntries   = fatEntries + fatSectorCnt;
    fatSectorCnt = (fatEntries * 2 + 511) / 512;

    bootSector->bsFATsecs       = fatSectorCnt;
    bootSector->bsSecPerTrack   = (USHORT)VFSExtension->DiskGeometry.SectorsPerTrack;
    bootSector->bsHeads         = (USHORT)VFSExtension->DiskGeometry.TracksPerCylinder;
    bootSector->bsBootSignature = 0x0;
    bootSector->bsVolumeID      = 0xC0FFFFEE;

    bootSector->bsLabel[0]  = 'N';
    bootSector->bsLabel[1]  = 'O';
    bootSector->bsLabel[2]  = ' ';
    bootSector->bsLabel[3]  = 'N';
    bootSector->bsLabel[4]  = 'A';
    bootSector->bsLabel[5]  = 'M';
    bootSector->bsLabel[6]  = 'E';
    bootSector->bsLabel[7]  = ' ';
    bootSector->bsLabel[8]  = ' ';
    bootSector->bsLabel[9]  = ' ';
    bootSector->bsLabel[10] = ' ';

    bootSector->bsFileSystemType[0] = 'F';
    bootSector->bsFileSystemType[1] = 'A';
    bootSector->bsFileSystemType[2] = 'T';
    bootSector->bsFileSystemType[3] = '1';
    bootSector->bsFileSystemType[4] = '6';
    bootSector->bsFileSystemType[5] = ' ';
    bootSector->bsFileSystemType[6] = ' ';
    bootSector->bsFileSystemType[7] = ' ';

    bootSector->bsSig2[0] = 0x55;
    bootSector->bsSig2[1] = 0xAA;

    //
    // The FAT is located immediately following the boot sector.
    //

    firstFatSector    = (PUCHAR)(bootSector + 1);
    firstFatSector[0] = (UCHAR)VFSExtension->DiskGeometry.MediaType;
    firstFatSector[1] = 0xFF;
    firstFatSector[2] = 0xFF;


    firstFatSector[3] = 0xFF;


    //
    // The Root Directory follows the FAT
    //

    rootDir = (PDIR_ENTRY)(bootSector + 1 + fatSectorCnt);
    
    rootDir->deName[0] = ' ';
    rootDir->deName[1] = ' ';
    rootDir->deName[2] = ' ';
    rootDir->deName[3] = ' ';
    rootDir->deName[4] = ' ';
    rootDir->deName[5] = ' ';
    rootDir->deName[6] = ' ';
    rootDir->deName[7] = ' ';

    rootDir->deExtension[0] = ' ';
    rootDir->deExtension[1] = ' ';
    rootDir->deExtension[2] = ' ';

    rootDir->deAttributes = DIR_ATTR_VOLUME;

    return STATUS_SUCCESS;
}