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
#include <ntdddisk.h>
#include <Mountmgr.h>
#include <devioctl.h>
#include <ntddcdrm.h>
#include <ntddstor.h>
#include <ntiologc.h>
#include <Mountdev.h>

#include "ioctl.h"
#include "vfsworker.h"
#include "vfscompat.h"
#include "vfsio.h"

//
// Disable compiler warnings
//

#pragma warning( disable: 4995 )
#pragma warning( disable: 4996 )

//
// VFS Macros
//

#define VFS_MiB(mb) (mb * 1024 * 1024)
#define VFS_EXTENSION(DeviceObject) ((PVFS_DEVICE_EXTENSION) DeviceObject->DeviceExtension)

//
// Type of the filesystem of the VFS object
//

#define FAT16 16
#define FAT32 32
#define NOFORMAT 0

//
// Symmetric key used to decrypt/encrypt the VFS
//

typedef struct _VFS_KEY {
	UCHAR key[16];
} VFS_KEY, *PVFS_KEY;

//
// Information which describes virtual file system object
//

typedef struct _VFS_DEVICE_EXTENSION {

	//
	// Information on virtual file system
	//

	DISK_GEOMETRY       DiskGeometry;  
	PCHAR		    DiskImage;
	ULONG 		    DiskSize;
	ULONG	            FileSystemType;

	//
	// Synchronization for work queue
	//
	
	KSEMAPHORE semQueue;         
	KSPIN_LOCK lockQueue;       
	LIST_ENTRY QueueListHead;  

	//
	// Handle to memory mapped file object
	//

	PHANDLE VFSFileHandle;
	PHANDLE VFSSection;
	HANDLE ProcessHandle;

} VFS_DEVICE_EXTENSION, *PVFS_DEVICE_EXTENSION;

//
// VFS Function Prototypes
//

NTSTATUS 
VFSInit(
		IN PDRIVER_OBJECT DriverObject, 
		IN PUNICODE_STRING regPath
       );

NTSTATUS
VFSCreateDisk(
		IN PUNICODE_STRING DeviceName,
		IN PUNICODE_STRING DriveName,
		IN PUNICODE_STRING FilePath,
		OUT PDEVICE_OBJECT *VFSHandle,	
		IN PVFS_KEY SymmetricKey,
		IN PLARGE_INTEGER   VFSSize,
		IN ULONG   FSType
	   );
