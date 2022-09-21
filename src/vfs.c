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
#include "vfscompat.h"
#include "vfsworker.h"

//
// Check if VFS has been initialized
//

#define VFS_INITIALIZED() if(VFSDriverObject == NULL) { \
	DbgPrint("Error VFS module has not been initialized"); \
	return STATUS_UNSUCCESSFUL; \
} 

//
// Driver Object for VFS
//

static PDRIVER_OBJECT VFSDriverObject = NULL;

//
// Forward declarations
//

static NTSTATUS
VFSPrepareFileSystem(
		IN  PUNICODE_STRING DeviceName,
		IN  PUNICODE_STRING DriveName,
		OUT HANDLE *VFSHandle,
		IN  PVOID DiskImage,
		IN  ULONG DiskSize,
		IN  ULONG FSType,
		HANDLE VFSFileHandle,
		HANDLE VFSSection,
		HANDLE ProcessHandle
	    );

static NTSTATUS 
VFSShutdown(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
		);

NTSTATUS 
VFSInit(
		IN PDRIVER_OBJECT DriverObject, 
		IN PUNICODE_STRING regPath
		)

/*++

  Routine Description:
  
  	Initializes the VFS subsystem

  Arguments:

  	DriverObject - Standard driver object structure for exclusive use by
		           VFS component is stored in static variable
	
	regPath - This parameter is not used by anything currently

  Return Value:
  
  	Always returns successfully

--*/

{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(regPath);

	VFSDriverObject = DriverObject;
	
 	DriverObject->MajorFunction[IRP_MJ_CREATE]          = VFSCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = VFSCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = VFSIoctl;
    DriverObject->MajorFunction[IRP_MJ_READ]            = VFSQueueWorkItem;
    DriverObject->MajorFunction[IRP_MJ_WRITE]           = VFSQueueWorkItem;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]        = VFSShutdown;

	return STATUS_SUCCESS;
}

NTSTATUS
VFSCreateDisk(
		IN PUNICODE_STRING DeviceName,
		IN PUNICODE_STRING DriveName,
		IN PUNICODE_STRING FilePath,
		OUT PDEVICE_OBJECT *VFSHandle,	
		IN PVFS_KEY SymmetricKey,
		IN PLARGE_INTEGER   VFSSize,
		IN ULONG   FSType
	   )

/*++

  Routine Description:
  
  	Creates a new/mounts an existing virtual file system driver

	One important thing to note is that if you are trying to format a file backed VFS and
	that has already been formated you must first delete the file before you call this API
	otherwise it will not be formatted properly.
	
  Arguments:

  	DeviceName   - Device name of the hard disk (e.g. \Device\RawDisk1)

	DriveName    - Name of the drive (e.g. \DosDevices\Hd1)
  
  	FilePath     - Path of the encrypted volume to be mounted/created in the past to a file on disk which
		           will be opened/created. Is null if you want to create a ramdisk
	
	VFSObjectRet - Returns to the caller a pointer to the VFS object structure of the newly 
		           created VFS object on successful mount on the drive. This pointer will be
		           set to null if the drive is not mounted properly
	
	SymmetricKey - Symmetric key for CAST128 cipher which will be used to decrypt the
		           contents of the VFS on access 
	
	VFSSize      - Size of the virtual filesystem is only applicable if the virtual filesystem
       		       does not exist or we are creating a ramdisk/volatile drive. Must be a multiple of
		           512 bytes

    FSType	 - Filesystem to format the driver if applicable. If you are trying 

  Return Value:

    	NTSTATUS (indicating success/failure)

--*/

{
	NTSTATUS status;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK IOStatus;
	PVOID DiskImage = NULL;
	SIZE_T DiskSize = 0;
	HANDLE VFSFileHandle;
	HANDLE VFSSection;
	HANDLE ProcessHandle;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(SymmetricKey);
	
	VFS_INITIALIZED();

	//
	// If the size of the VFS is less than 8MB or the size of the VFS is 
	// not a multiple of 512 then the VFS size is invalid size
	//
	
	if(VFSSize->QuadPart % 512 != 0 ||
			VFSSize->QuadPart < VFS_MiB(8)) {
		DbgPrint("[VFS] Error invalid VFS size");
		return STATUS_UNSUCCESSFUL;
	}

	//
	// If we are given a file path try to open if we are not
	// given a file path then we know that the caller wants to
	// create a ramdisk drive
	//

	if(FilePath != NULL)  {

		InitializeObjectAttributes(&ObjAttr, 
				FilePath, 
				OBJ_CASE_INSENSITIVE, 
				NULL, 
				NULL);

		status = ZwCreateFile(&VFSFileHandle,
				FILE_APPEND_DATA,
				&ObjAttr,
				&IOStatus,
				VFSSize,  
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ, 
				FILE_OPEN_IF,
				FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT | 
				FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS,
				NULL,
				0);

		if(!NT_SUCCESS(status)) {
			DbgPrint("[VFS] Opening of VFS virtual drive failed");
			return status;
		}

		//
		// Check if file was just created and allocation specified was zero. This
		// is an error and we will delete/close the file if this is the case 
		//
		
		if(IOStatus.Information == FILE_CREATED && VFSSize == 0) {
			DbgPrint("[VFS] Error VFS file does not exist and VFS size is zero");

			ZwClose(VFSFileHandle);
			return STATUS_UNSUCCESSFUL;
		} 
		
		//
		// If file already exists then we do not need to format it
		//

		if(IOStatus.Information == FILE_OPENED) {
			DbgPrint("[VFS] The VFS already exists so we will not format it now");
			FSType = NOFORMAT;
		}

	} else { // No path provided means we want to create a ramdisk
		VFSFileHandle = NULL;
	}


	//
	// We need to create a section object in order to map the section into 
	// virtual memory space of system process. To do this we must initialize 
	// the attributes of the object
	//

	InitializeObjectAttributes(
			&ObjAttr,
			NULL,
			OBJ_KERNEL_HANDLE | OBJ_EXCLUSIVE,
			NULL,
			NULL);

	status = ZwCreateSection(
			&VFSSection,
			SECTION_ALL_ACCESS,
			&ObjAttr,
			VFSSize,
			PAGE_READWRITE,
			0x8000000 | 0x10000000, // SEC_COMMIT | SEC_NOCACHE
			VFSFileHandle);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[VFS] ZwCreateSection failed when mapping VFS");
		return status;
	}

	ProcessHandle = NtCurrentProcess();

	status = ZwMapViewOfSection(VFSSection,
			ProcessHandle,
			&DiskImage,
			1,
			0,
			NULL,
			&DiskSize,
			ViewUnmap,
			0,
			PAGE_READWRITE);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[VFS] ZwMapViewOfSection failed while tring to map VFS into memory and STATUS = %d", status);
		return status;
	}

	//
	// Now that file has been mapped we need to setup the virtual filesystem
	// so that it is accessible from usermode
	//

	status = VFSPrepareFileSystem(
			DeviceName,
			DriveName,
			VFSHandle,
			DiskImage,
			(ULONG)VFSSize->QuadPart,
			FSType,
			VFSFileHandle,
			VFSSection,
			ProcessHandle);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[VFS] Setup of virtual file system failed");
		return status;
	}

	return status;
}

static NTSTATUS
VFSPrepareFileSystem(
		IN  PUNICODE_STRING DeviceName,
		IN  PUNICODE_STRING DriveName,
		OUT PDEVICE_OBJECT *VFSHandle,
		IN  PVOID DiskImage,
		IN  ULONG DiskSize,
		IN  ULONG FSType,
		HANDLE VFSFileHandle,
		HANDLE VFSSection,
		HANDLE ProcessHandle
	    )

/*++

  Routine Description:

 	Internal routine that handles setup and initialization of the VFS

  Arguments:

	DeviceName    - Name of the VFS device

	DriveName     - Name of the disk/symbolic link name (e.g. \DosDevices\Hd1\)

	VFSObject     - Output is initialized VFS structure 

	DiskImage     - Pointer to memory allocated to store VFS or memory mapped file

	DiskSize      - Must be multiple of 512

	FSType        - Enum which represents type of file system to format drive	

	VFSFileHandle - Handle to the file backing the VFS or is NULL if we are creating a ramdisk
	
	VFSSection    - Section object which backs the memory mapped file
	
	ProcessHandle - Handle to the userland process which the memory mapped file is
			        mapped into this should always be the [SYSTEM] (PID = 4) process

  Return Value:
  
  	Returns success or error condition if VFS object fails to be created

--*/

{
	NTSTATUS status;
	PVFS_DEVICE_EXTENSION VFSExtension;
	PDEVICE_OBJECT DeviceObject;

	PAGED_CODE();

	ASSERT(DeviceName != NULL);
	ASSERT(DriveName != NULL);
	ASSERT(DiskImage != NULL);
	ASSERT(DiskSize % 512 == 0);

	VFS_INITIALIZED();

	status = IoCreateDevice(VFSDriverObject,
			                sizeof(VFS_DEVICE_EXTENSION),          
			                DeviceName,
			                FILE_DEVICE_DISK,
			                0,
			                FALSE,
			                &DeviceObject);

	if (NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink(DriveName, DeviceName);
	} else {
		DbgPrint("[IG] Failed to Create Device Object for Driver");
		return status;
	}

	RtlZeroMemory(DeviceObject->DeviceExtension, sizeof(VFS_DEVICE_EXTENSION)); 
	VFSExtension = VFS_EXTENSION(DeviceObject);

	VFSExtension->VFSFileHandle  = VFSFileHandle;
	VFSExtension->VFSSection     = VFSSection;
	VFSExtension->ProcessHandle  = ProcessHandle;

	VFSExtension->DiskImage      = DiskImage;
	VFSExtension->DiskSize       = DiskSize;
	VFSExtension->FileSystemType = FSType;
	
	VFSExtension->DiskGeometry.Cylinders.QuadPart = VFSExtension->DiskSize / 512 / 32 / 2;
	VFSExtension->DiskGeometry.MediaType = FixedMedia;
    VFSExtension->DiskGeometry.TracksPerCylinder = 2;  
    VFSExtension->DiskGeometry.SectorsPerTrack = 32;    
	VFSExtension->DiskGeometry.BytesPerSector = 512;

	switch(VFSExtension->FileSystemType) {

		case FAT16:
			VFSFormatFAT16(VFSExtension);
			break;

		case NOFORMAT:
			break;

		default:
			DbgPrint("[IG] Failure Unrecognized Filesystem Type Specified");
			return STATUS_UNSUCCESSFUL;
	}	

	//
	// Prepare the worker thread which will handle processing of
	// the read/write requests to the hard disk
	//
	
	PrepareVFSWorkerThread(DeviceObject); 

	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	//
	// Return the address of VFS device object to the caller
	//
	
	*VFSHandle = DeviceObject;

	return status;
}

static NTSTATUS 
VFSShutdown(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
		) 

{
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);

	//
	// We need to make sure we properly close and unmap the sections
	// and close the file to make sure all changes to VFS are flushed
	// from the cache
	//

	ZwUnmapViewOfSection(VFSExtension->ProcessHandle, VFSExtension->DiskImage);
	ZwClose(VFSExtension->VFSSection);
	ZwClose(VFSExtension->VFSFileHandle);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}