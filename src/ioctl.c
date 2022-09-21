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

#include "ioctl.h"
#include "vfs.h"

static VOID VFSDiskVerify(PIO_STACK_LOCATION irpStack, PVFS_DEVICE_EXTENSION VFSExtension, PIRP irp);
static VOID VFSGetDiskLengthInfo(PIO_STACK_LOCATION irpStack, PVFS_DEVICE_EXTENSION VFSExtension, PIRP irp);
static VOID VFSGetParitionInfo(IN PIO_STACK_LOCATION irpStack, IN PVFS_DEVICE_EXTENSION VFSExtension, IN OUT PIRP irp);
static VOID VFSGetParitionInfoEx(PIO_STACK_LOCATION irpStack, IN PVFS_DEVICE_EXTENSION VFSExtension, IN OUT PIRP irp);
static VOID VFSQueryDiskGeometry(PIO_STACK_LOCATION irpStack, PVFS_DEVICE_EXTENSION VFSExtension, PIRP irp);

NTSTATUS 
VFSIoctl(
		IN PDEVICE_OBJECT DeviceObject, 
		OUT PIRP irp
		)

/*++

  Routine Description:
  
  	This component processes IOCTLs required for a device which emulates a hard disk drive

  Arguments:
  
  	DeviceObject is the deivce object associated with the driver

	irp is the IRP associated with the IOCTL request

  Return Value:
  
  	Returns an NTSTATUS value indicating success/failure of processing
	of IOCTL

 --*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);

	//
	// Handles Windows Disk Driver IOCTLs Required for Emulating a Hard Drive
	//

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {

		case IOCTL_DISK_GET_MEDIA_TYPES:
	        case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
			DbgPrint("[IG VFS] IOCTL_DISK_GET_DRIVE_GEOMETRY");
			VFSQueryDiskGeometry(irpStack, VFSExtension, irp);
			break;

		case IOCTL_DISK_GET_PARTITION_INFO:
			DbgPrint("[IG VFS] IOCTL_DISK_GET_PARTITION_INFO");
			VFSGetParitionInfo(irpStack, VFSExtension, irp);
			break;

		case IOCTL_DISK_GET_LENGTH_INFO:
			DbgPrint("[IG VFS] IOCTL_DISK_GET_LENGTH_INFO");
			VFSGetDiskLengthInfo(irpStack, VFSExtension, irp);
			break;

		case IOCTL_DISK_CHECK_VERIFY:
		case IOCTL_DISK_IS_WRITABLE:
		case IOCTL_DISK_MEDIA_REMOVAL:
		case IOCTL_DISK_SET_PARTITION_INFO:
		case IOCTL_DISK_VERIFY:
		case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
		case IOCTL_STORAGE_CHECK_VERIFY2:
		case IOCTL_STORAGE_CHECK_VERIFY:
		case IOCTL_STORAGE_MEDIA_REMOVAL:
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			break;

		default:
			irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			irp->IoStatus.Information = 0;
			break;
	}

	status = irp->IoStatus.Status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

VOID 
VFSGetParitionInfo(
		PIO_STACK_LOCATION irpStack,
		IN PVFS_DEVICE_EXTENSION DeviceExtension,
		IN OUT PIRP irp
		)
{
        PPARTITION_INFORMATION partition;

        if (irpStack->Parameters.DeviceIoControl.OutputBufferLength 
			< sizeof(PARTITION_INFORMATION)) {
                irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                return;
        }

        partition = (PPARTITION_INFORMATION)(irp->AssociatedIrp.SystemBuffer);

        partition->PartitionType = PARTITION_FAT32;
        partition->PartitionNumber = 1;                   

        partition->BootIndicator = FALSE;      
        partition->RecognizedPartition = TRUE;  
        partition->RewritePartition = FALSE;    

        partition->StartingOffset.QuadPart = (ULONGLONG)(0); 
        partition->PartitionLength.QuadPart = DeviceExtension->DiskSize;
        partition->HiddenSectors = 0; 

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);
}

VOID
VFSQueryDiskGeometry(
		PIO_STACK_LOCATION irpStack,
		PVFS_DEVICE_EXTENSION DeviceExtension,
		PIRP irp
		) 
{
	PDISK_GEOMETRY  geometry;

	if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY)) {
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
		return;
	}

	geometry = (PDISK_GEOMETRY) irp->AssociatedIrp.SystemBuffer;

	RtlCopyMemory(geometry, &DeviceExtension->DiskGeometry, sizeof(DISK_GEOMETRY));

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(DISK_GEOMETRY);
}

VOID
VFSGetDiskLengthInfo(
		PIO_STACK_LOCATION irpStack,
		PVFS_DEVICE_EXTENSION VFSExtension,
		PIRP irp
		)
{
	PGET_LENGTH_INFORMATION length;

	if (irpStack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(GET_LENGTH_INFORMATION))
	{
		irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Information = 0;
		return;
	}

	length = (PGET_LENGTH_INFORMATION) irp->AssociatedIrp.SystemBuffer;
	length->Length.QuadPart = VFSExtension->DiskSize;

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);
}

VOID
VFSDiskVerify(
		PIO_STACK_LOCATION irpStack, 
		PVFS_DEVICE_EXTENSION VFSExtension, 
		PIRP irp
		)
{
	PVERIFY_INFORMATION verify_information;

	UNREFERENCED_PARAMETER(VFSExtension);

	if (irpStack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(VERIFY_INFORMATION))
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		return;
	}

	verify_information = (PVERIFY_INFORMATION) irp->AssociatedIrp.SystemBuffer;

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = verify_information->Length;
}