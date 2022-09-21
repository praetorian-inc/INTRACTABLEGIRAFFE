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

NTSTATUS
VFSRead(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
    )

/*++
  
  Routine Description:
  
  	Handler for IRP_MJ_READ requests to VFS
	
  Arguments:
  
  	DeviceObject - DeviceObject associated with device IRP is destined 
	
	irp - I/O Request Packet associated with request

Return Value:

    	Always returns successfully

--*/

{
	PUCHAR src;
	PUCHAR dest;
	PIO_STACK_LOCATION irpStack;
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);

	irpStack = IoGetCurrentIrpStackLocation(irp);

    src = (PUCHAR)(VFSExtension->DiskImage + irpStack->Parameters.Read.ByteOffset.LowPart);
	dest = MmGetSystemAddressForMdl(irp->MdlAddress);

    RtlCopyBytes(dest, src, irpStack->Parameters.Read.Length);

	irp->IoStatus.Information = irpStack->Parameters.Read.Length;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
VFSWrite(
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP irp
    )

/*++

  Routine Description:
  
  	Handler for IRP_MJ_WRITE requests to VFS 
	
  Arguments:

  	DeviceObject - device associated with the IRP
	
	irp - I/O Request Packet

Return Value:

	Always returns successfully

--*/

{
	PUCHAR src;
	PUCHAR dest;
	PIO_STACK_LOCATION irpStack;
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);

	irpStack = IoGetCurrentIrpStackLocation(irp);

    src = (PUCHAR)(VFSExtension->DiskImage + irpStack->Parameters.Write.ByteOffset.LowPart);
	dest = MmGetSystemAddressForMdl(irp->MdlAddress);

    RtlCopyBytes(src, dest, irpStack->Parameters.Write.Length);

	irp->IoStatus.Information = irpStack->Parameters.Read.Length;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}