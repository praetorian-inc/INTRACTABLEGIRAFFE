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

#include "klogcompat.h"
#include "keylog.h"

NTSTATUS 
DispatchIRPUnsupported(
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP irp
	)

/*++

  Routine Description:
  
  	Generic handler for IRPs which are not supported we return a
	status of STATUS_NOT_IMPLEMENTED

  Arguments:

  	DeviceObject - device associated with the IRP
	
	irp - I/O Request Packet

  Return Value:
  
  	Returns status saying that the request is not implemented

--*/

{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(DeviceObject);

	//
	// Since we are the lowest level driver in the device stack we
	// do not have a lower level driver for which we need to pass
	// unsupported IRPs 
	//

	status = irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS 
DispatchPassThrough(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
		)
{
	IoSkipCurrentIrpStackLocation(irp);
	return IoCallDriver(((PKEYLOG_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->KeyboardDevice ,irp);
}
