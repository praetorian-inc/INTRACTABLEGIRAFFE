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
#include "vfsio.h"

NTSTATUS 
PrepareVFSWorkerThread(
		IN PDEVICE_OBJECT DeviceObject
		) 

/*++

Routine Description:

    Creates a worker thread which is responsible for handling read/write operations
    to the virtual file system

Arguments:

    DeviceObject - DeviceObject associated with the virtual file system

Return Value:

    Returns an NTSTATUS code indicating success or failure

--*/

{
	HANDLE WorkerThread; 
	NTSTATUS status;
	PVFS_DEVICE_EXTENSION VFSExtension;

	VFSExtension = VFS_EXTENSION(DeviceObject);

	//
	// Initializes synchronization primitives used for synchronizing
	// access to/from the virtual file system
	//

	InitializeListHead(&VFSExtension->QueueListHead);
	KeInitializeSpinLock(&VFSExtension->lockQueue);                                      
	KeInitializeSemaphore(&VFSExtension->semQueue, 0 , MAXLONG); 

	//
	// Creates a worker thread which will be responsible for handling read/write
	// requests to the virtual file system
	//

	status = PsCreateSystemThread(&WorkerThread, 
	                              (ACCESS_MASK)0, 
								  NULL, 
								  (HANDLE)0, 
								  NULL, 
								  VFSWorkerThread, 
								  DeviceObject);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[IG] Failed to Create a Worker Thread for the VFS");
		return status;
	}

	ZwClose(WorkerThread);

	return status;
}

VOID 
VFSWorkerThread(
		IN PDEVICE_OBJECT DeviceObject
		) 

/*++

Routine Description:

    Waits for read/write operations to be added to the work queue and waits in
    an alertable state for items to be added to the queue if it is empty

Arguments:

    DeviceObject the

Return Value:

    VOID (no return)

--*/

{
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);
	PLIST_ENTRY ListEntry;
	PIRP irp;
	PIO_STACK_LOCATION irpStack;

	PAGED_CODE();

	while(TRUE) {

		//
		// If we don't have any more requests to process we just sleep and 
		// for more requets to be added to the queue
		//

		KeWaitForSingleObject(&VFSExtension->semQueue, 
				              Executive, 
				              KernelMode, 
				              FALSE, 
				              NULL);

		ListEntry = ExInterlockedRemoveHeadList(&VFSExtension->QueueListHead,
				                                &VFSExtension->lockQueue);
		irp = CONTAINING_RECORD(ListEntry, IRP, Tail.Overlay.ListEntry);

		//
		// Route request to read/write handler
		//

		irpStack = IoGetCurrentIrpStackLocation(irp);

		if(irpStack->MajorFunction == IRP_MJ_READ) {
			VFSRead(DeviceObject, irp);
		} else if(irpStack->MajorFunction == IRP_MJ_WRITE) {
			VFSWrite(DeviceObject, irp);
		}

	}
}

NTSTATUS
VFSQueueWorkItem(
		IN PDEVICE_OBJECT DeviceObject, 
		IN PIRP irp
		)

/*++

  Routine Description:

	Queues read/write I/O request packet to work queue which will then
	be read by the worker thread which monitors the work queue and
	completes the IRP

  Arguments:

  	DeviceObject - DeviceObject associated with the VFS which is
		           trying to be read/written to
	
	irp - I/O Request Packet associated with the read/write request

  Return Value:
  	
  	Returns STATUS_PENDING to indicate that the IRP is waiting to 
	be processed by worker thread

--*/

{
	PVFS_DEVICE_EXTENSION VFSExtension = VFS_EXTENSION(DeviceObject);

	IoMarkIrpPending(irp);

	ExInterlockedInsertTailList(&VFSExtension->QueueListHead,
			&irp->Tail.Overlay.ListEntry,
			&VFSExtension->lockQueue);

	KeReleaseSemaphore(&VFSExtension->semQueue, 0, 1, FALSE);

	return STATUS_PENDING;
}
