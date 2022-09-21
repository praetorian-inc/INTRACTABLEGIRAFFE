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

//
// Define the keyboard indicators
//

#define KEYBOARD_LED_INJECTED     0x8000
#define KEYBOARD_SHADOW           0x4000
#define KEYBOARD_KANA_LOCK_ON     8
#define KEYBOARD_CAPS_LOCK_ON     4
#define KEYBOARD_NUM_LOCK_ON      2
#define KEYBOARD_SCROLL_LOCK_ON   1


#define IOCTL_KEYBOARD_QUERY_ATTRIBUTES \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEYBOARD_QUERY_INDICATORS \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0020, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEYBOARD_QUERY_TYPEMATIC \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEYBOARD_SET_TYPEMATIC \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEYBOARD_SET_INDICATORS \
  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0002, METHOD_BUFFERED, FILE_ANY_ACCESS)

DEFINE_GUID(GUID_DEVINTERFACE_KEYBOARD, \
  0x884b96c3, 0x56ef, 0x11d1, 0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd);

#define KEYBOARD_ERROR_VALUE_BASE         10000

/* KEYBOARD_INPUT_DATA.MakeCode constants */
#define KEYBOARD_OVERRUN_MAKE_CODE        0xFF

/* KEYBOARD_INPUT_DATA.Flags constants */
#define KEY_MAKE                          0
#define KEY_BREAK                         1
#define KEY_E0                            2
#define KEY_E1                            4

typedef struct _KEYBOARD_INPUT_DATA {
  USHORT  UnitId;
  USHORT  MakeCode;
  USHORT  Flags;
  USHORT  Reserved;
  ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;


typedef struct _KEYBOARD_TYPEMATIC_PARAMETERS {
	USHORT  UnitId;
	USHORT  Rate;
	USHORT  Delay;
} KEYBOARD_TYPEMATIC_PARAMETERS, *PKEYBOARD_TYPEMATIC_PARAMETERS;

typedef struct _KEYBOARD_ID {
	UCHAR  Type;
	UCHAR  Subtype;
} KEYBOARD_ID, *PKEYBOARD_ID;

#define ENHANCED_KEYBOARD(Id) ((Id).Type == 2 || (Id).Type == 4 || FAREAST_KEYBOARD(Id))
#define FAREAST_KEYBOARD(Id)  ((Id).Type == 7 || (Id).Type == 8)

typedef struct _KEYBOARD_INDICATOR_PARAMETERS {
  USHORT  UnitId;
  USHORT  LedFlags;
} KEYBOARD_INDICATOR_PARAMETERS, *PKEYBOARD_INDICATOR_PARAMETERS;

typedef struct _INDICATOR_LIST {
  USHORT  MakeCode;
  USHORT  IndicatorFlags;
} INDICATOR_LIST, *PINDICATOR_LIST;

typedef struct _KEYBOARD_INDICATOR_TRANSLATION {
  USHORT  NumberOfIndicatorKeys;
  INDICATOR_LIST  IndicatorList[1];
} KEYBOARD_INDICATOR_TRANSLATION, *PKEYBOARD_INDICATOR_TRANSLATION;

typedef struct _KEYBOARD_ATTRIBUTES {
	KEYBOARD_ID  KeyboardIdentifier;
	USHORT  KeyboardMode;
	USHORT  NumberOfFunctionKeys;
	USHORT  NumberOfIndicators;
	USHORT  NumberOfKeysTotal;
	ULONG  InputDataQueueLength;
	KEYBOARD_TYPEMATIC_PARAMETERS  KeyRepeatMinimum;
	KEYBOARD_TYPEMATIC_PARAMETERS  KeyRepeatMaximum;
} KEYBOARD_ATTRIBUTES, *PKEYBOARD_ATTRIBUTES;

typedef struct _KEYBOARD_UNIT_ID_PARAMETER {
  USHORT  UnitId;
} KEYBOARD_UNIT_ID_PARAMETER, *PKEYBOARD_UNIT_ID_PARAMETER;

typedef struct _KEYBOARD_IME_STATUS {
	USHORT  UnitId;
	ULONG  ImeOpen;
	ULONG  ImeConvMode;
} KEYBOARD_IME_STATUS, *PKEYBOARD_IME_STATUS;

//
// Undocumented NT Functions
//

typedef struct _DIRECTORY_BASIC_INFORMATION
{
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

extern NTSYSAPI NTSTATUS NTAPI
ZwOpenDirectoryObject(OUT PHANDLE DirectoryObjectHandle, IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes);

extern NTSYSAPI NTSTATUS NTAPI
ZwQueryDirectoryObject(IN HANDLE DirectoryObjectHandle, 
		OUT PDIRECTORY_BASIC_INFORMATION DirObjInformation,
		IN ULONG BufferLength, IN BOOLEAN GetNextIndex,
		IN BOOLEAN IgnoreInputIndex, IN OUT PULONG ObjectIndex,
		OUT PULONG DataWritten OPTIONAL);


