// Copyright (c) Javelin Networks. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


#pragma once

#include <Windows.h>


typedef struct _HookData
{
	WCHAR szHookedModuleName[MAX_PATH];
	WCHAR szHookedClass[MAX_PATH];
	WCHAR szHookedFunction[MAX_PATH];
	BYTE nHookedFunctionArgumentsCount;
	BYTE lpHookBuffer[MAX_PATH];
	BYTE nHookBufferSize;
	BOOL bHooked;
} HookData, *PHookData;
