// Copyright (c) Javelin Networks. All rights reserved.
// This is a modified version of CorProfiler by .NET Foundation (with the same license):
// Copyright (c) .NET Foundation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "ClassFactory.h"

const IID IID_IUnknown      = { 0x00000000, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

const IID IID_IClassFactory = { 0x00000001, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

BOOL STDMETHODCALLTYPE DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}

extern "C" HRESULT STDMETHODCALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    // {cf0d821e-299b-5307-a3d8-b283c03916db}
	if (ppv == nullptr || rclsid != CLSID_InvisiShellProfilerInvisiShell)
    {
        return E_FAIL;
    }

    auto factory = new ClassFactory;
    if (factory == nullptr)
    {
        return E_FAIL;
    }


    return factory->QueryInterface(riid, ppv);
}

extern "C" HRESULT STDMETHODCALLTYPE DllCanUnloadNow()
{

    return S_OK;
}