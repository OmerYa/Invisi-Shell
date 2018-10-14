// Copyright (c) Javelin Networks. All rights reserved.
// This is a modified version of CorProfiler by .NET Foundation (with the same license):
// Copyright (c) .NET Foundation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once


#ifndef MyDebugPrintA
#ifdef _DEBUG
#define MyDebugPrintA(x) OutputDebugStringA((x))
#define MyDebugPrintW(x) OutputDebugStringW((x))
#else
#define MyDebugPrintA(x)
#define MyDebugPrintW(x)
#endif
#endif

#include "unknwn.h"
#include <atomic>

// {cf0d821e-299b-5307-a3d8-b283c03916db}
const GUID CLSID_InvisiShellProfilerInvisiShell = { 0xcf0d821e, 0x299b, 0x5307, { 0xa3, 0xd8, 0xb2, 0x83, 0xc0, 0x39, 0x16, 0xdb } };


class ClassFactory : public IClassFactory
{
private:
    std::atomic<int> refCount;
public:
    ClassFactory();
    virtual ~ClassFactory();
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) override;
    ULONG   STDMETHODCALLTYPE AddRef(void) override;
    ULONG   STDMETHODCALLTYPE Release(void) override;
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override;
};