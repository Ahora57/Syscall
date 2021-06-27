#pragma once
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include "raii.hpp"
//#include "NtApi.hpp"
#include "HashWork.hpp"

namespace syscallWork {

    raii::Hmodule hDll = LoadLibraryExA(
        "C:\\Windows\\System32\\ntdll.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);


    EXTERN_C unsigned char SetCallNumber(unsigned char call_number);

   



    BOOL IsSyscall(LPCVOID pFunction) {
        LPCBYTE pBytePtr = (LPCBYTE)pFunction;

        if (pBytePtr[0] == 0x4C &&
            pBytePtr[1] == 0x8B &&
            pBytePtr[2] == 0xD1 &&
            pBytePtr[3] == 0xB8) return TRUE;

        return FALSE;
    }

    DWORD printSyscall() {



        if (!hDll.get() || hDll.get() == INVALID_HANDLE_VALUE)
            return GetLastError();

        auto pModuleBase = reinterpret_cast<PBYTE>(hDll.get());
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBase);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return ERROR_INVALID_EXE_SIGNATURE;

        auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
            pModuleBase + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
            return ERROR_INVALID_EXE_SIGNATURE;

        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            pModuleBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (pExportDir->NumberOfFunctions == 0)
            ERROR_INVALID_DLL;

        auto pdwAddressOfFunc =
            reinterpret_cast<PDWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfFunctions));
        auto pdwAddressOfName =
            reinterpret_cast<PDWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfNames));
        auto pwAddressOfOrd =
            reinterpret_cast<PWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfNameOrdinals));

        // Print column headers
        std::cout << std::left
            << std::setw(10) << "ordinal"
            << std::setw(10) << "number"
            << "name\t\t\t" << std::setw(10) << "hash" <<
            std::endl;

        for (uint64_t i = 0; i < pExportDir->NumberOfFunctions; i++) {
            // Get the pointer to the function
            auto pCurrentFunction = (PVOID)(
                pModuleBase + pdwAddressOfFunc[pwAddressOfOrd[i]]);

            // Identify "Nt" family functions
            if (IsSyscall(pCurrentFunction)) {
                // Calculate its RVA
                auto szFunctionName = (char*)(pModuleBase + pdwAddressOfName[i]);

                // Retrieve the syscall code number from the raw bytes
                auto pFunctionCode = *(uintptr_t*)pCurrentFunction;
                auto syscallNum = (pFunctionCode >> 8 * 4) & 0xfff;

                // Print the function's information
                std::cout << std::left
                    << std::setw(10) << std::dec << i

                    << std::setw(10) << std::hex << syscallNum
                    << std::setw(10) << szFunctionName <<
                    "  " << picosha2::hash256_hex_string((std::string)szFunctionName) <<
                    std::endl;
            }
        }

        return ERROR_SUCCESS;
    }
    
    
     DWORD GetSyscallByName(std::string hashValue) {

        if (!hDll.get() || hDll.get() == INVALID_HANDLE_VALUE)
            return GetLastError();

        auto pModuleBase = reinterpret_cast<PBYTE>(hDll.get());
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBase);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return ERROR_INVALID_EXE_SIGNATURE;

        auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
            pModuleBase + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
            return ERROR_INVALID_EXE_SIGNATURE;

        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            pModuleBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (pExportDir->NumberOfFunctions == 0)
            ERROR_INVALID_DLL;

        auto pdwAddressOfFunc =
            reinterpret_cast<PDWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfFunctions));
        auto pdwAddressOfName =
            reinterpret_cast<PDWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfNames));
        auto pwAddressOfOrd =
            reinterpret_cast<PWORD>((reinterpret_cast<LPBYTE>(pModuleBase) + pExportDir->AddressOfNameOrdinals));


        for (uint64_t i = 0; i < pExportDir->NumberOfFunctions; i++) {
            // Get the pointer to the function
            auto pCurrentFunction = (PVOID)(
                pModuleBase + pdwAddressOfFunc[pwAddressOfOrd[i]]);

            // Identify "Nt" family functions
            if (IsSyscall(pCurrentFunction)) {

                auto hashFuncthionName = picosha2::hash256_hex_string((std::string)(char*)((pModuleBase + pdwAddressOfName[i]))); // char* for  correct convert

                // Retrieve the syscall code number from the raw bytes
                auto pFunctionCode = *(uintptr_t*)pCurrentFunction;
                auto syscallNum = (pFunctionCode >> 8 * 4) & 0xfff;
                if (hashFuncthionName == hashValue) {
                    return syscallNum;
                }

            }
        }

        return ERROR_SUCCESS;

    }
    
    bool AutoGetSetSyscallumber(std::string hashValue)
    {
        DWORD syscall = NULL;
        syscall = GetSyscallByName(hashValue);
         
        if (syscall)
                    {return SetCallNumber(syscall);  }
         else   {  return false;  }
    }
    
    
    
}
