#include <iostream>
#include <string>

#include "Driver.h"
#include <ntstatus.h>


typedef NTSTATUS(NTAPI* FuncTy_NtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
    );

#define NT_PROXY_BODY(name, ...)\
    static FuncTy_##name lpfn##name = NULL;\
    if (lpfn##name == NULL) {\
        lpfn##name = (FuncTy_##name)GetProcAddress(\
            LoadLibraryW(L"ntdll.dll"), #name\
        );\
    }\
    return lpfn##name(\
        __VA_ARGS__\
    )

NTSTATUS My_NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
) {
    NT_PROXY_BODY(
        NtMapViewOfSection,
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        CommitSize,
        SectionOffset,
        ViewSize,
        InheritDisposition,
        AllocationType,
        Win32Protect
    );
}


// copy-pasted https://stackoverflow.com/questions/29242/off-the-shelf-c-hex-dump-code
void hexdump(void* ptr, int buflen) {
    unsigned char* buf = (unsigned char*)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
};


int main()
{
    std::wcout << L"vrdrv clt 1.0 (c) immortalp0ny @ ESC-VR" << std::endl;

    HANDLE hDevice = CreateFileW(L"\\??\\vrdev",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::wcout << L"[~] bad device handle. Is it available ? err=" << GetLastError() << std::endl;
        return -1;
    }

    DeviceRequestPing  ping;
    DevicePingResponse pong = { 0 };

    wchar_t overflowMessage[16] = L"AAAAAAAAAAAAAAA";

    memcpy(ping.message, overflowMessage, sizeof(overflowMessage));

    //wcscpy_s(ping.message, VR_PING);

    DWORD bytes = NULL;

    BOOL status = DeviceIoControl(
        hDevice,
        IOCTL_CODE_VR_PING,
        &ping,
        sizeof(DeviceRequestPing),
        nullptr,
        0,
        &bytes,
        NULL
    );
    if (!status) {
        std::wcout << L"[~] DeviceIoControl() failed. err=" << GetLastError() << std::endl;
        return -2;
    }

    std::wcout << L"[+] vrdrv response: " << pong.message << std::endl;

    DeviceInitRequest         initreq = { 0 };
    DeviceInitRequestResponse initresp = { 0 };

    initreq.szSectionIn = 0x1000;
    initreq.szSectionOut = 0x1000;

    DeviceIoControl(
        hDevice,
        IOCTL_CODE_VR_INIT,
        &initreq,
        sizeof(DeviceInitRequest),
        &initresp,
        sizeof(DeviceInitRequestResponse),
        &bytes,
        NULL
    );

    std::wcout << L"[+] vrdrv in=" << std::hex << initresp.hSectionIn << L" vrdrv out=" << std::hex << initresp.hSectionOut << std::endl;

    PVOID  lpMappedSectionIn = NULL;
    SIZE_T szMappedSectionIn = NULL;

    NTSTATUS viewStatus = My_NtMapViewOfSection(
        initresp.hSectionIn,
        GetCurrentProcess(),
        &lpMappedSectionIn,
        NULL,
        NULL,
        NULL,
        &szMappedSectionIn,
        2, // ViewUnmap 
        NULL,
        PAGE_READWRITE
    );
    if (viewStatus < 0) {
        std::wcout << L"[~] NtMapViewOfSection() failed. err=" << GetLastError() << " status=" << std::hex << viewStatus << std::endl;
        return -3;
    }

    std::wcout << "[+] lpMappedSectionIn: " << lpMappedSectionIn << std::endl;

    PVOID  lpMappedSectionOut = NULL;
    SIZE_T szMappedSectionOut = NULL;

    std::wcout << "[+] lpMappedSectionOut: " << lpMappedSectionOut << std::endl;

    viewStatus = My_NtMapViewOfSection(
        initresp.hSectionOut,
        GetCurrentProcess(),
        &lpMappedSectionOut,
        NULL,
        NULL,
        NULL,
        &szMappedSectionOut,
        2, // ViewUnmap 
        NULL,
        PAGE_READWRITE
    );
    if (viewStatus < 0) {
        std::wcout << L"[~] NtMapViewOfSection() failed. err=" << GetLastError() << " status=" << std::hex << viewStatus << std::endl;
        return -3;
    }

    DeviceCacheEntries* lpEntries = (DeviceCacheEntries*)(lpMappedSectionIn);
    lpEntries->count = 1;

    DeviceCacheSetData* csde = &lpEntries->entries[0];

    csde->dataId = MAXDWORD32;
    csde->dataTypeId = ENTRY_GLOBAL_INT;
    csde->data.u32 = 0xDEADBEEF;

    csde = &lpEntries->entries[1];

    uint32_t arbSize = 256;
    uint8_t  arbData[256];

    std::wcout << "[+] dataId: " << dataId << std::endl;
    std::wcout << "[+] arbData: " << arbData << std::endl;
    std::wcout << "[+] csde: " << csde << std::endl;

    memset(arbData, 0x41, arbSize);


    csde->dataId = MAXDWORD32;
    csde->dataTypeId = ENTRY_GLOBAL_DATA;
    csde->data.arb.ptr = &arbData;
    csde->data.arb.sz = arbSize;

    DeviceIoControl(
        hDevice,
        IOCTL_CODE_VR_SET,
        NULL,
        NULL,
        NULL,
        NULL,
        &bytes,
        NULL
    );

    DWORD32 indices[256];
    memcpy(indices, lpMappedSectionOut, lpEntries->count * sizeof(DWORD32));

    for (int i = 0; i < lpEntries->count; i++) {
        DWORD32 dataId = indices[i];

        std::wcout << "[+] vrdrv (" << i << ") = 0x" << std::hex << dataId << std::endl;

        Entry e;

        status = DeviceIoControl(
            hDevice,
            IOCTL_CODE_VR_GET,
            &i,
            sizeof(i),
            &e,
            sizeof(Entry),
            &bytes,
            NULL
        );
        if (!status) {
            std::wcout << L"[~] DeviceIoControl(IOCTL_CODE_VR_GET) Failed. err=" << GetLastError() << std::endl;
            continue;
        }

        PVOID data_ptr = NULL;
        if (e.bActive == FALSE) {
            data_ptr = HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY, e.size + sizeof(Entry));
            DeviceIoControl(
                hDevice,
                IOCTL_CODE_VR_GET,
                &i,
                sizeof(i),
                data_ptr,
                sizeof(Entry) + e.size,
                &bytes,
                NULL
            );
            if (GetLastError() != ERROR_SUCCESS) {
                std::wcout << L"[~] DeviceIoControl(IOCTL_CODE_VR_GET) heap_ptr=" << std::hex << (PVOID)(data_ptr) << " data size=" << e.size << " err=" << GetLastError() << std::endl;
                if (data_ptr)
                    HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, data_ptr);
                return -3;
            }
            e = *(Entry*)(data_ptr);
        }

        std::wcout << "[+]      -> wType: " << e.wType << std::endl;
        switch (e.wType) {
        case ENTRY_GLOBAL_DATA:
        {
            std::wcout << "[+]      -> Value: sz=" << e.size << std::endl;
            if (data_ptr)
                hexdump((Entry*)(data_ptr)+1, e.size);

            break;
        }
        case ENTRY_GLOBAL_INT: {
            std::wcout << "[+]      -> Value: u1=" << std::hex << e.data.u32.u1 << " u2 = " << e.data.u32.u2 << std::endl;
            break;
        }
        }


        if (data_ptr)
            HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, data_ptr);
    }


    status = DeviceIoControl(
        hDevice,
        IOCTL_CODE_VR_INFO,
        NULL,
        NULL,
        NULL,
        NULL,
        &bytes,
        NULL
    );

    InfoData* info = *(InfoData**)(lpMappedSectionOut);
    std::wcout << "[+]      -> info: count=" << std::hex << info->count << std::endl;
    std::wcout << "[+]      -> info: countOfGlobalData=" << std::hex << info->countOfGlobalData << std::endl;
    std::wcout << "[+]      -> info: countOfInt=" << std::hex << info->countOfInt << std::endl;
    std::wcout << "[+]      -> info: countOfProcData=" << std::hex << info->countOfProcData << std::endl;

    CloseHandle(hDevice);
}

