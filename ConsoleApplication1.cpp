// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include "ntos.h"
#include "ntstatus.h"

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL2(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_BUFFERED , FILE_ANY_ACCESS)
#define IOCTL3(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL4(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_OUT_DIRECT , FILE_ANY_ACCESS)


#define KMDF_NEITHER                                             IOCTL(0x900)
#define KMFD_BUFFERED                                            IOCTL2(0x901)
#define KMFD_IN_DIRECT                                           IOCTL3(0x902)
#define KMFD_OUT_DIRECT                                          IOCTL4(0x903)

//#pragma comment(lib, "ntdll.lib")

int main()
{

    printf("[+] IOCTL NEITHER %x\n", KMDF_NEITHER);
    printf("[+] IOCTL BUFFERED %x\n", KMFD_BUFFERED);
    printf("[+] IOCTL IN_DIRECT %x\n", KMFD_IN_DIRECT);
    printf("[+] IOCTL OUT_DIRECT %x\n", KMFD_OUT_DIRECT);
    
    LPCSTR driverName = (LPCSTR)"\\\\.\\PepitoDriver";

    HANDLE hDriver = CreateFileA(driverName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("No pude obtener el handle al driver.\nError code:%d\n", GetLastError());
        exit(1);
    }
    else {
        printf("[+] HANDLE %p\n", hDriver);
    }

    printf("\nPRESS 1 to METHOD_NEITHER,2 to METHOD_BUFFERED, 3 to METHOD_IN_DIRECT, 4 to METHOD_OUT_DIRECT\n");
    int entrada = getchar();

    LPVOID input_buffer = NULL;
    LPVOID input_buffer2 = NULL;
    LPVOID output_buffer = NULL;

    input_buffer = VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    input_buffer2 = VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    output_buffer = VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    printf("[+] Input_buffer address %p\n", input_buffer);
    printf("[+] Input_buffer 2 address %p\n", input_buffer2);
    printf("[+] Output_buffer address %p\n", output_buffer);

    if (input_buffer != 0) {
        memset(input_buffer, 0, sizeof(input_buffer));
    }

    if (input_buffer2 != 0) {
        memset(input_buffer2, 0, sizeof(input_buffer2));
    }

    if (output_buffer != 0) {
        memset(output_buffer, 0, sizeof(output_buffer));
    }

    RtlMoveMemory(input_buffer, "CAFECAFE", 9);
    RtlMoveMemory(input_buffer2, "MUZZARELLA", 11);

    ULONG bytesReturned = 0;

    if (entrada == 0x31) {
        printf("\n[+] METHOD_NEITHER\n");
        DeviceIoControl(hDriver, (DWORD)KMDF_NEITHER, input_buffer, 512, output_buffer, 512, &bytesReturned, NULL);
        printf("[+] UserInputBuffer=  %p\n", *(PUINT64)output_buffer);
    }
    if (entrada == 0x32) {
        printf("\n[+] METHOD_BUFFERED\n");
        DeviceIoControl(hDriver, (DWORD)KMFD_BUFFERED, input_buffer, 512, output_buffer, 512, &bytesReturned, NULL);
        printf("[+] SystemBuffer=  %p\n", *(PUINT64)output_buffer);
    }
    if (entrada == 0x33) {
        printf("\n[+] METHOD_IN_DIRECT\n");
        DeviceIoControl(hDriver, (DWORD)KMFD_IN_DIRECT, input_buffer, 512, input_buffer2, 512, &bytesReturned, NULL);
        printf("[+] MDLInBuffer=  %p\n", *(PUINT64)input_buffer2);
        printf("[+] MDLInBufferAddr=  %p\n", &input_buffer2);
        printf("[+] SystemBuffer=  %p\n", *(PUINT64)input_buffer);
        printf("[+] SystemBufferAddr=  %p\n", &input_buffer);
    }
    if (entrada == 0x34) {
        printf("\n[+] METHOD_OUT_DIRECT\n");
        DeviceIoControl(hDriver, (DWORD)KMFD_OUT_DIRECT, input_buffer, 512, output_buffer, 512, &bytesReturned, NULL);
        printf("[+] SystemBuffer=  %p\n", *(PUINT64)input_buffer);
        printf("[+] SystemBufferAddr=  %p\n", &input_buffer);
        printf("[+] MDLOutBuffer=  %p\n", *(PUINT64)output_buffer);
        printf("[+] MDLOutBufferAddr=  %p\n", &output_buffer);
        printf("[+] IOBuffer=  %s\n", output_buffer);
    }


    BOOL ret1;
    ret1 = CloseHandle(hDriver);
}
