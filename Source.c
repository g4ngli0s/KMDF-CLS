#include <ntddk.h>
#include <wdf.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL2(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_BUFFERED , FILE_ANY_ACCESS)
#define IOCTL3(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL4(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function,  METHOD_OUT_DIRECT , FILE_ANY_ACCESS)

#define KMDF_NEITHER        IOCTL(0x900)
#define KMFD_BUFFERED       IOCTL2(0x901)
#define KMFD_IN_DIRECT      IOCTL3(0x902)
#define KMFD_OUT_DIRECT     IOCTL4(0x903)

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    ULONG IoControlCode = 0;
    PIO_STACK_LOCATION IrpSp = NULL;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    SIZE_T SizeIn, SizeOut = 0;
    PVOID UserInputBuffer = NULL;
    PVOID UserOutputBuffer = NULL;
    PVOID SystemBuffer = NULL;


    UCHAR KernelBuffer[512] = { 0 };

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp)
    {
        IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

        switch (IoControlCode)
        {
        case KMDF_NEITHER:
            __try
            {
                DbgPrint("\n****** KMDF_METHOD_NEITHER ******\n");
                PAGED_CODE();

                UserInputBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
                UserOutputBuffer = Irp->UserBuffer;
                PVOID PUserInputBuffer = &UserInputBuffer;

                SizeIn = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
                SizeOut = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

                ProbeForRead(UserInputBuffer, SizeIn, (ULONG)__alignof(UCHAR));
                ProbeForWrite(UserOutputBuffer, SizeOut, (ULONG)__alignof(UCHAR));

                RtlCopyMemory((PVOID)KernelBuffer, UserInputBuffer, SizeIn);

                DbgPrint("[-] Enviado %s\n", KernelBuffer);

                RtlCopyMemory((PVOID)UserOutputBuffer, PUserInputBuffer, 16);

            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();
                DbgPrint("[-] Exception Code: 0x%X\n", Status);
            }
            break;

        case KMFD_BUFFERED:
            DbgPrint("\n****** KMFD_METHOD_BUFFERED ******\n");

            SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
            PVOID PSystemBuffer = &SystemBuffer;

            DbgPrint("[-] SystemBuffer = %p\n", SystemBuffer);

            SizeIn = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            SizeOut = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            RtlCopyMemory((PVOID)KernelBuffer, SystemBuffer, SizeIn);

            RtlFillMemory(SystemBuffer, 512, 0);

            DbgPrint("[-] Enviado %s\n", KernelBuffer);

            RtlCopyMemory((PVOID)SystemBuffer, PSystemBuffer, 16);

            break;
        case KMFD_IN_DIRECT:
            DbgPrint("\n****** KMFD_METHOD_IN_DIRECT ******\n");

            //Segundo INPUT similar al BUFFERED
            SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
            DbgPrint("[-] SystemBuffer = %p\n", SystemBuffer);
            //SizeIn = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            
            //Primer INPUT
            //SizeOut = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            PVOID pReadDataBuffer = NULL;
            if (Irp->MdlAddress)
            {
                pReadDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                DbgPrint("[-] MDLInputBuffer = %p\n", pReadDataBuffer);
            }
            else
            {
                DbgPrint("[-] Error Initializing MDLInputBuffer\n");
                break;
            }

            //SEND & RECEIVE
            //RtlCopyMemory((PVOID)KernelBuffer, SystemBuffer, SizeIn);

            DbgPrint("[-] EnviadoSystemBuffer %s\n", SystemBuffer);
            DbgPrint("[-] EnviadoIOBuffer %s\n", pReadDataBuffer);

            //RtlCopyMemory((PVOID)SystemOutputBuffer, pSystemOutputBuffer, 16);

            break;
        case KMFD_OUT_DIRECT:
            DbgPrint("\n****** KMFD_METHOD_OUT_DIRECT ******\n");

            //INPUT similar al BUFFERED
            SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
            DbgPrint("[-] SystemBuffer = %p\n", SystemBuffer);

            //OUTPUT por el MDL
            PVOID pWriteDataBuffer = NULL;
            if (Irp->MdlAddress)
            {
                pWriteDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                DbgPrint("[-] MDLInputBuffer = %p\n", pWriteDataBuffer);
            }
            else
            {
                DbgPrint("[-] Error Initializing MDLOutputBuffer\n");
                break;
            }

            DbgPrint("[-] EnviadoSystemBuffer %s\n", SystemBuffer);

            RtlCopyMemory((PVOID)pWriteDataBuffer, "SALIDA OUTPUT BUFFER", 21);

            break;
        }

    }
    //
    // Update the IoStatus information
    //
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 16;

    //
    // Complete the request
    //
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}


NTSTATUS
IrpCreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    DbgPrint("[-] Current IRP %p\n", Irp);

    struct _IO_STACK_LOCATION* pCurrentSL = Irp->Tail.Overlay.CurrentStackLocation;
    //DbgPrint("[-] CurrentStackLocation %p\n", pCurrentSL);

    //DbgPrint("[-] MajorFunction Code %x\n", pCurrentSL->MajorFunction);

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    if (pCurrentSL->MajorFunction == 0) {
        DbgPrint("[-] Pepito Driver CreateFile\n");
    }
    if (pCurrentSL->MajorFunction == 2) {
        DbgPrint("[-] Pepito Driver CloseFile\n\n");
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

void DriverUnload(
    PDRIVER_OBJECT pDriverObject)
{

    UNICODE_STRING DosDeviceName = { 0 };

    PAGED_CODE();

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\PepitoDriver");

    //
    // Delete the symbolic link
    //
    IoDeleteSymbolicLink(&DosDeviceName);
    //
    // Delete the device
    //
    IoDeleteDevice(pDriverObject->DeviceObject);

    DbgPrint("[-] Pepito Driver Unloaded\n\n");
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    //WORKING WITH DRIVER OBJECT
    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("[-] Driver Entry Called\n");

    //CREATING A DEVICE OBJECT---------------------
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING DeviceName, DosDeviceName = { 0 };

    RtlInitUnicodeString(&DeviceName, L"\\Device\\PepitoDriver");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\PepitoDriver");

    Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[-] Error Initializing Pepito Driver\n");
    }

    else {
        DbgPrint("[-] Pepito Driver initialized\n");
    }


    DriverObject->DeviceObject = DeviceObject;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    return STATUS_SUCCESS;
}
