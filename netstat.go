package main

import (
    "fmt"
    "syscall"
    "unsafe"

    "golang.org/x/sys/windows"
)

var (
    modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
    procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)
// https://github.com/reactos/reactos/blob/90432c1a4c2051a0a00a7780d04fb5555eca20e2/sdk/include/psdk/winsock.h#L369
const (
    AF_INET        = 2
    TCP_TABLE_BASIC_ALL = 5
)
// https://learn.microsoft.com/zh-cn/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
type MIB_TCPROW struct {
    State          uint32
    LocalAddr      uint32
    LocalPort      uint32
    RemoteAddr     uint32
    RemotePort     uint32
    OwningPid      uint32
}
// https://learn.microsoft.com/zh-cn/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid
type MIB_TCPTABLE struct {
    NumEntries uint32
    Table      [1]MIB_TCPROW
}
// https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_lh
var TCPRowState = map[uint32]string {
    1    : "TCP_STATE_CLOSED",
    2    : "TCP_STATE_LISTEN",
    3    : "TCP_STATE_SYN_SENT",
    4    : "TCP_STATE_SYN_RCVD",
    5    : "TCP_STATE_ESTAB",
    6    : "TCP_STATE_FIN_WAIT1",
    7    : "TCP_STATE_FIN_WAIT2",
    8    : "TCP_STATE_CLOSE_WAIT",
    9    : "TCP_STATE_CLOSING",
    10    : "TCP_STATE_LAST_ACK",
    11    : "TCP_STATE_TIME_WAIT",
    12    : "TCP_STATE_DELETE_TCB",
}
    
func main() {
    var size uint32
    var table *MIB_TCPTABLE

    // 第一次调用 GetExtendedTcpTable 获取所需的缓冲区大小
    err := getExtendedTcpTable(0, &size, false, AF_INET, TCP_TABLE_BASIC_ALL)
    if err != nil && err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER && err.Error() != "The operation completed successfully."{
        fmt.Println("Failed to get buffer size:", err)
        return
    }
    fmt.Printf("size:%d\n", size)

    // 分配足够的内存来存储 TCP 表
    tablePtr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
    if err != nil {
        fmt.Println("Failed to allocate memory:", err)
        return
    }
    defer windows.VirtualFree(tablePtr, 0, windows.MEM_RELEASE)

    table = (*MIB_TCPTABLE)(unsafe.Pointer(tablePtr))

    // 第二次调用 GetExtendedTcpTable 获取实际的 TCP 表
    err = getExtendedTcpTable(uintptr(unsafe.Pointer(table)), &size, false, AF_INET, TCP_TABLE_BASIC_ALL)
    if err != nil {
        fmt.Println("Failed to get TCP table:", err)
        return
    }

    // 解析并打印 TCP 表
    fmt.Printf("LocalAddr\tRemoteAddr\tState\t\tPID\n")
    for i := 0; i < int(table.NumEntries); i++ {
        row := (*MIB_TCPROW)(unsafe.Pointer(uintptr(unsafe.Pointer(&table.Table[0])) + uintptr(i)*unsafe.Sizeof(table.Table[0])))
        localAddr := fmt.Sprintf("%d.%d.%d.%d", byte(row.LocalAddr), byte(row.LocalAddr>>8), byte(row.LocalAddr>>16), byte(row.LocalAddr>>24))
        remoteAddr := fmt.Sprintf("%d.%d.%d.%d", byte(row.RemoteAddr), byte(row.RemoteAddr>>8), byte(row.RemoteAddr>>16), byte(row.RemoteAddr>>24))
        localPort := row.LocalPort >> 8 | (row.LocalPort & 0xff << 8)
        remotePort := row.RemotePort >> 8 | (row.RemotePort & 0xff << 8)
        fmt.Printf("%s:%d  => %s:%d\t%s\t%d\n", localAddr, localPort, remoteAddr, remotePort, TCPRowState[row.State], row.OwningPid)
    }
}
// IPHLPAPI_DLL_LINKAGE DWORD GetExtendedTcpTable(
//     [out]     PVOID           pTcpTable,
//     [in, out] PDWORD          pdwSize,
//     [in]      BOOL            bOrder,
//     [in]      ULONG           ulAf,
//     [in]      TCP_TABLE_CLASS TableClass,
//     [in]      ULONG           Reserved
//   );
func getExtendedTcpTable(table uintptr, size *uint32, order bool, af, level uint32) error {
    var dwOrder uint32
    if order {
        dwOrder = 1
    }

    r1, _, err := procGetExtendedTcpTable.Call(
        table,
        uintptr(unsafe.Pointer(size)),
        uintptr(dwOrder),
        uintptr(af),
        uintptr(level),
        0,
    )

    if r1 != 0 {
        return err
    }

    return nil
}
/*
LocalAddr       RemoteAddr      State           PID
0.0.0.0:135  => 0.0.0.0:0       TCP_STATE_LISTEN        1504
10.17.23.76:139  => 0.0.0.0:0   TCP_STATE_LISTEN        4
10.36.8.66:139  => 0.0.0.0:0    TCP_STATE_LISTEN        4
192.168.56.1:139  => 0.0.0.0:0  TCP_STATE_LISTEN        4
*/
