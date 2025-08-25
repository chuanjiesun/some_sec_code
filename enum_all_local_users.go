package main 

import (
    "fmt"
    "syscall"
    "unsafe"
    "strings"
    "golang.org/x/sys/windows"
)
var (
    modnetapi32             = syscall.NewLazyDLL("netapi32.dll")
    procNetApiBufferFree    = modnetapi32.NewProc("NetApiBufferFree")
    procNetUserEnum            = modnetapi32.NewProc("NetUserEnum")
)
const (
    MAX_PREFERRED_LENGTH  = 0xFFFFFFFF
    USER_FILTER_NORMAL_ACCOUNT = 0x0002
)

// reference https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum
// NET_API_STATUS NET_API_FUNCTION NetUserEnum(
//     [in]      LPCWSTR servername, // A pointer to a constant string that specifies the DNS or NetBIOS name of the remote server on which the function is to execute. If this parameter is NULL, the local computer is used.
//     [in]      DWORD   level,
//     [in]      DWORD   filter,
//     [out]     LPBYTE  *bufptr, //The format of this data depends on the value of the level parameter.
//     [in]      DWORD   prefmaxlen,
//     [out]     LPDWORD entriesread,
//     [out]     LPDWORD totalentries,
//     [in, out] PDWORD  resume_handle
//   );
// typedef struct _USER_INFO_0 {
//     LPWSTR usri0_name;
//   } USER_INFO_0, *PUSER_INFO_0, *LPUSER_INFO_0;
// typedef struct _USER_INFO_10 {
//     LPWSTR usri10_name;
//     LPWSTR usri10_comment;
//     LPWSTR usri10_usr_comment;
//     LPWSTR usri10_full_name;
//   } USER_INFO_10, *PUSER_INFO_10, *LPUSER_INFO_10;

// definition reference src/syscall/security_windows.go type UserInfo10 struct
// usage reference src/os/user/lookup_windows.go  syscall.NetUserGetInfo()
// usage reference src/os/user/lookup_windows.go entries := (*[1024]windows.LocalGroupUserInfo0)(unsafe.Pointer(p0))[:entriesRead:entriesRead]
type UserInfo0 struct {
    UserName0     *uint16
}
type UserInfo1 struct {
    UserName1         *uint16
    Passwd1         *uint16
    PasswdAge1         uint32 // The number of seconds that have elapsed since the usri1_password member was last changed. 
    UserPriv1        uint32 
    UserHomedir1     *uint16 
    UserComment1    *uint16
    UserFlag1         uint32 
    UserScriptPath1    *uint16
}
type UserInfo10 struct { // src/syscall/security_windows.go
    Name       *uint16
    Comment    *uint16
    UsrComment *uint16
    FullName   *uint16
}

type PRIV uint32
const (
    USER_PRIV_GUEST PRIV = iota
    USER_PRIV_USER
    USER_PRIV_ADMIN
)
var priv = [...]string{
    USER_PRIV_GUEST : "USER_PRIV_GUEST",
    USER_PRIV_USER  : "USER_PRIV_USER",
    USER_PRIV_ADMIN : "USER_PRIV_ADMIN",
}

// 标志位在二进制中其实也就为1或者0， 所以将大数字转化为标志位的位置数字，uint32最多也就32位，这样就方便使用位移操作进行计算
const (
    UF_SCRIPT            =    1 // 0x00000001  // 0001
    UF_ACCOUNTDISABLE     =    2 // 0x00000002  // 0010 
    UF_HOMEDIR_REQUIRED    =     3 // 0x00000008  // 0100
    UF_LOCKOUT            =    5 // 0x00000010  // 0001 0000
    UF_PASSWD_NOTREQD    =    6 // 0x00000020  // 0010 0000  
    UF_PASSWD_CANT_CHANGE =    7 // 0x00000040  // 0100 0000
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 8 // 0x00000080  // 1000 0000
    UF_TEMP_DUPLICATE_ACCOUNT     =     9 // 0x00000100  // 0001 0000 0000 
    UF_NORMAL_ACCOUNT            =    10 // 0x00000200  // 0010 0000 0000
    UF_INTERDOMAIN_TRUST_ACCOUNT        = 12 // 0x00000800  // 1000 0000 0000
    UF_WORKSTATION_TRUST_ACCOUNT =    13 // 0x00001000  // 0001 0000 0000 0000
    UF_SERVER_TRUST_ACCOUNT     =    14 // 0x00002000  // 0010 0000 0000 0000
    UF_DONT_EXPIRE_PASSWD        =    17 // 0x00010000  // 0001 0000 0000 0000 0000
    UF_MNS_LOGON_ACCOUNT        =    18 // 0x00020000  // 0010 0000 0000 0000 0000
    UF_SMARTCARD_REQUIRED        =    19 // 0x00040000  // 0100 0000 0000 0000 0000
    UF_TRUSTED_FOR_DELEGATION    =    20 // 0x00080000  // 1000 0000 0000 0000 0000
    UF_NOT_DELEGATED            =    21 // 0x00100000  // 0001 0000 0000 0000 0000 0000
    UF_USE_DES_KEY_ONLY        =    22 // 0x00200000  // 0010 0000 0000 0000 0000 0000
    UF_DONT_REQUIRE_PREAUTH    =    23 // 0x00400000  // 0100 0000 0000 0000 0000 0000
    UF_PASSWORD_EXPIRED        =    24 // 0x00800000  // 1000 0000 0000 0000 0000 0000
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION    =    25 // 0x01000000  // 0001 0000 0000 0000 0000 0000 0000
    UF_NO_AUTH_DATA_REQUIRED    =    26 // 0x02000000  // 0010 0000 0000 0000 0000 0000 0000
    UF_PARTIAL_SECRETS_ACCOUNT    =    27 // 0x04000000  // 0100 0000 0000 0000 0000 0000 0000
    UF_USE_AES_KEYS            =    28 // 0x08000000  // 1000 0000 0000 0000 0000 0000 0000
)

var uf_flags  = [...]string{
    UF_SCRIPT            : "UF_SCRIPT",
    UF_ACCOUNTDISABLE     : "UF_ACCOUNTDISABLE",
    UF_HOMEDIR_REQUIRED    : "UF_HOMEDIR_REQUIRED",
    UF_LOCKOUT            : "UF_LOCKOUT",
    UF_PASSWD_NOTREQD    : "UF_PASSWD_NOTREQD",
    UF_PASSWD_CANT_CHANGE : "UF_PASSWD_CANT_CHANGE",
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED : "UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    UF_TEMP_DUPLICATE_ACCOUNT     : "UF_TEMP_DUPLICATE_ACCOUNT",
    UF_NORMAL_ACCOUNT            : "UF_NORMAL_ACCOUNT",
    UF_INTERDOMAIN_TRUST_ACCOUNT: "UF_INTERDOMAIN_TRUST_ACCOUNT",
    UF_WORKSTATION_TRUST_ACCOUNT: "UF_WORKSTATION_TRUST_ACCOUNT",
    UF_SERVER_TRUST_ACCOUNT     : "UF_SERVER_TRUST_ACCOUNT",
    UF_DONT_EXPIRE_PASSWD        : "UF_DONT_EXPIRE_PASSWD",
    UF_MNS_LOGON_ACCOUNT        : "UF_MNS_LOGON_ACCOUNT",
    UF_SMARTCARD_REQUIRED        : "UF_SMARTCARD_REQUIRED",
    UF_TRUSTED_FOR_DELEGATION    : "UF_TRUSTED_FOR_DELEGATION",
    UF_NOT_DELEGATED            : "UF_NOT_DELEGATED",
    UF_USE_DES_KEY_ONLY        : "UF_USE_DES_KEY_ONLY",
    UF_DONT_REQUIRE_PREAUTH    : "UF_DONT_REQUIRE_PREAUTH",
    UF_PASSWORD_EXPIRED        : "UF_PASSWORD_EXPIRED",
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION    : "UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
    UF_NO_AUTH_DATA_REQUIRED    : "UF_NO_AUTH_DATA_REQUIRED",
    UF_PARTIAL_SECRETS_ACCOUNT    : "UF_PARTIAL_SECRETS_ACCOUNT",
    UF_USE_AES_KEYS            : "UF_USE_AES_KEYS",
}

func Num2Flags(input uint32) string {
    fmt.Printf("%d ==> 0x%x\n", input, input)
    var flags_list []string 
    for i:=1; i<=32; i++ {
        if input & 0x01 == 0x01 {
            flags_list = append(flags_list, uf_flags[i])
        }
        input = input >> 1
    }
    
    flags_string := strings.Join(flags_list, "|")
    fmt.Println(flags_string)
    return flags_string
}

func NetUserEnum(servername *uint16, level uint32, filter uint32, bufptr **byte, prefmaxlen uint32, entriesread *uint32, totalentries *uint32, resume_handle *uint32) (neterr error) {
    r0, _, _ := syscall.Syscall9(procNetUserEnum.Addr(), 8, uintptr(unsafe.Pointer(servername)), uintptr(level), uintptr(filter), uintptr(unsafe.Pointer(bufptr)), uintptr(prefmaxlen), uintptr(unsafe.Pointer(entriesread)), uintptr(unsafe.Pointer(totalentries)), uintptr(unsafe.Pointer(resume_handle)), 0)
    if r0 != 0 {
        neterr = syscall.Errno(r0)
    }
    return
}

func GetAllLocalUserNames() {
    level := 0
    // USER_FILTER_NORMAL_ACCOUNT = 0x0002
    var dataPtr *byte //The format of this data depends on the value of the level parameter.
    // MAX_PREFERRED_LENGTH  = 0xFFFFFFFF
    var entriesRead, entriesTotal uint32 
    var resumeHandle uint32

    // 只获取用户名
    NetUserEnum(nil, uint32(level), uint32(USER_FILTER_NORMAL_ACCOUNT), &dataPtr, uint32(USER_FILTER_NORMAL_ACCOUNT), &entriesRead, &entriesTotal, &resumeHandle)
    fmt.Printf("entriesRead:%#v\tentriesTotal:%#v\tresumeHandle:%#v\n", entriesRead, entriesTotal, resumeHandle)
    ui0s := (*[1024]UserInfo0)(unsafe.Pointer(dataPtr))[:entriesRead:entriesRead] //因为不支持使用格式*[entriesRead]UserInfo0)(unsafe.Pointer(dataPtr))，所以使用这种格式[:entriesRead:entriesRead]
    for i, ui0 := range ui0s {
        name := windows.UTF16PtrToString(ui0.UserName0)
        fmt.Printf("%d\tname:%s\n", i, name)
    }
    syscall.NetApiBufferFree((*byte)(unsafe.Pointer(dataPtr)))

}

// typedef struct _USER_INFO_1 {
//     LPWSTR usri1_name;
//     LPWSTR usri1_password;
//     DWORD  usri1_password_age;
//     DWORD  usri1_priv;
//     LPWSTR usri1_home_dir;
//     LPWSTR usri1_comment;
//     DWORD  usri1_flags;
//     LPWSTR usri1_script_path;
//   } USER_INFO_1, *PUSER_INFO_1, *LPUSER_INFO_1;
func GetAllLocalUserInfos() {
    fmt.Printf("\nUserInfo1 ...\n")
    level := 1
    // USER_FILTER_NORMAL_ACCOUNT = 0x0002
    var dataPtr *byte //The format of this data depends on the value of the level parameter.
    // MAX_PREFERRED_LENGTH  = 0xFFFFFFFF
    var entriesRead, entriesTotal uint32 
    var resumeHandle uint32

    // 只获取用户名
    NetUserEnum(nil, uint32(level), uint32(USER_FILTER_NORMAL_ACCOUNT), &dataPtr, uint32(USER_FILTER_NORMAL_ACCOUNT), &entriesRead, &entriesTotal, &resumeHandle)
    fmt.Printf("entriesRead:%#v\tentriesTotal:%#v\tresumeHandle:%#v\n", entriesRead, entriesTotal, resumeHandle)
    ui1s := (*[1024]UserInfo1)(unsafe.Pointer(dataPtr))[:entriesRead:entriesRead] //因为不支持使用格式*[entriesRead]UserInfo0)(unsafe.Pointer(dataPtr))，所以使用这种格式[:entriesRead:entriesRead]
    for i, ui1 := range ui1s {
        name := windows.UTF16PtrToString(ui1.UserName1)
        passwd := windows.UTF16PtrToString(ui1.Passwd1)
        homedir := windows.UTF16PtrToString(ui1.UserHomedir1)
        usercomment := windows.UTF16PtrToString(ui1.UserComment1)
        scriptpath := windows.UTF16PtrToString(ui1.UserScriptPath1)
        // fmt.Printf("%d\tname:%s\tpasswd:%s\tpasswdage:%d\tpriv:%d\thomedir:%s\tusercomment:%s\tuserflag:%d\tscriptpath:%s\n", i, name, passwd, ui1.PasswdAge1, ui1.UserPriv1, homedir, usercomment, ui1.UserFlag1, scriptpath)
        fmt.Printf("%d\tname:%s\tpasswd:%s\tpasswdage:%d\tpriv:%s\thomedir:%s\tusercomment:%s\tuserflag:%s\tscriptpath:%s\n", i, name, passwd, ui1.PasswdAge1, priv[ui1.UserPriv1], homedir, usercomment, Num2Flags(ui1.UserFlag1), scriptpath)
    }
    syscall.NetApiBufferFree((*byte)(unsafe.Pointer(dataPtr)))
}
func main() {
    GetAllLocalUserNames() // user_info_0
    GetAllLocalUserInfos() // user_info_1
}
