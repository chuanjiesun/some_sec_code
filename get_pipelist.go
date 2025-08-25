package main 

import (
    "fmt"
    "golang.org/x/sys/windows"
)


// use FindFirstFile, FindNextFile and FindClose Windows API to implement directory reading. instead of using NtQueryDirectoryFile
func Pipelist() {
    pipedir := "\\\\.\\pipe\\*"
    // pipedir := "//./pipe/"
    pipe_ptr, err := windows.UTF16PtrFromString(pipedir)
    if err != nil {
        fmt.Printf("UTF16PtrFromString err:%#v\n", err)
        return 
    }
    var data windows.Win32finddata
    var handle windows.Handle
    for handle, err = windows.FindFirstFile(pipe_ptr, &data); err == nil; err = windows.FindNextFile(handle, &data) {
        filename := windows.UTF16ToString(data.FileName[:])
        if filename != "." && filename != ".." {
            fmt.Printf("pipe filename:%s\n", filename)
        }
    }
    if err != windows.ERROR_NO_MORE_FILES {
        fmt.Printf("FindNextFile err:%#v\n", err)
        return 
    }
    defer windows.CloseHandle(handle)
}

func main(){
    Pipelist()
}

// type Win32finddata struct {
//     FileAttributes    uint32
//     CreationTime      Filetime
//     LastAccessTime    Filetime
//     LastWriteTime     Filetime
//     FileSizeHigh      uint32
//     FileSizeLow       uint32
//     Reserved0         uint32
//     Reserved1         uint32
//     FileName          [MAX_PATH - 1]uint16
//     AlternateFileName [13]uint16
// }


// pipe filename:InitShutdown
// pipe filename:lsass
// pipe filename:ntsvcs
// pipe filename:scerpc
// pipe filename:Winsock2\CatalogChangeListener-3b0-0
// pipe filename:epmapper
