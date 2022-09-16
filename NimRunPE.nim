import winim
import ptr_math

var success: BOOL

when defined(args):
    const toLoadfromMem = slurp"C:\\windows\\system32\\cmd.exe"
else:
    const toLoadfromMem = slurp"C:\\windows\\system32\\calc.exe"
# pass this arguments to the PE 
# to use the args of the parent process just pass an empty string
when defined(args):
    const exeArgs = "/c whoami"
else:
    const exeArgs = ""

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

when defined(args):
    proc patchMemory*(targetAddr: pointer, data: openArray[byte]): void =
        var oldProtect: DWORD
        VirtualProtect(targetAddr, cast[SIZE_T](len(data)), PAGE_READWRITE, cast[PDWORD](addr(oldProtect)))
        copyMem(targetAddr, unsafeAddr data[0], len(data))
        VirtualProtect(targetAddr, cast[SIZE_T](len(data)), oldProtect, cast[PDWORD](addr(oldProtect)))
when defined(args):
    proc patchArgFunctionMemory*(funcAddr: pointer, pNewCommandLine: pointer): void =
        when defined x86:
            var shellcode: seq[byte] = @[byte(0xb8)] # movabs rax, new_cmd
        else:
            var shellcode: seq[byte] = @[byte(0x48), byte(0xb8)] # movabs rax, new_cmd
        # add new_cmd addr to shellcode
        for t in cast[array[sizeOf(pointer), byte]](pNewCommandLine):
            shellcode.add t        
        shellcode.add(byte(0xc3)) # ret
        patchMemory(funcAddr, shellcode)

var memloadBytes = toByteSeq(toLoadfromMem)

var shellcodePtr: ptr = memloadBytes[0].addr

proc getNtHdrs*(pe_buffer: ptr BYTE): ptr BYTE =
  if pe_buffer == nil:
    return nil
  var idh: ptr IMAGE_DOS_HEADER = cast[ptr IMAGE_DOS_HEADER](pe_buffer)
  if idh.e_magic != IMAGE_DOS_SIGNATURE:
    return nil
  let kMaxOffset: LONG = 1024
  var pe_offset: LONG = idh.e_lfanew
  if pe_offset > kMaxOffset:
    return nil
  var inh: ptr IMAGE_NT_HEADERS32 = cast[ptr IMAGE_NT_HEADERS32]((
      cast[ptr BYTE](pe_buffer) + pe_offset))
  if inh.Signature != IMAGE_NT_SIGNATURE:
    return nil
  return cast[ptr BYTE](inh)

proc getPeDir*(pe_buffer: PVOID; dir_id: csize_t): ptr IMAGE_DATA_DIRECTORY =
  if dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
    return nil
  var nt_headers: ptr BYTE = getNtHdrs(cast[ptr BYTE](pe_buffer))
  if nt_headers == nil:
    return nil
  var peDir: ptr IMAGE_DATA_DIRECTORY = nil
  var nt_header: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](nt_headers)
  peDir = addr((nt_header.OptionalHeader.DataDirectory[dir_id]))
  if peDir.VirtualAddress == 0:
    return nil
  return peDir

type
  BASE_RELOCATION_ENTRY* {.bycopy.} = object
    Offset* {.bitsize: 12.}: WORD
    Type* {.bitsize: 4.}: WORD


const
  RELOC_32BIT_FIELD* = 3

proc applyReloc*(newBase: ULONGLONG; oldBase: ULONGLONG; modulePtr: PVOID;
                moduleSize: SIZE_T): bool =
  echo "    [!] Applying Reloc "
  var relocDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(modulePtr,
      IMAGE_DIRECTORY_ENTRY_BASERELOC)
  if relocDir == nil:
    return false
  var maxSize: csize_t = csize_t(relocDir.Size)
  var relocAddr: csize_t = csize_t(relocDir.VirtualAddress)
  var reloc: ptr IMAGE_BASE_RELOCATION = nil
  var parsedSize: csize_t = 0
  while parsedSize < maxSize:
    reloc = cast[ptr IMAGE_BASE_RELOCATION]((
        size_t(relocAddr) + size_t(parsedSize) + cast[size_t](modulePtr)))
    if reloc.VirtualAddress == 0 or reloc.SizeOfBlock == 0:
      break
    var entriesNum: csize_t = csize_t((reloc.SizeOfBlock - sizeof((IMAGE_BASE_RELOCATION)))) div
        csize_t(sizeof((BASE_RELOCATION_ENTRY)))
    var page: csize_t = csize_t(reloc.VirtualAddress)
    var entry: ptr BASE_RELOCATION_ENTRY = cast[ptr BASE_RELOCATION_ENTRY]((
        cast[size_t](reloc) + sizeof((IMAGE_BASE_RELOCATION))))
    var i: csize_t = 0
    while i < entriesNum:
      var offset: csize_t = entry.Offset
      var entryType: csize_t = entry.Type
      var reloc_field: csize_t = page + offset
      if entry == nil or entryType == 0:
        break
      if entryType != RELOC_32BIT_FIELD:
        echo "    [!] Not supported relocations format at ", cast[cint](i), " ", cast[cint](entryType)
        return false
      if size_t(reloc_field) >= moduleSize:
        echo "    [-] Out of Bound Field: ", reloc_field
        return false
      var relocateAddr: ptr csize_t = cast[ptr csize_t]((
          cast[size_t](modulePtr) + size_t(reloc_field)))
      echo "    [V] Apply Reloc Field at ", repr(relocateAddr)
      (relocateAddr[]) = ((relocateAddr[]) - csize_t(oldBase) + csize_t(newBase))
      entry = cast[ptr BASE_RELOCATION_ENTRY]((
          cast[size_t](entry) + sizeof((BASE_RELOCATION_ENTRY))))
      inc(i)
    inc(parsedSize, reloc.SizeOfBlock)
  return parsedSize != 0

proc OriginalFirstThunk*(self: ptr IMAGE_IMPORT_DESCRIPTOR): DWORD {.inline.} = self.union1.OriginalFirstThunk

proc fixIAT*(modulePtr: PVOID, exeArgs: Stringable): bool =
  echo "[+] Fix Import Address Table\n"
  var importsDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(modulePtr,
      IMAGE_DIRECTORY_ENTRY_IMPORT)
  if importsDir == nil:
    return false
  var maxSize: csize_t = cast[csize_t](importsDir.Size)
  var impAddr: csize_t = cast[csize_t](importsDir.VirtualAddress)
  var lib_desc: ptr IMAGE_IMPORT_DESCRIPTOR
  var parsedSize: csize_t = 0
  while parsedSize < maxSize:
    lib_desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR]((
        impAddr + parsedSize + cast[uint64](modulePtr)))
    
    if (lib_desc.OriginalFirstThunk == 0) and (lib_desc.FirstThunk == 0):
      break
    var libname: LPSTR = cast[LPSTR](cast[ULONGLONG](modulePtr) + lib_desc.Name)
    echo "    [+] Import DLL: ", $libname
    var call_via: csize_t = cast[csize_t](lib_desc.FirstThunk)
    var thunk_addr: csize_t = cast[csize_t](lib_desc.OriginalFirstThunk)
    if thunk_addr == 0:
      thunk_addr = csize_t(lib_desc.FirstThunk)
    var offsetField: csize_t = 0
    var offsetThunk: csize_t = 0
    var hmodule: HMODULE = LoadLibraryA(libname)

    when defined(args):
        var commandStr: string
        var exeArgsPassed = false
        if len(exeArgs) > 0: 
            commandStr = " " & exeArgs # in case commands are passed we have to prepend at least a space so that argv[1] is the first part of exeArgs
            exeArgsPassed = true
        if exeArgsPassed:
            # patch _wcmdln and _acmdln if they are present in the import to make exeArgs working for some C++ binaries
            var wcmdlenaddr = GetProcAddress(hmodule,"_wcmdln") 
            if wcmdlenaddr != NULL:
                echo "        Found _wcmdln -> patching with exeArgs"
                var newCmd = newWideCString(commandStr) # we have to prepend 
                patchMemory(wcmdlenaddr, cast[array[sizeOf(pointer), byte]](newCmd))
            var acmdlenaddr = GetProcAddress(hmodule,"_acmdln") 
            if acmdlenaddr != NULL:
                echo "        Found _wcmdln -> patching with exeArgs"
                var newCmd = &(commandStr)
                patchMemory(acmdlenaddr, cast[array[sizeOf(pointer), byte]](newCmd))
        
    while true:
      var fieldThunk: PIMAGE_THUNK_DATA = cast[PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetField + call_via))
      var orginThunk: PIMAGE_THUNK_DATA = cast[PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetThunk + thunk_addr))
      var boolvar: bool
      if ((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG32) != 0):
        boolvar = true
      elif((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG64) != 0):
        boolvar = true
      if (boolvar):
        var libaddr: size_t = cast[size_t](GetProcAddress(LoadLibraryA(libname),cast[LPSTR]((orginThunk.u1.Ordinal and 0xFFFF))))
        fieldThunk.u1.Function = ULONGLONG(libaddr)
        echo "        [V] API ord: ", (orginThunk.u1.Ordinal and 0xFFFF)
      if fieldThunk.u1.Function == 0:
        break
      if fieldThunk.u1.Function == orginThunk.u1.Function:
        var nameData: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](orginThunk.u1.AddressOfData)
        var byname: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONGLONG](modulePtr) + cast[DWORD](nameData))
      
        var func_name: LPCSTR = cast[LPCSTR](addr byname.Name)
        var libaddr: csize_t = cast[csize_t](GetProcAddress(hmodule,func_name))
        echo "        [V] API: ", func_name
        fieldThunk.u1.Function = ULONGLONG(libaddr)

        when defined(args):
            # patch common Win32 functions to get the command line
            if exeArgsPassed and "GetCommandLineW" == $$func_name:
                echo "           [>] Patching function to pass exeArgs: ", func_name
                patchArgFunctionMemory(cast[pointer](libaddr), cast[pointer](newWideCString(commandStr)))
            if exeArgsPassed and $$"GetCommandLineA" == func_name:
                echo "           [>] Patching function to pass exeArgs: ", func_name
                patchArgFunctionMemory(cast[pointer](libaddr), cast[pointer](&commandStr))

      inc(offsetField, sizeof((IMAGE_THUNK_DATA)))
      inc(offsetThunk, sizeof((IMAGE_THUNK_DATA)))
    inc(parsedSize, sizeof((IMAGE_IMPORT_DESCRIPTOR)))
  return true

proc ExecTLSCallbacks*(baseAddress: PVOID) =
  var tlsDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(baseAddress,
      IMAGE_DIRECTORY_ENTRY_TLS)
  var ntHeader: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(cast[ptr byte](baseAddress)))
 
  if tlsDir == nil:
    echo "[-] No TLS Directory found"
    return
  else:
    echo "[+] TLS Directory found"
  var tls: ptr IMAGE_TLS_DIRECTORY = cast[ptr IMAGE_TLS_DIRECTORY](
      cast[ULONGLONG](baseAddress) + tlsDir.VirtualAddress)
  var tlsCallback: ptr ULONGLONG = cast[ptr ULONGLONG](tls.AddressOfCallBacks)
  
  while tlsCallback[] != 0:
    echo "    [+] TLS Callback: ", repr(&tlsCallback[])
    var callback: proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): void {.cdecl.} = cast[proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): void {.cdecl.}](tlsCallback[])
    try:
      callback(cast[HINSTANCE](baseAddress), DLL_PROCESS_ATTACH, nil)
    except:
      echo "[-] TLS Callback failed"
    tlsCallback = tlsCallback + 1

var pImageBase: ptr BYTE = nil
var preferAddr: LPVOID = nil
var ntHeader: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(shellcodePtr))
if (ntHeader == nil):
  echo "[+] File isn\'t a PE file."
  quit()

var relocDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(shellcodePtr,IMAGE_DIRECTORY_ENTRY_BASERELOC)
preferAddr = cast[LPVOID](ntHeader.OptionalHeader.ImageBase)
echo "[+] Exe File Prefer Image Base at \n"

echo "Size:"
echo $ntHeader.OptionalHeader.SizeOfImage

pImageBase = cast[ptr BYTE](VirtualAlloc(preferAddr,
                                      ntHeader.OptionalHeader.SizeOfImage,
                                      MEM_COMMIT or MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE))

if (pImageBase == nil and relocDir == nil):
  echo "[-] Allocate Image Base At Failure.\n"
  quit()
if (pImageBase == nil and relocDir != nil):
  echo"[+] Try to Allocate Memory for New Image Base\n"
  pImageBase = cast[ptr BYTE](VirtualAlloc(nil,
      ntHeader.OptionalHeader.SizeOfImage, MEM_COMMIT or MEM_RESERVE,
      PAGE_EXECUTE_READWRITE))
  if (pImageBase == nil):
    echo"[-] Allocate Memory For Image Base Failure.\n"
    quit()
echo"[+] Mapping Section ..."
ntHeader.OptionalHeader.ImageBase = cast[ULONGLONG](pImageBase)
copymem(pImageBase, shellcodePtr, ntHeader.OptionalHeader.SizeOfHeaders)
var SectionHeaderArr: ptr IMAGE_SECTION_HEADER = cast[ptr IMAGE_SECTION_HEADER]((cast[size_t](ntHeader) + sizeof((IMAGE_NT_HEADERS))))
var i: int = 0
while i < cast[int](ntHeader.FileHeader.NumberOfSections):
  echo "    [+] Mapping Section :", $(addr SectionHeaderArr[i].addr.Name)
  var dest: LPVOID = (pImageBase + SectionHeaderArr[i].VirtualAddress)
  var source: LPVOID = (shellcodePtr + SectionHeaderArr[i].PointerToRawData)
  copymem(dest,source,cast[DWORD](SectionHeaderArr[i].SizeOfRawData))
  inc(i)

var goodrun = fixIAT(pImageBase, exeArgs)

ExecTLSCallbacks(pImageBase)

if pImageBase != preferAddr:
  if applyReloc(cast[ULONGLONG](pImageBase), cast[ULONGLONG](preferAddr), pImageBase,
               ntHeader.OptionalHeader.SizeOfImage):
    echo "[+] Relocation Fixed."
var retAddr: HANDLE = cast[HANDLE](pImageBase) + cast[HANDLE](ntHeader.OptionalHeader.AddressOfEntryPoint)

echo "Run Exe Module:\n"


var thread = CreateThread(nil, cast[SIZE_T](0), cast[LPTHREAD_START_ROUTINE](retAddr), nil, 0, nil)
WaitForSingleObject(thread, cast[DWORD](0xFFFFFFFFF))
