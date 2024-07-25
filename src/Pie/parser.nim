import winim/lean, types, ptr_math

proc rvaToVa[T](peBase: DWORD_PTR, rva: DWORD): T =
    return cast[T](peBase + rva)

proc readPeFile*(filePath: LPCSTR): (LPVOID, DWORD) =
    var peFile: HANDLE = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
    var peFileSize = GetFileSize(peFile, NULL)

    var peBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, peFileSize)

    if (ReadFile(
        peFile,
        peBuffer,
        peFileSize,
        NULL,
        NULL
    ) == FALSE):
        CloseHandle(peFile)
        return (NULL, 0)

    CloseHandle(peFile)
    return (peBuffer, peFileSize)


proc rvaToFileOffset(ntHeaders: PIMAGE_NT_HEADERS, rva: DWORD): DWORD =
    var sectionHeader = IMAGE_FIRST_SECTION(ntHeaders)

    for i in 0 .. int(ntHeaders.FileHeader.NumberOfSections):
        var sectionSize = sectionHeader.Misc.VirtualSize
        var sectionAddress = sectionHeader.VirtualAddress

        if (rva >= sectionAddress and rva < sectionAddress + sectionSize):
            return cast[DWORD](rva - sectionAddress + sectionHeader.PointerToRawData)
        
        sectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](sectionHeader) + sizeof(IMAGE_SECTION_HEADER))
    return 0; 


proc `$`*(flexableArray: array[1, BYTE]): string =
    var pEntry = cast[PBYTE](addr(flexableArray))
    var i = 0

    while pEntry[i] != cast[BYTE]('\0'):
        result.add(cast[char](pEntry[i]))
        i = i + 1

proc toString*(chars: openArray[BYTE]): string =
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc parsePe*(filePath: string): Pe =
    var peFileTup = readPeFile(filePath)

    var peFile = peFileTup[0]
    var peFileSize = peFileTup[1]

    var peBase = cast[DWORD_PTR](peFile)

    var dosHdr = cast[PIMAGE_DOS_HEADER](peBase)
    var ntHdrs: PIMAGE_NT_HEADERS = rvaToVa[PIMAGE_NT_HEADERS](peBase, dosHdr.e_lfanew)

    var optHdr: IMAGE_OPTIONAL_HEADER = ntHdrs.OptionalHeader
    var fileHdr: IMAGE_FILE_HEADER = ntHdrs.FileHeader

    var peHdrs = PeHeaders(
        dosHdr: dosHdr,
        ntHdr: ntHdrs,
        optHdr: optHdr,
        fileHdr: fileHdr
    )

    var sections: PeSections

    var currentSection = IMAGE_FIRST_SECTION(ntHdrs)

    for i in 0 ..< int(fileHdr.NumberOfSections):
        sections.add(currentSection)
        currentSection = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](currentSection) + sizeof(IMAGE_SECTION_HEADER))


    var exports: seq[PeExport]

    
    var exportDir = rvaToVa[PIMAGE_EXPORT_DIRECTORY](peBase, rvaToFileOffset(ntHdrs, optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))

    var addressOfNames = rvaToVa[PDWORD](peBase, rvaToFileOffset(ntHdrs, exportDir.AddressOfNames))
    var addressOfFunctions = rvaToVa[PDWORD](peBase, rvaToFileOffset(ntHdrs, exportDir.AddressOfFunctions))
    var addressOfNameOrds = rvaToVa[PWORD](peBase, rvaToFileOffset(ntHdrs, exportDir.AddressOfNameOrdinals))

    for i in 0 ..< exportDir.NumberOfFunctions:
        var expName = rvaToVa[LPCSTR](peBase, rvaToFileOffset(ntHdrs, addressOfNames[i]))
        var ord = cast[WORD](addressOfNameOrds[i])
        var fnRva = cast[PVOID](addressOfFunctions[DWORD(ord)])

        var peExport = PeExport(
            name: $expName,
            ordinal: ord,
            address: fnRva
        )

        exports.add(peExport)


    var imports: seq[PeImportEntry]

    var impDir = rvaToVa[PIMAGE_IMPORT_DESCRIPTOR](peBase, rvaToFileOffset(ntHdrs, optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress))
    
    while impDir.Name != 0:
        var dllName = rvaToVa[LPCSTR](peBase, rvaToFileOffset(ntHdrs, impDir.Name))

        var orgFt = rvaToVa[PIMAGE_THUNK_DATA](peBase, rvaToFileOffset(ntHdrs, impDir.union1.OriginalFirstThunk))
        var fT = rvaToVa[PIMAGE_THUNK_DATA](peBase, rvaToFileOffset(ntHdrs, impDir.FirstThunk))
        
        var importedFunctions: seq[PeImportFunction]

        while orgFt.u1.AddressOfData != 0:
            var pFnName = rvaToVa[PIMAGE_IMPORT_BY_NAME](peBase, rvaToFileOffset(ntHdrs, cast[DWORD](orgFt.u1.AddressOfData)))
            var fnName = $pFnName.Name
            var fnAddr = cast[PVOID](fT.u1.Function)
            
            importedFunctions.add(
                PeImportFunction(
                    name: fnName,
                    address: fnAddr
                )
            )
            orgFt += 1

        imports.add(
            PeImportEntry(
                dll: $dllName,
                imports: importedFunctions
            )
        )
        impDir += 1

    return Pe(buffer: peFile, size: peFileSize, headers: peHdrs, sections: sections, exports: exports, imports: imports)

    
proc section*(pe: Pe, sectName: string): PIMAGE_SECTION_HEADER =
    for section in pe.sections:
        if toString(section.Name) == sectName:
            return section
