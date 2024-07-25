import winim/lean, types, ptr_math, math, parser


proc codeCaves*(peFile: Pe, minSize: int): seq[CodeCave] =
    for section in peFile.sections:
        var sectionName = toString(section.Name)
        var ptrToData = section.PointerToRawData
        
        var sectionDataBase = cast[DWORD_PTR](cast[DWORD_PTR](peFile.buffer) + ptrToData)
        var sectionDataSize = section.SizeOfRawData
        var freeBytes = 0

        for i in 0..sectionDataSize:
            var readByte = cast[PBYTE](sectionDataBase + cast[DWORD](i))[]
            if readByte == 0x0:
                freeBytes += 1
            else:
                if freeBytes > minSize:
                    var caveStartAddress = cast[LPVOID](ptrToData + i - freeBytes)
                    var caveVa = cast[LPVOID](peFile.headers.optHdr.ImageBase + ptrToData + i - freeBytes)
                    result.add(
                        CodeCave(
                            section: section,
                            size: freeBytes,
                            sectionName: sectionName,
                            rawAddress: caveStartAddress,
                            virtualAddress: caveVa
                        )
                    )

                freeBytes = 0

proc getOccurance(buffer: pointer, size: int, value: byte): int =
    var count = 0
    for i in 0 .. size:
        if cast[ptr byte](buffer)[i] == value:
            count += 1
    
    return count

proc calcEntropy*(buffer: pointer, size: int): float =
    var entropy: float = 0

    for i in 0 ..< 256:
        var p = getOccurance(buffer, size, byte(i)) / size
        if p > 0:
            entropy += -p * math.log(p, 2)

    return entropy


proc entropy*(pe: Pe, section: PIMAGE_SECTION_HEADER): float =
    var buffer = cast[PBYTE](cast[DWORD_PTR](pe.buffer) + section.PointerToRawData)
    return calcEntropy(buffer, section.SizeOfRawData)

proc entropy*(pe: Pe): float =    
    return calcEntropy(pe.buffer, pe.size)

proc rwxSections*(pe: Pe): seq[PIMAGE_SECTION_HEADER] =
    for section in pe.sections:
        var R = (section.Characteristics and 0x40000000)
        var W = (section.Characteristics and 0x80000000)
        var X = (section.Characteristics and 0x20000000)

        if (X == 0x20000000) and (R == 0x40000000) and (W == 0x80000000):
            result.add(section)