import winim/lean

type
    PeHeaders* = object
     dosHdr*: PIMAGE_DOS_HEADER
     ntHdr*: PIMAGE_NT_HEADERS
     optHdr*: IMAGE_OPTIONAL_HEADER
     fileHdr*: IMAGE_FILE_HEADER

    PeSections* = seq[PIMAGE_SECTION_HEADER]
    
    PeImportFunction* = object
     name*: string
     address*: pointer

    PeImportEntry* = object
     dll*: string
     imports*: seq[PeImportFunction]

    PeExport* = object
     name*: string
     address*: pointer
     ordinal*: uint16

    CodeCave* = object
     section*: PIMAGE_SECTION_HEADER
     sectionName*: string
     size*: int
     rawAddress*: pointer
     virtualAddress*: pointer

    Pe* = object
     buffer*: pointer
     size*: int
     
     headers*: PeHeaders
     sections*: PeSections

     imports*: seq[PeImportEntry]
     exports*: seq[PeExport]