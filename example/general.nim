import Pie, strformat, strutils

var pe = parsePe("C:\\windows\\system32\\kernel32.dll")

# Basic Data About PE Buffer / File
echo(fmt"[*] Pe Buffer Address: 0x{repr(pe.buffer)}")
echo(fmt"[*] Pe File Size: {pe.size}")

# Parsing AOEP
var aoep = pe.headers.optHdr.AddressOfEntryPoint
echo(fmt"[*] AddressOfEntryPoint: {toHex(aoep)}")

# Parsing Sections
for section in pe.sections:
    # var entropy = pe.entropy(section) (Optionally get section entropy)
    echo(fmt"[*] Section: {toString(section.Name)} ({toHex(section.VirtualAddress)})")

# Parsing Imports
for peImport in pe.imports:
    echo(fmt"[{peImport.dll}]")

    for importEntry in peImport.imports:
        echo("\t" & fmt"Name: {importEntry.name}, RVA: {repr(importEntry.address)}")


# Parsing Exports
for peExport in pe.exports:
    echo(fmt"Name: {peExport.name}, RVA: {repr(peExport.address)}, Ordinal: {peExport.ordinal}")

# Finding Code Caves
var codeCaves = pe.codeCaves(300) # enough to fit in calc.bin shellcode

for cave in codeCaves:
    echo(fmt"[*] Code Cave Found, Section: {cave.sectionName}, Size: {cave.size} Bytes")


# Calculating PE Entropy
var peEntropy = pe.entropy()
echo(fmt"Pe Entropy: {peEntropy}")