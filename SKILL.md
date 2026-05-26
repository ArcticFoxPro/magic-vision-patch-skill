---
name: "magic-vision-patch-skill"
description: "Automatically discovers RVA offsets for bypassing runtime validation checks in PE files (like Honor Magic Vision device/model verification). Invoke when analyzing binary files to find patch locations for model/PCManager validation bypass."
---

# Binary Patch Analyzer Skill

## Overview

This skill provides a systematic approach to discover **RVA (Relative Virtual Address)** offsets and modify assembly code in Windows PE (Portable Executable) files. It is specifically designed to bypass runtime validation checks such as:
- Device model verification (机型校验)
- PCManager verification (PCManager校验)
- Installation support checks

## When to Use

Invoke this skill when:
1. You need to bypass device/model validation in software like Honor Magic Vision
2. Software updates have changed the validation code locations
3. You need to find new RVA offsets after a program update
4. You want to automate the discovery of validation checkpoints

## Prerequisites

1. **Tools Required**:
   - Python 3.7+
   - `pefile` library (`pip install pefile`)
   - `capstone` library (for disassembly, optional)
   - IDA Pro/Ghidra (for advanced analysis, optional)

2. **Files Needed**:
   - Target PE file (e.g., `Util.dll`, `Launcher.exe`, `MagicVisuals.exe`)
   - Knowledge of validation keywords (e.g., "HONOR", "PCManager", "IsHonorDevice")

## Discovery Workflow

### Step 1: Identify Validation Keywords

Search for strings related to validation in the target binary:

| Keyword Type | Examples |
|--------------|----------|
| Device Model | "HONOR", "productName", "MachineType", "SmBios" |
| Validation | "IsHonorDevice", "IsSupportInstall", "CheckDevice" |
| PCManager | "PCManager", "com.huawei.pcmanager" |

### Step 2: Locate String References

Find where these strings are referenced in the code:

```python
import pefile

pe = pefile.PE("Util.dll")

# Find all string references
for section in pe.sections:
    if b"HONOR" in section.get_data():
        print(f"Found in section: {section.Name.decode().strip()}")
```

### Step 3: Analyze Cross-References

Use disassembly to find LEA instructions that reference these strings:

```
Example assembly pattern:
LEA RDX, [RIP+0x123456]  ; Reference to "IsHonorDevice"
CALL SomeValidationFunc
TEST AL, AL
JZ Short Exit_Failure
```

### Step 4: Identify Validation Functions

Look for common validation function patterns:

| Pattern | Description |
|---------|-------------|
| `IsHonorDevice` | Returns boolean indicating if device is Honor |
| `IsSupportInstall` | Returns boolean indicating install support |
| `GetProductName` | Returns device product name |

### Step 5: Determine Patch Points

Find key locations to patch:

1. **Function Entry Point**: Replace function prologue with `MOV EAX, 1; RET`
2. **Conditional Branches**: Change `JZ/JNZ` to `JMP` or `NOP`
3. **Return Values**: Modify `XOR EAX,EAX` to `MOV EAX,1`

## RVA Calculation

### Converting RVA to File Offset

```python
def rva_to_offset(pe, rva):
    """Convert Relative Virtual Address to file offset"""
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None
```

### Important Notes

- **RVA** is relative to the module's base address when loaded in memory
- **File Offset** is the actual position in the disk file
- Use `pefile.PE.get_offset_from_rva()` for automatic conversion

## Patch Creation Guidelines

### Patch Structure

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Patch:
    name: str          # Description of what the patch does
    rva: int           # Relative Virtual Address to patch
    expected: bytes    # Original bytes (for safety check)
    replacement: bytes # New bytes to write
```

### Common Patch Patterns

| Patch Type | Original Bytes | Replacement | Effect |
|------------|----------------|-------------|--------|
| **Return True** | `48 89 5C 24 08 57` | `B8 01 00 00 00 C3` | Function returns true immediately |
| **Return 1** | `33 C0` | `B8 01 00 00 00` | EAX = 1 (success) |
| **Always Jump** | `75 07` (JNZ) | `EB 07` (JMP) | Skip validation failure path |
| **Skip Check** | `74 32` (JZ) | `90 90` (NOP) | Ignore conditional branch |

### Example Patch Definitions

```python
PATCHES = {
    "Util.dll": [
        Patch(
            "IsHonorDevice -> always true",
            0x119190,
            b"\x48\x89\x5C\x24\x08\x57",
            b"\xB8\x01\x00\x00\x00\xC3",
        ),
        Patch(
            "GetProductName early fail -> return 1",
            0x14A5C3,
            b"\x33\xC0",
            b"\xB8\x01\x00\x00\x00",
        ),
    ],
    "Launcher.exe": [
        Patch(
            "isSupportInstall result -> force success",
            0x20507,
            b"\x0F\xB6\xD8",
            b"\xB3\x01\x90",
        ),
    ],
}
```

## Verification Process

### After Applying Patches

1. **Check Byte Consistency**: Verify the expected bytes match before patching
2. **Create Backups**: Always backup original files before modification
3. **Test Execution**: Run the patched binary to confirm validation is bypassed
4. **Error Handling**: Check for crashes or unexpected behavior

### Idempotency

Ensure patches can be applied safely multiple times:

```python
if current == patch.expected:
    # Apply patch
    data[offset:offset+len(patch.replacement)] = patch.replacement
elif current == patch.replacement:
    # Already patched, skip
    print("Already patched")
```

## Automation Script Template

```python
import pefile
import shutil
from pathlib import Path

def apply_patches(file_path, patches):
    pe = pefile.PE(str(file_path), fast_load=True)
    data = bytearray(file_path.read_bytes())
    
    for patch in patches:
        offset = pe.get_offset_from_rva(patch.rva)
        current = bytes(data[offset:offset+len(patch.expected)])
        
        if current == patch.expected:
            data[offset:offset+len(patch.replacement)] = patch.replacement
            print(f"Patched: {patch.name}")
        elif current == patch.replacement:
            print(f"Already patched: {patch.name}")
    
    output_path = file_path.with_suffix(file_path.suffix + ".patched")
    output_path.write_bytes(data)
    print(f"Saved to: {output_path}")
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| **RVA not found** | Wrong section or invalid RVA | Re-analyze the binary |
| **Bytes don't match** | Different binary version | Re-discover the correct bytes |
| **File locked** | Binary is in use | Close all related processes |
| **Crash after patch** | Incorrect patch length | Verify replacement byte count |

### Debug Tips

1. Use IDA Pro/Ghidra to confirm RVA locations
2. Compare disassembly before/after patching
3. Check PE section headers for valid ranges
4. Use debugger to trace validation flow

## Maintenance

### After Software Updates

1. Run the discovery workflow on the new binary
2. Identify changed validation code locations
3. Update patch RVAs and byte patterns
4. Test thoroughly before deployment

### Version Tracking

Maintain a version-specific patch database:

```python
PATCHES_BY_VERSION = {
    "10.0.0.37": { "Util.dll": [...] },
    "10.0.0.38": { "Util.dll": [...] },
}
```

## Security Considerations

1. **Backup First**: Always create backups before modifying binaries
2. **Verify Source**: Only patch trusted binaries
3. **Test Environment**: Test patches in a non-production environment
4. **Legal Compliance**: Ensure you have rights to modify the software

## Conclusion

This skill provides a systematic approach to discovering and applying patches to bypass validation checks in PE files. By following this workflow, you can efficiently adapt to software updates and maintain functional patches across versions.

---

*Skill created for analyzing Honor Magic Vision and similar validation-bypass scenarios.*
