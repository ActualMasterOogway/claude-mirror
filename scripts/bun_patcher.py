"""
Bun Standalone Patcher
=========================
Injects arbitrary JavaScript into the .bun section of any Bun standalone
executable.  Supports PE (Windows), ELF (Linux), and Mach-O (macOS).

Patch metadata is stored in the dead space between the Bun data boundary
(8 + length_header) and the end of the section's aligned size.  The Bun
runtime only reads up to the length header, so the metadata is completely
invisible to it.

Binary layout after patching (all formats)::

    .bun section raw data
    +-- [8 B]   u64 LE length header  (= vsize - 8)
    +-- [...]   bundle data (modules, strings, source, bytecode ...)
    +-- [32 B]  Offsets struct
    +-- [16 B]  Bun trailer  "\\n---- Bun! ----\\n"
    |           -- vsize boundary --
    +-- [...]   zero padding  (to fill alignment gap)
    +-- [...]   PatchMetadata JSON
    +-- [4 B]   u32 LE metadata-JSON length
    +-- [16 B]  PATCH_MAGIC  "\\n- Bun Patch -\\x01\\n"
                -- raw_size boundary --

Supported formats
-----------------
- **PE** (Windows):  `.bun` PE section, SizeOfImage / FileAlignment headers
- **ELF** (Linux):   `.bun` ELF section with a dedicated PT_LOAD segment
- **Mach-O** (macOS): `__BUN` segment with `__bun` section
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

# ━━ Constants ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BUN_TRAILER        = b"\n---- Bun! ----\n"
BUN_TRAILER_SIZE   = 16
OFFSETS_SIZE       = 32
MODULE_ENTRY_SIZE  = 52      # 6 StringPointers (48 B) + 4 enum u8 fields (4 B)
NUM_STRING_PTRS    = 6       # name, contents, sourcemap, bytecode, module_info, bytecode_origin_path
SP_CONTENTS        = 1
SP_BYTECODE        = 3
SP_BYTECODE_PATH   = 5

PATCH_MAGIC        = b"\n- Bun Patch -\x01\n"  # 16 bytes -- \x01 = format version 1
PATCH_MAGIC_SIZE   = 16
PATCH_LENGTH_SIZE  = 4                       # u32 LE that stores the JSON length

assert len(PATCH_MAGIC) == PATCH_MAGIC_SIZE

# -- ELF constants --
ELF_MAGIC       = b"\x7fELF"
ELFCLASS64      = 2
ELFDATA2LSB     = 1
PT_LOAD         = 1
EHDR_SIZE       = 64   # sizeof(Elf64_Ehdr)
SHDR_SIZE       = 64   # sizeof(Elf64_Shdr)
PHDR_SIZE       = 56   # sizeof(Elf64_Phdr)
EM_AARCH64      = 183
EM_PPC64        = 21

# -- Mach-O constants --
MH_MAGIC_64             = 0xFEEDFACF
MACHO_HEADER_SIZE       = 32   # sizeof(mach_header_64)
MACHO_SEGMENT_CMD_SIZE  = 72   # sizeof(segment_command_64)
MACHO_SECTION_SIZE      = 80   # sizeof(section_64)
LC_SEGMENT_64           = 0x19
LC_SYMTAB               = 0x02
LC_DYSYMTAB             = 0x0B
LC_CODE_SIGNATURE       = 0x1D
LC_DYLD_INFO            = 0x22
LC_DYLD_INFO_ONLY       = 0x80000022
LC_FUNCTION_STARTS      = 0x26
LC_DATA_IN_CODE         = 0x29
LC_DYLIB_CODE_SIGN_DRS  = 0x2B
LC_LINKER_OPT_HINT      = 0x2E
LC_DYLD_EXPORTS_TRIE    = 0x80000033
LC_DYLD_CHAINED_FIXUPS  = 0x80000034
MACHO_BUN_SEGNAME       = "__BUN"
MACHO_BUN_SECTNAME      = "__bun"
MACHO_BLOB_ALIGN        = 16384   # 16 KB -- matches Bun's blob_alignment


# ━━ Common data structures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True, slots=True)
class StringPointer:
    """Bun StringPointer -- (offset, length) into the data buffer."""
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class ModuleEntry:
    """One CompiledModuleGraphFile: six StringPointers + four u8 enum fields."""
    string_ptrs: tuple[StringPointer, ...]
    encoding: int
    loader: int
    module_format: int
    side: int


@dataclass(frozen=True, slots=True)
class BunModuleGraph:
    """Parsed Bun Offsets struct + module entry table."""
    byte_count: int
    mod_offset: int
    mod_length: int
    entry_id: int
    argv_offset: int
    argv_length: int
    flags: int
    offsets_pos: int          # absolute offset within the bundle blob
    entries: tuple[ModuleEntry, ...]


# ━━ Patch metadata ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(slots=True)
class PatchMetadata:
    """
    Metadata written into the dead space so we can identify, inspect,
    and reverse a patch without needing an external state file.

    All offsets are relative to the *start of the .bun section raw data*
    (i.e. the first byte of the u64 length header).
    """
    version: int = 1
    format: str = "pe"           # "pe", "elf", "macho"

    # Where the payload was spliced in (absolute bundle offset).
    inject_offset: int = 0
    payload_size: int = 0
    payload_sha256: str = ""

    # Original values so we can restore them on unpatch.
    original_vsize: int = 0
    original_raw_size: int = 0
    original_image_size: int = 0  # PE=SizeOfImage  ELF=e_shoff  Mach-O=LINKEDIT fileoff

    # Bytecode StringPointers we zeroed (main module only).
    # Stored as [offset, length] pairs.
    original_bytecode_sp: list[int] = field(default_factory=lambda: [0, 0])
    original_bytecode_path_sp: list[int] = field(default_factory=lambda: [0, 0])

    patched_at: str = ""      # ISO-8601 UTC timestamp

    def to_json(self) -> bytes:
        return json.dumps(asdict(self), separators=(",", ":")).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> Self:
        d = json.loads(raw)
        if "format" not in d:
            d["format"] = "pe"   # backward compat with pre-multiformat patches
        return cls(**d)


# ━━ PE data structures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True, slots=True)
class PESection:
    """A single PE section header."""
    name: str
    vsize: int
    vaddr: int
    raw_size: int
    raw_off: int
    header_off: int


@dataclass(frozen=True, slots=True)
class PEInfo:
    """Parsed PE64 metadata relevant to patching."""
    pe_off: int
    opt_off: int
    size_of_image_off: int
    size_of_image: int
    file_align: int
    sect_align: int
    sections: tuple[PESection, ...]


# ━━ ELF data structures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True, slots=True)
class ELFInfo:
    """Parsed ELF64 metadata relevant to patching."""
    e_machine: int
    e_phoff: int
    e_phnum: int
    e_shoff: int
    e_shnum: int
    e_shstrndx: int
    page_size: int
    bun_shdr_idx: int       # index of .bun in section header table
    bun_phdr_idx: int       # index of LOAD program header covering .bun
    bun_off: int            # file offset of .bun section data
    bun_vsize: int          # .bun sh_size (content size)
    bun_raw_size: int       # LOAD p_filesz (aligned size in file)
    bun_vaddr: int          # .bun virtual address


# ━━ Mach-O data structures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True, slots=True)
class MachOInfo:
    """Parsed Mach-O 64-bit metadata relevant to patching."""
    cputype: int
    ncmds: int
    sizeofcmds: int
    bun_seg_cmd_off: int    # file offset of __BUN LC_SEGMENT_64 command
    bun_sect_hdr_off: int   # file offset of __bun section_64 header (0 if none)
    bun_off: int            # file offset of __BUN segment data
    bun_vsize: int          # __bun section size (content size)
    bun_seg_filesize: int   # __BUN segment filesize (aligned)
    bun_seg_vmaddr: int     # __BUN segment vmaddr
    bun_seg_vmsize: int     # __BUN segment vmsize
    linkedit_cmd_off: int   # file offset of __LINKEDIT segment command (0 if none)
    linkedit_fileoff: int   # __LINKEDIT file offset
    codesign_cmd_off: int   # file offset of LC_CODE_SIGNATURE command (0 if none)


# ━━ Errors ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PatcherError(Exception):
    """Base for all patcher errors."""

class UnsupportedFormat(PatcherError): ...
class NotAPEFile(PatcherError): ...
class NotAnELFFile(PatcherError): ...
class NotAMachOFile(PatcherError): ...
class NoBunSection(PatcherError): ...
class BunFormatError(PatcherError): ...
class AlreadyPatched(PatcherError): ...
class NotPatched(PatcherError): ...


# ━━ Utility functions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()

def _u16(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]

def _u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]

def _u64(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]

def _p32(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<I", buf, off, val)

def _p64(buf: bytearray, off: int, val: int) -> None:
    struct.pack_into("<Q", buf, off, val)


# ━━ Format detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_format(data: bytes) -> str:
    """Detect binary format from magic bytes.  Returns 'pe', 'elf', or 'macho'."""
    if len(data) < 4:
        raise UnsupportedFormat("File too small to identify")
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == ELF_MAGIC:
        return "elf"
    magic = _u32(data, 0)
    if magic == MH_MAGIC_64:
        return "macho"
    raise UnsupportedFormat(
        f"Unknown binary format (magic: {data[:4].hex()}).  "
        "Expected PE (MZ), ELF (\\x7fELF), or Mach-O 64 (FEEDFACF)."
    )


# ━━ PE parsing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_pe(data: bytes) -> PEInfo:
    """Parse PE64 headers and return the subset we need for patching."""
    pe_off = _u32(data, 0x3C)
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise NotAPEFile("PE signature not found")

    _machine, num_sections = struct.unpack_from("<HH", data, pe_off + 4)
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24

    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic != 0x20B:
        raise NotAPEFile(f"Expected PE32+ (0x20B), got {magic:#x}")

    sect_align = _u32(data, opt_off + 32)
    file_align = _u32(data, opt_off + 36)
    soi_off    = opt_off + 56
    soi        = _u32(data, soi_off)

    sec_table = pe_off + 24 + opt_size
    sections: list[PESection] = []
    for i in range(num_sections):
        off = sec_table + i * 40
        name = data[off : off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
        sections.append(PESection(name, vsize, vaddr, raw_size, raw_off, off))

    return PEInfo(
        pe_off=pe_off,
        opt_off=opt_off,
        size_of_image_off=soi_off,
        size_of_image=soi,
        file_align=file_align,
        sect_align=sect_align,
        sections=tuple(sections),
    )


def _find_bun_section_pe(pe: PEInfo) -> PESection:
    for sec in pe.sections:
        if sec.name == ".bun":
            return sec
    raise NoBunSection("No .bun section found in PE -- is this a Bun standalone binary?")


# ━━ ELF parsing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_elf(data: bytes) -> ELFInfo:
    """Parse ELF64 headers and find the .bun section with its LOAD segment."""
    if len(data) < EHDR_SIZE:
        raise NotAnELFFile("File too small for ELF64 header")
    if data[:4] != ELF_MAGIC:
        raise NotAnELFFile("ELF magic not found")
    if data[4] != ELFCLASS64:
        raise NotAnELFFile("Only 64-bit ELF is supported")
    if data[5] != ELFDATA2LSB:
        raise NotAnELFFile("Only little-endian ELF is supported")

    e_machine   = _u16(data, 0x12)
    e_phoff     = _u64(data, 0x20)
    e_shoff     = _u64(data, 0x28)
    e_phentsize = _u16(data, 0x36)
    e_phnum     = _u16(data, 0x38)
    e_shentsize = _u16(data, 0x3A)
    e_shnum     = _u16(data, 0x3C)
    e_shstrndx  = _u16(data, 0x3E)

    page_size = 0x10000 if e_machine in (EM_AARCH64, EM_PPC64) else 0x1000

    # --- read .shstrtab for section names ---
    if e_shstrndx >= e_shnum:
        raise NotAnELFFile("Invalid e_shstrndx")
    shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
    strtab_off  = _u64(data, shstrtab_hdr + 0x18)   # sh_offset
    strtab_size = _u64(data, shstrtab_hdr + 0x20)    # sh_size
    strtab = data[strtab_off : strtab_off + strtab_size]

    # --- find .bun section ---
    bun_shdr_idx = -1
    bun_off = bun_vsize = bun_vaddr = 0
    for i in range(e_shnum):
        hdr = e_shoff + i * e_shentsize
        name_idx = _u32(data, hdr)
        if name_idx >= len(strtab):
            continue
        nul = strtab.find(b"\x00", name_idx)
        name = strtab[name_idx : nul if nul >= 0 else len(strtab)].decode("ascii", errors="replace")
        if name == ".bun":
            bun_shdr_idx = i
            bun_off   = _u64(data, hdr + 0x18)   # sh_offset
            bun_vsize = _u64(data, hdr + 0x20)    # sh_size
            bun_vaddr = _u64(data, hdr + 0x10)    # sh_addr
            break

    if bun_shdr_idx < 0:
        raise NoBunSection("No .bun section found in ELF -- is this a Bun standalone binary?")

    # --- find the PT_LOAD covering .bun ---
    bun_phdr_idx = -1
    bun_raw_size = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type   = _u32(data, ph)
        p_offset = _u64(data, ph + 0x08)
        p_filesz = _u64(data, ph + 0x20)
        if p_type == PT_LOAD and p_offset <= bun_off < p_offset + p_filesz:
            bun_phdr_idx = i
            # raw_size = space from .bun start to LOAD segment end
            bun_raw_size = (p_offset + p_filesz) - bun_off
            break

    if bun_phdr_idx < 0:
        raise NoBunSection("No PT_LOAD segment found covering .bun section")

    return ELFInfo(
        e_machine=e_machine, e_phoff=e_phoff, e_phnum=e_phnum,
        e_shoff=e_shoff, e_shnum=e_shnum, e_shstrndx=e_shstrndx,
        page_size=page_size,
        bun_shdr_idx=bun_shdr_idx, bun_phdr_idx=bun_phdr_idx,
        bun_off=bun_off, bun_vsize=bun_vsize,
        bun_raw_size=bun_raw_size, bun_vaddr=bun_vaddr,
    )


# ━━ Mach-O parsing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_macho(data: bytes) -> MachOInfo:
    """Parse Mach-O 64-bit headers and find the __BUN segment / __bun section."""
    if len(data) < MACHO_HEADER_SIZE:
        raise NotAMachOFile("File too small for Mach-O 64 header")
    magic = _u32(data, 0)
    if magic != MH_MAGIC_64:
        raise NotAMachOFile(f"Not a 64-bit little-endian Mach-O (magic: {magic:#010x})")

    cputype    = _u32(data, 4)
    ncmds      = _u32(data, 0x10)
    sizeofcmds = _u32(data, 0x14)

    bun_seg_cmd_off = bun_sect_hdr_off = 0
    bun_off = bun_vsize = 0
    bun_seg_filesize = bun_seg_vmaddr = bun_seg_vmsize = 0
    linkedit_cmd_off = linkedit_fileoff = 0
    codesign_cmd_off = 0
    found_bun = False

    cmd_off = MACHO_HEADER_SIZE
    for _ in range(ncmds):
        if cmd_off + 8 > len(data):
            break
        cmd     = _u32(data, cmd_off)
        cmdsize = _u32(data, cmd_off + 4)

        if cmd == LC_SEGMENT_64 and cmd_off + MACHO_SEGMENT_CMD_SIZE <= len(data):
            segname_raw = data[cmd_off + 8 : cmd_off + 24]
            segname = segname_raw.rstrip(b"\x00").decode("ascii", errors="replace")

            if segname == MACHO_BUN_SEGNAME:
                bun_seg_cmd_off = cmd_off
                bun_seg_vmaddr  = _u64(data, cmd_off + 0x18)
                bun_seg_vmsize  = _u64(data, cmd_off + 0x20)
                seg_fileoff     = _u64(data, cmd_off + 0x28)
                bun_seg_filesize = _u64(data, cmd_off + 0x30)
                nsects          = _u32(data, cmd_off + 0x40)

                # Default: use segment bounds as section bounds
                bun_off   = seg_fileoff
                bun_vsize = bun_seg_filesize

                # Look for the __bun section within the segment
                sect_off = cmd_off + MACHO_SEGMENT_CMD_SIZE
                for _ in range(nsects):
                    if sect_off + MACHO_SECTION_SIZE > len(data):
                        break
                    sname = data[sect_off : sect_off + 16].rstrip(b"\x00").decode("ascii", errors="replace")
                    if sname == MACHO_BUN_SECTNAME:
                        bun_sect_hdr_off = sect_off
                        bun_off   = _u32(data, sect_off + 0x30)   # section offset (u32)
                        bun_vsize = _u64(data, sect_off + 0x28)   # section size   (u64)
                        break
                    sect_off += MACHO_SECTION_SIZE

                found_bun = True

            elif segname == "__LINKEDIT":
                linkedit_cmd_off = cmd_off
                linkedit_fileoff = _u64(data, cmd_off + 0x28)

        elif cmd == LC_CODE_SIGNATURE:
            codesign_cmd_off = cmd_off

        cmd_off += cmdsize

    if not found_bun:
        raise NoBunSection("No __BUN segment found in Mach-O -- is this a Bun standalone binary?")

    return MachOInfo(
        cputype=cputype, ncmds=ncmds, sizeofcmds=sizeofcmds,
        bun_seg_cmd_off=bun_seg_cmd_off, bun_sect_hdr_off=bun_sect_hdr_off,
        bun_off=bun_off, bun_vsize=bun_vsize,
        bun_seg_filesize=bun_seg_filesize,
        bun_seg_vmaddr=bun_seg_vmaddr, bun_seg_vmsize=bun_seg_vmsize,
        linkedit_cmd_off=linkedit_cmd_off, linkedit_fileoff=linkedit_fileoff,
        codesign_cmd_off=codesign_cmd_off,
    )


# ━━ Common bundle operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_module_graph(bundle: bytes, vsize: int) -> BunModuleGraph:
    """Parse the Offsets trailer and module entry table from the bundle blob."""
    trailer_start = vsize - BUN_TRAILER_SIZE
    trailer = bundle[trailer_start : vsize]
    if trailer != BUN_TRAILER:
        raise BunFormatError(f"Bun trailer not found at vsize boundary (got {trailer!r})")

    off = vsize - OFFSETS_SIZE - BUN_TRAILER_SIZE
    byte_count  = _u64(bundle, off)
    mod_offset  = _u32(bundle, off + 8)
    mod_length  = _u32(bundle, off + 12)
    entry_id    = _u32(bundle, off + 16)
    argv_offset = _u32(bundle, off + 20)
    argv_length = _u32(bundle, off + 24)
    flags       = _u32(bundle, off + 28)

    num_entries = mod_length // MODULE_ENTRY_SIZE
    entries: list[ModuleEntry] = []
    for i in range(num_entries):
        epos = 8 + mod_offset + i * MODULE_ENTRY_SIZE
        sps = tuple(
            StringPointer(_u32(bundle, epos + j * 8), _u32(bundle, epos + j * 8 + 4))
            for j in range(NUM_STRING_PTRS)
        )
        enum_base = epos + NUM_STRING_PTRS * 8
        entries.append(ModuleEntry(
            string_ptrs=sps,
            encoding=bundle[enum_base],
            loader=bundle[enum_base + 1],
            module_format=bundle[enum_base + 2],
            side=bundle[enum_base + 3],
        ))

    return BunModuleGraph(
        byte_count=byte_count, mod_offset=mod_offset,
        mod_length=mod_length, entry_id=entry_id,
        argv_offset=argv_offset, argv_length=argv_length,
        flags=flags, offsets_pos=off, entries=tuple(entries),
    )


def read_patch_metadata(section_raw: bytes, raw_size: int) -> PatchMetadata | None:
    """
    Try to read patch metadata from the dead space at the end of the section.

    Layout (reading backwards from raw_size):
        [PATCH_MAGIC 16B] [u32 LE json_len 4B] [JSON json_len B] ...
    """
    if raw_size < PATCH_MAGIC_SIZE + PATCH_LENGTH_SIZE:
        return None

    magic_start = raw_size - PATCH_MAGIC_SIZE
    if section_raw[magic_start : raw_size] != PATCH_MAGIC:
        return None

    json_len = _u32(section_raw, magic_start - PATCH_LENGTH_SIZE)
    json_start = magic_start - PATCH_LENGTH_SIZE - json_len
    if json_start < 0:
        return None

    try:
        return PatchMetadata.from_json(section_raw[json_start : json_start + json_len])
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def _embed_metadata(section_buf: bytearray, metadata: PatchMetadata, file_align: int) -> bytearray:
    """
    Append serialised metadata + length + magic into the section buffer,
    aligned to *file_align*, with PATCH_MAGIC as the final 16 bytes.
    """
    meta_json = metadata.to_json()
    tail = meta_json + struct.pack("<I", len(meta_json)) + PATCH_MAGIC

    min_size = len(section_buf) + len(tail)
    aligned = _align_up(min_size, file_align)

    section_buf.extend(b"\x00" * (aligned - len(section_buf)))
    section_buf[-len(tail):] = tail
    return section_buf


def _find_injection_point(bundle: bytes, start: int, end: int,
                          anchor: bytes | None = None) -> int:
    """
    Locate the byte offset within *bundle* where the payload will be spliced.
    """
    region = bundle[start:end]

    if anchor is not None:
        pos = region.find(anchor)
        if pos != -1:
            abs_pos = start + pos + len(anchor)
            for i in range(abs_pos, min(abs_pos + 80, end)):
                if bundle[i : i + 1] in (b";", b"\n"):
                    return i + 1
            return abs_pos
        print("  [WARN] anchor not found - falling back to auto-detect")

    for sig in (b"__dirname){", b"__dirname) {"):
        pos = region.find(sig)
        if pos != -1:
            brace = region.index(b"{", pos)
            print("  detected CJS wrapper, injecting inside function body")
            return start + brace + 1

    return start


def _adjust_string_pointers(
    buf: bytearray,
    graph: BunModuleGraph,
    mod_list_pos: int,
    inject_rel: int,
    delta: int,
) -> int:
    """
    Walk every StringPointer in every module entry and shift offsets/lengths
    that straddle or follow *inject_rel* by *delta* bytes.
    """
    updated = 0
    for i in range(len(graph.entries)):
        epos = mod_list_pos + i * MODULE_ENTRY_SIZE
        for j in range(NUM_STRING_PTRS):
            sp_pos = epos + j * 8
            sp_off = _u32(buf, sp_pos)
            sp_len = _u32(buf, sp_pos + 4)
            if sp_off == 0 and sp_len == 0:
                continue
            if sp_off >= inject_rel:
                _p32(buf, sp_pos, sp_off + delta)
                updated += 1
            elif sp_off + sp_len > inject_rel:
                _p32(buf, sp_pos + 4, sp_len + delta)
                updated += 1
    return updated


# ━━ Unified binary parsing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parse_binary(data: bytes) -> tuple[str, Any, int, int, int, int]:
    """
    Auto-detect format and extract .bun section info.

    Returns ``(format, format_info, bun_off, vsize, raw_size, file_align)``.
    """
    fmt = detect_format(data)

    if fmt == "pe":
        pe = parse_pe(data)
        sec = _find_bun_section_pe(pe)
        return fmt, pe, sec.raw_off, sec.vsize, sec.raw_size, pe.file_align

    if fmt == "elf":
        elf = parse_elf(data)
        return fmt, elf, elf.bun_off, elf.bun_vsize, elf.bun_raw_size, elf.page_size

    if fmt == "macho":
        mo = parse_macho(data)
        return fmt, mo, mo.bun_off, mo.bun_vsize, mo.bun_seg_filesize, MACHO_BLOB_ALIGN

    raise UnsupportedFormat(fmt)


# ━━ PE rebuild helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _rebuild_pe_patch(original_data: bytes, pe: PEInfo,
                      bundle_final: bytearray, new_vsize: int) -> bytes:
    bun_sec = _find_bun_section_pe(pe)
    new_raw_size = len(bundle_final)
    new_image_size = _align_up(bun_sec.vaddr + new_vsize, pe.sect_align)

    result = bytearray(original_data[:bun_sec.raw_off])
    result.extend(bundle_final)
    result.extend(original_data[bun_sec.raw_off + bun_sec.raw_size :])

    # section header: VirtualSize, SizeOfRawData
    _p32(result, bun_sec.header_off + 8, new_vsize)
    _p32(result, bun_sec.header_off + 16, new_raw_size)

    # optional header: SizeOfImage
    _p32(result, pe.size_of_image_off, new_image_size)

    # clear the Security Directory (invalidated by our changes)
    sec_dir_off = pe.opt_off + 112 + 4 * 8
    _p32(result, sec_dir_off, 0)
    _p32(result, sec_dir_off + 4, 0)

    print(f"  SizeOfImage:   {pe.size_of_image:,} -> {new_image_size:,}")
    return bytes(result)


def _rebuild_pe_unpatch(patched_data: bytes, pe: PEInfo,
                        padded_bundle: bytes, old_vsize: int,
                        meta: PatchMetadata) -> bytes:
    bun_sec = _find_bun_section_pe(pe)
    new_raw_size = len(padded_bundle)

    result = bytearray(patched_data[:bun_sec.raw_off])
    result.extend(padded_bundle)
    result.extend(patched_data[bun_sec.raw_off + bun_sec.raw_size :])

    _p32(result, bun_sec.header_off + 8, old_vsize)
    _p32(result, bun_sec.header_off + 16, new_raw_size)
    _p32(result, pe.size_of_image_off, meta.original_image_size)

    sec_dir_off = pe.opt_off + 112 + 4 * 8
    _p32(result, sec_dir_off, 0)
    _p32(result, sec_dir_off + 4, 0)

    return bytes(result)


# ━━ ELF rebuild helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _rebuild_elf_patch(original_data: bytes, elf: ELFInfo,
                       bundle_final: bytearray, new_vsize: int) -> bytes:
    """
    Rebuild the ELF with the modified .bun section.

    Strategy: insert (new_raw_size - bun_raw_size) bytes of bundle expansion
    between the old bun-LOAD region and everything that follows it. Every
    program/section header field that points past the old bundle end is
    shifted forward by the same delta. This preserves non-allocatable
    sections (.comment/.symtab/.strtab/.shstrtab) that live between the LOAD
    end and the section header table, and keeps pre-.bun LOAD sections
    (.tdata/.data/.got/.bss) within the LOAD segment after we grow its
    p_filesz/p_memsz.
    """
    new_raw_size = len(bundle_final)
    delta = new_raw_size - elf.bun_raw_size  # bytes added to the bundle

    # 1. Build the new file: everything before .bun, then expanded bundle,
    #    then everything that was after the original bun-LOAD region.
    result = bytearray(original_data[:elf.bun_off])
    result.extend(bundle_final)
    threshold = elf.bun_off + elf.bun_raw_size  # old end of bun-LOAD region
    result.extend(original_data[threshold:])

    # 2. Update e_shoff (section header table shifted forward by delta).
    new_e_shoff = elf.e_shoff + delta
    _p64(result, 0x28, new_e_shoff)

    # 3. Update LOAD program header for .bun: grow filesz/memsz by delta so
    #    pre-.bun sections (.tdata, .data, .got, etc.) stay mapped.
    ph = elf.e_phoff + elf.bun_phdr_idx * PHDR_SIZE
    old_p_filesz = _u64(result, ph + 0x20)
    old_p_memsz  = _u64(result, ph + 0x28)
    _p64(result, ph + 0x20, old_p_filesz + delta)
    _p64(result, ph + 0x28, old_p_memsz + delta)

    # 4. Shift every program header whose p_offset is past the old bundle end.
    for i in range(elf.e_phnum):
        php = elf.e_phoff + i * PHDR_SIZE
        p_offset = _u64(result, php + 0x08)
        if p_offset >= threshold:
            _p64(result, php + 0x08, p_offset + delta)

    # 5. Walk the (now relocated) section header table and shift sh_offset
    #    for every section past the old bundle end.
    for i in range(elf.e_shnum):
        shdr_pos = new_e_shoff + i * SHDR_SIZE
        sh_offset = _u64(result, shdr_pos + 0x18)
        if sh_offset >= threshold:
            _p64(result, shdr_pos + 0x18, sh_offset + delta)

    # 6. Update .bun section header sh_size to the new bun-data vsize.
    bun_shdr = new_e_shoff + elf.bun_shdr_idx * SHDR_SIZE
    _p64(result, bun_shdr + 0x20, new_vsize)

    print(f"  e_shoff:       {elf.e_shoff:,} -> {new_e_shoff:,}")
    print(f"  LOAD p_filesz: {old_p_filesz:,} -> {old_p_filesz + delta:,}")
    return bytes(result)


def _rebuild_elf_unpatch(patched_data: bytes, elf: ELFInfo,
                         padded_bundle: bytes, old_vsize: int,
                         meta: PatchMetadata) -> bytes:
    """Rebuild ELF after removing the patch (mirror of _rebuild_elf_patch)."""
    new_raw_size = len(padded_bundle)
    delta = new_raw_size - elf.bun_raw_size  # negative when shrinking

    result = bytearray(patched_data[:elf.bun_off])
    result.extend(padded_bundle)
    threshold = elf.bun_off + elf.bun_raw_size
    result.extend(patched_data[threshold:])

    new_e_shoff = elf.e_shoff + delta
    _p64(result, 0x28, new_e_shoff)

    ph = elf.e_phoff + elf.bun_phdr_idx * PHDR_SIZE
    old_p_filesz = _u64(result, ph + 0x20)
    old_p_memsz  = _u64(result, ph + 0x28)
    _p64(result, ph + 0x20, old_p_filesz + delta)
    _p64(result, ph + 0x28, old_p_memsz + delta)

    for i in range(elf.e_phnum):
        php = elf.e_phoff + i * PHDR_SIZE
        p_offset = _u64(result, php + 0x08)
        if p_offset >= threshold:
            _p64(result, php + 0x08, p_offset + delta)

    for i in range(elf.e_shnum):
        shdr_pos = new_e_shoff + i * SHDR_SIZE
        sh_offset = _u64(result, shdr_pos + 0x18)
        if sh_offset >= threshold:
            _p64(result, shdr_pos + 0x18, sh_offset + delta)

    bun_shdr = new_e_shoff + elf.bun_shdr_idx * SHDR_SIZE
    _p64(result, bun_shdr + 0x20, old_vsize)

    return bytes(result)


# ━━ Mach-O rebuild helpers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _shift_macho_offsets(result: bytearray, mo: MachOInfo, size_diff: int) -> None:
    """
    Walk all Mach-O load commands and shift file/vm offsets that reference
    data after the __BUN segment by *size_diff* bytes.
    """
    file_thresh  = mo.bun_off + mo.bun_seg_filesize   # old end of __BUN on disk
    vaddr_thresh = mo.bun_seg_vmaddr + mo.bun_seg_vmsize

    def shift32(off: int) -> None:
        v = _u32(result, off)
        if v != 0 and v >= file_thresh:
            _p32(result, off, v + size_diff)

    def shift64_file(off: int) -> None:
        v = _u64(result, off)
        if v != 0 and v >= file_thresh:
            _p64(result, off, v + size_diff)

    def shift64_vaddr(off: int) -> None:
        v = _u64(result, off)
        if v != 0 and v >= vaddr_thresh:
            _p64(result, off, v + size_diff)

    ncmds = _u32(result, 0x10)
    cmd_off = MACHO_HEADER_SIZE

    for _ in range(ncmds):
        if cmd_off + 8 > len(result):
            break
        cmd     = _u32(result, cmd_off)
        cmdsize = _u32(result, cmd_off + 4)

        if cmd == LC_SEGMENT_64:
            segname = result[cmd_off + 8 : cmd_off + 24].rstrip(b"\x00").decode("ascii", errors="replace")
            if segname != MACHO_BUN_SEGNAME:
                fileoff = _u64(result, cmd_off + 0x28)
                if fileoff >= file_thresh:
                    shift64_vaddr(cmd_off + 0x18)           # vmaddr
                    shift64_file(cmd_off + 0x28)            # fileoff
                    # shift sections within this segment
                    nsects = _u32(result, cmd_off + 0x40)
                    so = cmd_off + MACHO_SEGMENT_CMD_SIZE
                    for _ in range(nsects):
                        if so + MACHO_SECTION_SIZE > len(result):
                            break
                        shift64_vaddr(so + 0x20)            # section addr
                        shift32(so + 0x30)                  # section offset
                        so += MACHO_SECTION_SIZE

        elif cmd == LC_SYMTAB:
            shift32(cmd_off + 8)                            # symoff
            shift32(cmd_off + 16)                           # stroff

        elif cmd == LC_DYSYMTAB:
            for fo in (32, 40, 48, 56, 64, 72):
                shift32(cmd_off + fo)

        elif cmd in (LC_CODE_SIGNATURE, LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
                     LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS,
                     LC_LINKER_OPT_HINT, LC_DYLIB_CODE_SIGN_DRS):
            shift32(cmd_off + 8)                            # dataoff

        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            for fo in (8, 16, 24, 32, 40):
                shift32(cmd_off + fo)

        cmd_off += cmdsize


def _rebuild_macho_patch(original_data: bytes, mo: MachOInfo,
                         bundle_final: bytearray, new_vsize: int) -> bytes:
    """
    Rebuild the Mach-O with the modified __BUN section.

    Everything after __BUN (including __LINKEDIT) is shifted forward.
    The code signature is invalidated.
    """
    new_raw_size = len(bundle_final)
    size_diff = new_raw_size - mo.bun_seg_filesize

    # Build new file: [before __BUN][new __BUN data][shifted remainder]
    result = bytearray(original_data[:mo.bun_off])
    result.extend(bundle_final)
    result.extend(original_data[mo.bun_off + mo.bun_seg_filesize :])

    # -- Update __BUN segment command --
    seg = mo.bun_seg_cmd_off
    new_vmsize = _align_up(new_raw_size, MACHO_BLOB_ALIGN)
    _p64(result, seg + 0x20, new_vmsize)                     # vmsize
    _p64(result, seg + 0x30, new_raw_size)                   # filesize

    # -- Update __bun section header --
    if mo.bun_sect_hdr_off:
        _p64(result, mo.bun_sect_hdr_off + 0x28, new_vsize)  # section size

    # -- Shift offsets after __BUN --
    if size_diff != 0:
        _shift_macho_offsets(result, mo, size_diff)

    # -- Invalidate code signature --
    if mo.codesign_cmd_off:
        _p32(result, mo.codesign_cmd_off + 8, 0)             # dataoff
        _p32(result, mo.codesign_cmd_off + 12, 0)            # datasize

    print(f"  __BUN vmsize:  {mo.bun_seg_vmsize:,} -> {new_vmsize:,}")
    return bytes(result)


def _rebuild_macho_unpatch(patched_data: bytes, mo: MachOInfo,
                           padded_bundle: bytes, old_vsize: int,
                           meta: PatchMetadata) -> bytes:
    """Rebuild Mach-O after removing the patch."""
    new_raw_size = len(padded_bundle)
    size_diff = new_raw_size - mo.bun_seg_filesize  # negative

    result = bytearray(patched_data[:mo.bun_off])
    result.extend(padded_bundle)
    result.extend(patched_data[mo.bun_off + mo.bun_seg_filesize :])

    seg = mo.bun_seg_cmd_off
    new_vmsize = _align_up(new_raw_size, MACHO_BLOB_ALIGN)
    _p64(result, seg + 0x20, new_vmsize)
    _p64(result, seg + 0x30, new_raw_size)

    if mo.bun_sect_hdr_off:
        _p64(result, mo.bun_sect_hdr_off + 0x28, old_vsize)

    if size_diff != 0:
        _shift_macho_offsets(result, mo, size_diff)

    if mo.codesign_cmd_off:
        _p32(result, mo.codesign_cmd_off + 8, 0)
        _p32(result, mo.codesign_cmd_off + 12, 0)

    return bytes(result)


# ━━ Rebuild dispatch ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _rebuild_binary(original_data: bytes, fmt: str, info: Any,
                    bundle_final: bytearray, new_vsize: int) -> bytes:
    if fmt == "pe":
        return _rebuild_pe_patch(original_data, info, bundle_final, new_vsize)
    if fmt == "elf":
        return _rebuild_elf_patch(original_data, info, bundle_final, new_vsize)
    if fmt == "macho":
        return _rebuild_macho_patch(original_data, info, bundle_final, new_vsize)
    raise UnsupportedFormat(fmt)


def _rebuild_binary_unpatch(patched_data: bytes, fmt: str, info: Any,
                            padded_bundle: bytes, old_vsize: int,
                            meta: PatchMetadata) -> bytes:
    if fmt == "pe":
        return _rebuild_pe_unpatch(patched_data, info, padded_bundle, old_vsize, meta)
    if fmt == "elf":
        return _rebuild_elf_unpatch(patched_data, info, padded_bundle, old_vsize, meta)
    if fmt == "macho":
        return _rebuild_macho_unpatch(patched_data, info, padded_bundle, old_vsize, meta)
    raise UnsupportedFormat(fmt)


# ━━ patch / unpatch (format-agnostic) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def patch_exe(
    original_data: bytes,
    payload: bytes,
    *,
    anchor: bytes | None = None,
    force: bool = False,
) -> bytes:
    """
    Inject *payload* (raw JS) into the main module of a Bun standalone binary.

    Supports PE, ELF, and Mach-O.  If the binary is already patched,
    ``force=True`` unpatches first, ``force=False`` raises ``AlreadyPatched``.

    Returns the complete patched binary as bytes.
    """
    # guard the payload with semicolons to prevent token fusion
    payload = b";" + payload.rstrip() + b";\n"

    fmt, info, bun_off, vsize, raw_size, file_align = _parse_binary(original_data)

    section_raw = original_data[bun_off : bun_off + raw_size]
    existing = read_patch_metadata(section_raw, raw_size)

    if existing is not None:
        if not force:
            raise AlreadyPatched(
                "Binary is already patched.  Use --force to replace the existing patch."
            )
        print("[patcher] existing patch detected - unpatching first")
        original_data = unpatch_exe(original_data)
        fmt, info, bun_off, vsize, raw_size, file_align = _parse_binary(original_data)

    bundle = bytearray(original_data[bun_off : bun_off + raw_size])
    print(f"  .bun section ({fmt}): off={bun_off:,}  raw_size={raw_size:,}  vsize={vsize:,}")

    length_header = _u64(bundle, 0)
    if length_header != vsize - 8:
        raise BunFormatError(
            f"length header mismatch: header={length_header:#x}, expected={vsize - 8:#x}"
        )

    graph = parse_module_graph(bytes(bundle), vsize)
    main = graph.entries[graph.entry_id]
    contents_sp = main.string_ptrs[SP_CONTENTS]
    bytecode_sp = main.string_ptrs[SP_BYTECODE]
    bc_path_sp  = main.string_ptrs[SP_BYTECODE_PATH]

    print(f"  module graph: {len(graph.entries)} modules, entry={graph.entry_id}")
    print(f"  main source: @{contents_sp.offset:#x} ({contents_sp.length:,} B)  "
          f"bytecode: @{bytecode_sp.offset:#x} ({bytecode_sp.length:,} B)")

    source_start = 8 + contents_sp.offset
    source_end   = source_start + contents_sp.length
    inject_at    = _find_injection_point(bytes(bundle), source_start, source_end, anchor)
    inject_rel   = inject_at - 8
    added = len(payload)

    label = "anchor" if anchor else "prepend"
    print(f"  injection ({label}): offset {inject_at:,} (source+{inject_at - source_start:,})")

    # splice payload into the bundle
    bundle[inject_at:inject_at] = payload
    new_vsize = vsize + added
    print(f"  injected {added:,} bytes, vsize {vsize:,} -> {new_vsize:,}")

    # update length header
    _p64(bundle, 0, new_vsize - 8)

    # update Offsets struct
    offsets_pos = new_vsize - OFFSETS_SIZE - BUN_TRAILER_SIZE

    old_bc = _u64(bundle, offsets_pos)
    _p64(bundle, offsets_pos, old_bc + added)

    old_mod_off = _u32(bundle, offsets_pos + 8)
    if old_mod_off >= inject_rel:
        _p32(bundle, offsets_pos + 8, old_mod_off + added)

    old_argv_off = _u32(bundle, offsets_pos + 20)
    if old_argv_off > 0 and old_argv_off >= inject_rel:
        _p32(bundle, offsets_pos + 20, old_argv_off + added)

    # update module StringPointers
    mod_list_pos = 8 + old_mod_off + (added if old_mod_off >= inject_rel else 0)
    sp_updated = _adjust_string_pointers(bundle, graph, mod_list_pos, inject_rel, added)
    print(f"  updated {sp_updated} StringPointer fields")

    # clear bytecode for main module (force source execution)
    main_epos = mod_list_pos + graph.entry_id * MODULE_ENTRY_SIZE
    for sp_idx in (SP_BYTECODE, SP_BYTECODE_PATH):
        sp_pos = main_epos + sp_idx * 8
        _p32(bundle, sp_pos, 0)
        _p32(bundle, sp_pos + 4, 0)
    print("  cleared main-module bytecode (forcing source execution)")

    # build metadata
    original_image_size = 0
    if fmt == "pe":
        original_image_size = info.size_of_image
    elif fmt == "elf":
        original_image_size = info.e_shoff
    elif fmt == "macho":
        original_image_size = info.linkedit_fileoff

    metadata = PatchMetadata(
        format=fmt,
        inject_offset=inject_at,
        payload_size=added,
        payload_sha256=_sha256_bytes(payload),
        original_vsize=vsize,
        original_raw_size=raw_size,
        original_image_size=original_image_size,
        original_bytecode_sp=[bytecode_sp.offset, bytecode_sp.length],
        original_bytecode_path_sp=[bc_path_sp.offset, bc_path_sp.length],
        patched_at=datetime.now(timezone.utc).isoformat(),
    )

    # trim bundle to new_vsize, then append metadata + re-align
    bundle_trimmed = bytearray(bundle[:new_vsize])
    bundle_final = _embed_metadata(bundle_trimmed, metadata, file_align)
    new_raw_size = len(bundle_final)

    # format-specific rebuild
    result = _rebuild_binary(original_data, fmt, info, bundle_final, new_vsize)

    print(f"  VirtualSize:   {vsize:,} -> {new_vsize:,}")
    print(f"  SizeOfRawData: {raw_size:,} -> {new_raw_size:,}")
    return result


def unpatch_exe(patched_data: bytes) -> bytes:
    """
    Remove a previously applied patch, restoring the original binary.

    Reads the embedded PatchMetadata to know exactly what to reverse.
    """
    fmt, info, bun_off, vsize, raw_size, file_align = _parse_binary(patched_data)

    section_raw = patched_data[bun_off : bun_off + raw_size]
    meta = read_patch_metadata(section_raw, raw_size)
    if meta is None:
        raise NotPatched("No patch metadata found - binary does not appear to be patched.")

    print(f"  found patch metadata (injected {meta.payload_size:,} B at offset {meta.inject_offset:,})")

    bundle = bytearray(section_raw[:vsize])

    # remove the injected payload
    inject_at  = meta.inject_offset
    added      = meta.payload_size
    del bundle[inject_at : inject_at + added]

    old_vsize = meta.original_vsize
    inject_rel = inject_at - 8

    # restore length header
    _p64(bundle, 0, old_vsize - 8)

    # restore Offsets struct
    offsets_pos = old_vsize - OFFSETS_SIZE - BUN_TRAILER_SIZE

    old_bc = _u64(bundle, offsets_pos)
    _p64(bundle, offsets_pos, old_bc - added)

    old_mod_off = _u32(bundle, offsets_pos + 8)
    if old_mod_off >= inject_rel + added:
        _p32(bundle, offsets_pos + 8, old_mod_off - added)

    old_argv_off = _u32(bundle, offsets_pos + 20)
    if old_argv_off > 0 and old_argv_off >= inject_rel + added:
        _p32(bundle, offsets_pos + 20, old_argv_off - added)

    # restore module StringPointers
    restored_mod_off = _u32(bundle, offsets_pos + 8)
    mod_list_pos = 8 + restored_mod_off

    graph = parse_module_graph(bytes(bundle), old_vsize)
    sp_updated = _adjust_string_pointers(bundle, graph, mod_list_pos, inject_rel, -added)
    print(f"  restored {sp_updated} StringPointer fields")

    # restore bytecode SPs for main module
    main_epos = mod_list_pos + graph.entry_id * MODULE_ENTRY_SIZE
    bc_pos   = main_epos + SP_BYTECODE * 8
    bcp_pos  = main_epos + SP_BYTECODE_PATH * 8
    _p32(bundle, bc_pos,     meta.original_bytecode_sp[0])
    _p32(bundle, bc_pos + 4, meta.original_bytecode_sp[1])
    _p32(bundle, bcp_pos,     meta.original_bytecode_path_sp[0])
    _p32(bundle, bcp_pos + 4, meta.original_bytecode_path_sp[1])
    print("  restored main-module bytecode pointers")

    # pad bundle to aligned size
    new_raw_size = _align_up(old_vsize, file_align)
    padded_bundle = bytes(bundle).ljust(new_raw_size, b"\x00")

    # format-specific rebuild
    result = _rebuild_binary_unpatch(patched_data, fmt, info, padded_bundle, old_vsize, meta)

    print(f"  VirtualSize:   {vsize:,} -> {old_vsize:,}")
    print(f"  SizeOfRawData: {raw_size:,} -> {new_raw_size:,}")
    return result


# ━━ extract / info (format-agnostic) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def extract_main_source(data: bytes) -> bytes:
    """Extract the main module's JavaScript source from a Bun standalone binary."""
    _fmt, _info, bun_off, vsize, raw_size, _fa = _parse_binary(data)

    bundle = data[bun_off : bun_off + raw_size]
    graph = parse_module_graph(bundle, vsize)

    main = graph.entries[graph.entry_id]
    sp = main.string_ptrs[SP_CONTENTS]
    return bundle[8 + sp.offset : 8 + sp.offset + sp.length]


def get_binary_info(data: bytes) -> dict:
    """Return a dict of inspection data about a Bun standalone binary."""
    fmt, info, bun_off, vsize, raw_size, _fa = _parse_binary(data)

    bundle = data[bun_off : bun_off + raw_size]
    graph = parse_module_graph(bundle, vsize)

    meta = read_patch_metadata(bundle, raw_size)

    modules = []
    for i, entry in enumerate(graph.entries):
        name_sp = entry.string_ptrs[0]
        name = bundle[8 + name_sp.offset : 8 + name_sp.offset + name_sp.length]
        modules.append({
            "index": i,
            "name": name.rstrip(b"\x00").decode("utf-8", errors="replace"),
            "source_size": entry.string_ptrs[SP_CONTENTS].length,
            "bytecode_size": entry.string_ptrs[SP_BYTECODE].length,
            "format": (["none", "esm", "cjs"][entry.module_format]
                       if entry.module_format < 3 else str(entry.module_format)),
            "is_entry": i == graph.entry_id,
        })

    # format-specific header info
    header_info: dict[str, Any] = {"format": fmt}

    if fmt == "pe":
        pe = info
        header_info["file_alignment"] = pe.file_align
        header_info["section_alignment"] = pe.sect_align
        header_info["size_of_image"] = pe.size_of_image
        header_info["sections"] = [
            {"name": s.name, "vsize": s.vsize, "raw_size": s.raw_size, "raw_off": s.raw_off}
            for s in pe.sections
        ]

    elif fmt == "elf":
        elf = info
        header_info["page_size"] = elf.page_size
        header_info["e_machine"] = elf.e_machine
        header_info["e_phnum"] = elf.e_phnum
        header_info["e_shnum"] = elf.e_shnum
        header_info["e_shoff"] = elf.e_shoff
        header_info["bun_vaddr"] = elf.bun_vaddr

    elif fmt == "macho":
        mo = info
        header_info["cputype"] = mo.cputype
        header_info["ncmds"] = mo.ncmds
        header_info["bun_seg_vmaddr"] = mo.bun_seg_vmaddr
        header_info["bun_seg_vmsize"] = mo.bun_seg_vmsize
        header_info["linkedit_fileoff"] = mo.linkedit_fileoff

    return {
        "header": header_info,
        "bun": {
            "bun_off": bun_off,
            "vsize": vsize,
            "raw_size": raw_size,
            "dead_space": raw_size - vsize,
            "module_count": len(graph.entries),
            "entry_module": graph.entry_id,
            "byte_count": graph.byte_count,
        },
        "modules": modules,
        "patch": asdict(meta) if meta else None,
    }


# ━━ File-level operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def patch_binary(
    input_path: Path,
    inject_path: Path,
    *,
    output_path: Path | None = None,
    anchor: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> Path | None:
    """Read *input_path*, inject JS from *inject_path*, write result."""
    payload = inject_path.read_bytes()
    if not payload.strip():
        raise PatcherError(f"inject file is empty: {inject_path}")

    print(f"\n[patch] {input_path.name} ({input_path.stat().st_size // 1024 // 1024} MB)")
    print(f"[patch] payload: {inject_path.name} ({len(payload):,} B)")

    data = input_path.read_bytes()
    anchor_bytes = anchor.encode() if anchor else None

    patched = patch_exe(data, payload, anchor=anchor_bytes, force=force)

    if dry_run:
        print("[patch] dry run - not writing")
        return None

    dest = output_path or input_path.with_stem(input_path.stem + "_patched")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(patched)
    print(f"[patch] written to {dest}")
    return dest


def unpatch_binary(
    input_path: Path,
    *,
    output_path: Path | None = None,
    dry_run: bool = False,
) -> Path | None:
    """Read *input_path*, remove the existing patch, write result."""
    print(f"\n[unpatch] {input_path.name}")
    data = input_path.read_bytes()
    restored = unpatch_exe(data)

    if dry_run:
        print("[unpatch] dry run - not writing")
        return None

    dest = output_path or input_path.with_stem(input_path.stem + "_unpatched")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(restored)
    print(f"[unpatch] written to {dest}")
    return dest


# ━━ CLI ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USAGE = """\
Bun Standalone Patcher
=========================
Usage:
  bun_patcher.py patch   INPUT --inject FILE [OPTIONS]   Inject JS into a Bun standalone binary
  bun_patcher.py unpatch INPUT [-o OUTPUT]               Remove a previously applied patch
  bun_patcher.py extract INPUT OUTPUT                    Extract the main module's JS source
  bun_patcher.py info    INPUT                           Show binary layout + patch status

Supported formats:  PE (Windows)  |  ELF (Linux)  |  Mach-O (macOS)

Patch options:
  -o, --output PATH     Write to PATH  (default: <name>_patched)
  --anchor PATTERN      Inject after this byte pattern  (default: auto-detect)
  --force               Replace an existing patch instead of erroring
  --dry-run             Parse and log but don't write anything

Examples:
  bun_patcher.py patch  app.exe --inject bootstrap.js -o app_out.exe
  bun_patcher.py patch  claude  --inject hook.js --force
  bun_patcher.py unpatch app_patched -o app_clean
  bun_patcher.py extract claude dumped_source.js
  bun_patcher.py info   claude
"""


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bun_patcher",
        description="Bun Standalone Patcher (PE / ELF / Mach-O)",
        add_help=False,
    )
    parser.add_argument("command", nargs="?", default=None,
                        choices=["patch", "unpatch", "extract", "info"],
                        help="Operation to perform")
    parser.add_argument("positional", nargs="*", default=[])
    parser.add_argument("-o", "--output", type=str, default=None)
    parser.add_argument("--inject", type=str, default=None)
    parser.add_argument("--anchor", type=str, default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")

    opts = parser.parse_args(argv)

    if opts.help or opts.command is None:
        print(USAGE)
        return 0

    if not opts.positional:
        print(f"[error] INPUT path is required for '{opts.command}'")
        return 1

    input_path = Path(opts.positional[0])

    if not input_path.exists():
        print(f"[error] file not found: {input_path}")
        return 1

    try:
        match opts.command:
            case "patch":
                if not opts.inject:
                    print("[error] --inject FILE is required for 'patch'")
                    return 1
                inject_path = Path(opts.inject)
                if not inject_path.exists():
                    print(f"[error] inject file not found: {inject_path}")
                    return 1
                output = Path(opts.output) if opts.output else None
                result = patch_binary(
                    input_path, inject_path,
                    output_path=output,
                    anchor=opts.anchor,
                    force=opts.force,
                    dry_run=opts.dry_run,
                )
                if result and sys.platform in ("linux", "darwin"):
                    mode = result.stat().st_mode
                    if not (mode & 0o111) and sys.stdin.isatty():
                        ans = input("[patch] make executable? [y/N] ").strip().lower()
                        if ans in ("y", "yes"):
                            result.chmod(mode | 0o111)
                            print(f"[patch] marked {result.name} as executable")

            case "unpatch":
                output = Path(opts.output) if opts.output else None
                unpatch_binary(input_path, output_path=output, dry_run=opts.dry_run)

            case "extract":
                if len(opts.positional) < 2:
                    print("[error] extract requires INPUT and OUTPUT paths")
                    return 1
                out_path = Path(opts.positional[1])
                data = input_path.read_bytes()
                source = extract_main_source(data)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(source)
                print(f"[extract] {len(source):,} bytes -> {out_path}")

            case "info":
                data = input_path.read_bytes()
                info = get_binary_info(data)

                hdr = info["header"]
                fmt = hdr["format"]

                print(f"\n{'=' * 60}")
                print(f"  {input_path.name}  [{fmt.upper()}]")
                print(f"{'=' * 60}")

                if fmt == "pe":
                    print(f"\n  PE sections:")
                    print(f"  {'Name':>10}  {'VirtSize':>12}  {'RawSize':>12}  {'RawOffset':>12}")
                    for s in hdr["sections"]:
                        print(f"  {s['name']:>10}  {s['vsize']:>12,}  {s['raw_size']:>12,}  {s['raw_off']:>12,}")
                    print(f"\n  FileAlignment:    {hdr['file_alignment']:,}")
                    print(f"  SectionAlignment: {hdr['section_alignment']:,}")
                    print(f"  SizeOfImage:      {hdr['size_of_image']:,}")

                elif fmt == "elf":
                    print(f"\n  ELF info:")
                    print(f"    e_machine:  {hdr['e_machine']}")
                    print(f"    page_size:  {hdr['page_size']:,}")
                    print(f"    sections:   {hdr['e_shnum']}")
                    print(f"    segments:   {hdr['e_phnum']}")
                    print(f"    e_shoff:    {hdr['e_shoff']:,}")
                    print(f"    bun_vaddr:  {hdr['bun_vaddr']:#x}")

                elif fmt == "macho":
                    print(f"\n  Mach-O info:")
                    print(f"    cputype:         {hdr['cputype']:#x}")
                    print(f"    load commands:   {hdr['ncmds']}")
                    print(f"    __BUN vmaddr:    {hdr['bun_seg_vmaddr']:#x}")
                    print(f"    __BUN vmsize:    {hdr['bun_seg_vmsize']:,}")
                    print(f"    LINKEDIT fileoff:{hdr['linkedit_fileoff']:,}")

                bun = info["bun"]
                print(f"\n  .bun section:")
                print(f"    offset:     {bun['bun_off']:>12,}")
                print(f"    vsize:      {bun['vsize']:>12,}")
                print(f"    raw_size:   {bun['raw_size']:>12,}")
                print(f"    dead space: {bun['dead_space']:>12,} bytes")
                print(f"    modules:    {bun['module_count']}")
                print(f"    byte_count: {bun['byte_count']:>12,}")

                print(f"\n  Modules:")
                for m in info["modules"]:
                    marker = " *" if m["is_entry"] else "  "
                    print(f"  {marker} [{m['index']}] {m['name']}")
                    print(f"       source={m['source_size']:,} B  bytecode={m['bytecode_size']:,} B  fmt={m['format']}")

                patch = info["patch"]
                print(f"\n  Patch status: {'PATCHED' if patch else 'clean (no patch)'}")
                if patch:
                    print(f"    format:      {patch.get('format', 'pe')}")
                    print(f"    injected:    {patch['payload_size']:,} bytes at offset {patch['inject_offset']:,}")
                    print(f"    payload sha: {patch['payload_sha256'][:16]}...")
                    print(f"    patched at:  {patch['patched_at']}")
                    print(f"    orig vsize:  {patch['original_vsize']:,}")

    except PatcherError as exc:
        print(f"\n[error] {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
