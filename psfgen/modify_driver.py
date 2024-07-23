from ctypes import *
from enum import IntEnum
import io
import subprocess
from typing import Optional
import lief
import psexe
import psf


class XMType(IntEnum):
    Music = 0
    SFX = 1

class XMPanningType(IntEnum):
    XM = 0
    S3M = 1

class SongInfoStruct(LittleEndianStructure):
    _fields_ = [
        ("pxm_ptr", c_uint32),
        ("vh_ptr", c_uint32),
        ("vb_ptr", c_uint32),
        ("type", c_int32),
        ("loop", c_int32),
        ("position", c_int32),
        ("panning_type", c_int32),
    ]


def _load_driver() -> lief.ELF.Binary:
    lets_go_gambling_aw_dangit = lief.ELF.ParserConfig()
    lets_go_gambling_aw_dangit.parse_notes = False
    elf: lief.ELF.Binary = lief.ELF.parse("psexe/xmplayer.elf", lets_go_gambling_aw_dangit)
    return elf

def make_psflib(xm: str) -> psf.PSF1:
    subprocess.run(["make", "-C", "psexe", "XM_BUILTIN=true", f"XM={xm}", "clean", "all"], check=True)
    exe = _load_driver()
    with psexe.elf_to_psexe(exe) as p:
        psf1 = psf.PSF1()
        psf1.program = p.read()
    return exe, psf1


def make_minipsf(lib: lief.ELF.Binary, lib_fn: str,
                 type: XMType, loop: bool, position: int, panning_type: XMPanningType):
    psf1 = psf.PSF1()
    psf1.libs.append(lib_fn)

    song_info: lief.ELF.Symbol = lib.get_symbol("song_info")
    assert song_info and song_info.type == lief.ELF.SYMBOL_TYPES.OBJECT, "cannot find song_info"
    assert song_info.size == sizeof(SongInfoStruct), "song_info is not the right size"
    text_addr = song_info.value

    info = SongInfoStruct.from_buffer_copy(lib.get_content_from_virtual_address(text_addr, sizeof(SongInfoStruct)))
    info.type = type
    info.loop = loop
    info.position = position
    info.panning_type = panning_type

    # That's right we're going to manually assemble a PSX-EXE
    info_b = bytes(info)
    psf1.program += psexe.PSXExeHeader(text_addr, len(info_b))
    psf1.program += info_b

    return psf1