from ctypes import *
from enum import IntEnum
import subprocess
from typing import Optional, Union
import lief
import psexe
import psf


class XMType(IntEnum):
    Music = 0
    SFX = 1

class XMPanningType(IntEnum):
    XM = 0
    S3M = 1

SONGINFO_VERSION = 1
class SongInfoStruct(LittleEndianStructure):
    _fields_ = [
        ("version", c_int32),
        ("pxm_ptr", c_uint32),
        ("vh_ptr", c_uint32),
        ("vb_ptr", c_uint32),
        ("type", c_int32),
        ("loop", c_int32),
        ("position", c_int32),
        ("panning_type", c_int32),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.version = SONGINFO_VERSION


def _load_driver(xm_dir: str, xm: str) -> lief.ELF.Binary:
    lets_go_gambling_aw_dangit = lief.ELF.ParserConfig()
    lets_go_gambling_aw_dangit.parse_notes = False
    diff_mark = f"{xm_dir}_{xm}".replace('/', '_').replace('.', '_').replace('-', '_')
    elf: lief.ELF.Binary = lief.ELF.parse(f"psexe/xmplayer_{diff_mark}.elf", lets_go_gambling_aw_dangit)
    if elf is None:
        raise Exception("failed to load driver ELF")
    return elf


def _clean_src() -> lief.ELF.Binary:
    subprocess.run(["make", "-C", "psexe", "XM_BUILTIN=true",
                    "clean"], check=True)


def _make_psflib_elf(xm: str, xm_dir: Optional[str] = "retail", xmplay_variant: Optional[str] = "sbspss", worse_timing: Optional[bool] = False) -> lief.ELF.Binary:
    subprocess.run(["make", "-C", "psexe", "XM_BUILTIN=true",
                    f"XMPLAY_VARIANT={xmplay_variant}", f"XMPLAY_WORSE_TIMING=true" if worse_timing else "",
                    f"XM_DIR={xm_dir}", f"XM={xm}"], check=True)
    return _load_driver(xm_dir, xm)

def make_psflib_psf(exe: lief.ELF.Binary):
    with psexe.elf_to_psexe(exe) as p:
        psf1 = psf.PSF1()
        psf1.program = p.read()
    return psf1

def make_psflib(xm: str, xm_dir: Optional[str] = "retail", xmplay_variant: Optional[str] = "sbspss", worse_timing: Optional[bool] = False) -> Union[lief.ELF.Binary, psf.PSF1]:
    exe = _make_psflib_elf(xm, xm_dir, xmplay_variant, worse_timing)
    return exe, make_psflib_psf(exe)


def make_patched_songinfo(exe: lief.ELF.Binary, type: XMType, loop: bool, position: int, panning_type: XMPanningType) \
    -> Union[lief.ELF.Symbol, SongInfoStruct]:
    song_info: lief.ELF.Symbol = exe.get_symbol("song_info")
    assert song_info and song_info.type == lief.ELF.Symbol.TYPE.OBJECT, "cannot find song_info"
    assert song_info.size == sizeof(SongInfoStruct), "song_info is not the right size"

    info_struct = SongInfoStruct.from_buffer_copy(exe.get_content_from_virtual_address(song_info.value, sizeof(SongInfoStruct)))
    assert info_struct.version == SONGINFO_VERSION, "song_info is not version %d" % SONGINFO_VERSION
    info_struct.type = type
    info_struct.loop = loop
    info_struct.position = position
    info_struct.panning_type = panning_type

    return song_info, info_struct

def _make_psf_patch_lib(exe: lief.ELF.Binary,
                 type: XMType, loop: bool, position: int, panning_type: XMPanningType) -> psf.PSF1:
    song_info, info = make_patched_songinfo(exe, type, loop, position, panning_type)
    exe.patch_address(song_info.value, list(bytes(info)))

    return make_psflib_psf(exe)

def make_psf(xm: str,
                 type: XMType, loop: bool, position: int, panning_type: XMPanningType,
                 xm_dir: Optional[str] = "retail", xmplay_variant: Optional[str] = "sbspss",
                 worse_timing: Optional[bool] = False) -> Union[lief.ELF.Binary, psf.PSF1]:
    exe = _make_psflib_elf(xm, xm_dir, xmplay_variant, worse_timing)
    return exe, _make_psf_patch_lib(exe, type, loop, position, panning_type)

def make_minipsf(lib: lief.ELF.Binary, lib_fn: str,
                 type: XMType, loop: bool, position: int, panning_type: XMPanningType):
    psf1 = psf.PSF1()
    psf1.libs.append(lib_fn)

    song_info, info = make_patched_songinfo(lib, type, loop, position, panning_type)
    # That's right we're going to manually assemble a PSX-EXE
    psf1.program += psexe.PSXExeHeader(song_info.value, sizeof(SongInfoStruct))
    psf1.program += bytes(info)

    return psf1