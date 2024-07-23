from ctypes import *
from enum import IntEnum
import io
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


def change_song(exe: lief.ELF.Binary, pxm: io.BytesIO, vh: io.BytesIO, vb: io.BytesIO,
                       type: XMType, loop: bool, position: int, panning_type: XMPanningType):
    # FIXME: This makes the program refuse to run in any other emulator than Highly Experimental

    songdata_sect: lief.ELF.Section = lief.ELF.Section(".songdata", lief._lief.ELF.SECTION_TYPES.PROGBITS)
    songdata_sect += lief.ELF.SECTION_FLAGS.ALLOC
    songdata_sect.alignment = 8

    sbss: lief.ELF.Section = exe.get_section(".sbss")
    # elf.next_virtual_address is 0 for some reason so
    songdata_sect.virtual_address = sbss.virtual_address + sbss.size

    content = bytearray()
    def align_8():
        nonlocal content
        if len(content) % songdata_sect.alignment != 0:
            content += b"\0" * (songdata_sect.alignment - len(content) % songdata_sect.alignment)
    pxm_addr = songdata_sect.virtual_address + len(content)
    content += pxm.read()
    align_8()
    vh_addr = songdata_sect.virtual_address + len(content)
    content += vh.read()
    align_8()
    vb_addr = songdata_sect.virtual_address + len(content)
    content += vb.read()

    songdata_sect.content = content
    songdata_sect.size = len(content)
    exe.add(songdata_sect, loaded=True)

    exe_header = psexe.PSXExeHeader.from_buffer_copy(exe.get_content_from_virtual_address(0x8000f800, sizeof(psexe.PSXExeHeader)))
    exe_header.text_size += len(content)
    exe.patch_address(0x8000f800, list(bytearray(exe_header)))

    change_song_params(exe, pxm_addr, vh_addr, vb_addr, type, loop, position, panning_type)

def change_song_params(exe: lief.ELF.Binary,
                       pxm_ptr: int, vh_ptr: int, vb_ptr: int,
                       type: XMType, loop: bool, position: int, panning_type: XMPanningType):
    song_info: lief.ELF.Symbol = exe.get_symbol("song_info")
    assert song_info and song_info.type == lief.ELF.SYMBOL_TYPES.OBJECT, "cannot find song_info"
    assert song_info.size == sizeof(SongInfoStruct), "song_info is not the right size"

    song_info_loc = song_info.value - song_info.section.virtual_address
    old_song_info_data = SongInfoStruct.from_buffer_copy(song_info.section.content[song_info_loc:song_info_loc + sizeof(SongInfoStruct)])
    song_info_data = SongInfoStruct(
        pxm_ptr=pxm_ptr or old_song_info_data.pxm_ptr,
        vh_ptr=vh_ptr or old_song_info_data.vh_ptr,
        vb_ptr=vb_ptr or old_song_info_data.vb_ptr,
        type=type or old_song_info_data.type,
        loop=loop is None and old_song_info_data.loop or loop,
        position=position or old_song_info_data.position,
        panning_type=panning_type or old_song_info_data.panning_type
    )
    exe.patch_address(song_info.value, bytearray(song_info_data))


def _load_driver() -> lief.ELF.Binary:
    lets_go_gambling_aw_dangit = lief.ELF.ParserConfig()
    lets_go_gambling_aw_dangit.parse_notes = False
    elf: lief.ELF.Binary = lief.ELF.parse("psexe/xmplayer.elf", lets_go_gambling_aw_dangit)
    return elf

def make_psflib(pxm: io.BytesIO, vh: io.BytesIO, vb: io.BytesIO) -> psf.PSF1:
    exe = _load_driver()
    change_song(exe, pxm, vh, vb, XMType.Music, False, 0, XMPanningType.XM)
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
    skip_ptrs = sizeof(c_uint32) * 3
    text_addr = song_info.value + skip_ptrs

    info_pretrunc = SongInfoStruct()
    info_pretrunc.type = type
    info_pretrunc.loop = loop
    info_pretrunc.position = position
    info_pretrunc.panning_type = panning_type
    text = bytes(info_pretrunc)[skip_ptrs:]

    # That's right we're going to manually assemble one just for the lib
    exe_hdr = psexe.PSXExeHeader(0, text_addr, len(text))
    psf1.program += bytes(exe_hdr)
    psf1.program += text

    return psf1