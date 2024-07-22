from ctypes import *
from enum import IntEnum
import lief


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


def change_song_params(exe: lief.ELF.Binary, type: XMType, loop: bool, position: int, panning_type: XMPanningType):
    pass


if __name__ == "__main__":
    import psexe
    import psf

    lets_go_gambling_aw_dangit = lief.ELF.ParserConfig()
    lets_go_gambling_aw_dangit.parse_notes = False
    elf: lief.ELF.Binary = lief.ELF.parse("psexe/xmplayer.elf", lets_go_gambling_aw_dangit)

    song_info: lief.ELF.Symbol = elf.get_symbol("song_info")
    assert song_info and song_info.type == lief.ELF.SYMBOL_TYPES.OBJECT, "cannot find song_info"
    assert song_info.size == sizeof(SongInfoStruct), "song_info is not the right size"
    song_info_sect: lief.ELF.Section = song_info.section
    song_info_loc = song_info.value - song_info_sect.virtual_address

    rodata: lief.ELF.Section = elf.get_section(".rodata")
    newcontent = bytearray(rodata.content)
    pxm_addr = rodata.virtual_address + rodata.size
    with open("psexe/songdata/chapter1.xm", "rb") as f:
        buf = f.read()
        newcontent.extend(buf)
    vh_addr = rodata.virtual_address + rodata.size
    with open("psexe/songdata/chapter1.vh", "rb") as f:
        buf = f.read()
        newcontent.extend(buf)
    vb_addr = rodata.virtual_address + rodata.size
    with open("psexe/songdata/chapter1.vb", "rb") as f:
        buf = f.read()
        newcontent.extend(buf)
    rodata.content = newcontent

    song_info_data = SongInfoStruct(pxm_ptr=pxm_addr, vh_ptr=vh_addr, vb_ptr=vb_addr, type=0, loop=1, position=0, panning_type=0)
    newcontent2 = bytearray(song_info_sect.content)
    newcontent2[song_info_loc:song_info_loc + song_info.size] = song_info_data
    song_info_data.content = newcontent2

    elf.strip()

    import libopenmpt
    song_length = 0
    with open("psexe/songdata/chapter1.xm", "rb") as f:
        mod = libopenmpt.Module(f)
        mod.subsong = 0
        mod.repeat_count = 1 # FIXME the song length from libopenmpt doesn't respect this??
        mod.ctl["play.at_end"] = "stop"
        song_length = mod.length

    with psexe.elf_to_psexe(elf) as p:
        psf = psf.PSF1()
        psf.program = p.read()
        psf.tags["length"] = song_length
        psf.tags["fade"] = 10
        with open("xmplayer.psf", "wb") as psf_out:
            psf.write(psf_out)