import glob
import os
from ctypes import LittleEndianStructure, c_uint8
from enum import IntFlag
from io import BufferedReader, BufferedWriter
from os import path
from struct import calcsize, pack, unpack


def poke(writer: BufferedWriter, pos: int, data: bytes):
    old_pos = writer.tell()
    writer.seek(pos)
    res = writer.write(data)
    writer.seek(old_pos)
    return res


def unpack_io(reader: BufferedReader, format: str, peek: bool = False) -> tuple:
    data_size = calcsize(format)
    if not peek:
        buffer = reader.read(data_size)
    else:
        buffer = reader.peek(data_size)
    if len(buffer) != data_size:
        if not peek:
            reader.seek(-len(buffer), os.SEEK_CUR)
        raise EOFError()
    return unpack(format, buffer)


def unpack_io1(reader: BufferedReader, format: str, peek: bool = False):
    data = unpack_io(reader, format, peek=peek)
    assert len(data) == 1
    return data[0]


class XM_Note(LittleEndianStructure):
    _pack_ = 0
    _fields_ = [
        ("note", c_uint8),
        ("inst", c_uint8),
        ("volc", c_uint8),
        ("efft", c_uint8),
        ("effp", c_uint8),
    ]


class XM_RowPackedFlag(IntFlag):
    packed = 0x80
    note = 0x01
    inst = 0x02
    volc = 0x04
    efft = 0x08
    effp = 0x10


# ported from: https://github.com/OpenDriver2/OpenDriver2Tools/blob/89009f7f4f48f37a886b376292432cdffab4a136/DriverSoundTool/driver_sound.cpp#L181
# unreadability is preserved because idk what it's doing
# samples are not restored because it doesn't matter here
def decompress_xm(inf: BufferedReader, outf: BufferedWriter):
    inf.seek(58)
    in_ver = unpack_io1(inf, "<H")
    inf.seek(0)

    if in_ver != 0xDDBA:
        print("This is a non-superpacked XM")
        outf.write(inf.read())
        return

    outf.write(inf.read(336))  # go to patterns
    poke(outf, 58, pack("<H", 0x104))  # convert XM to standard version

    inf.seek(68)
    num_chnl, num_pat = unpack_io(inf, "<HH")
    inf.seek(264, os.SEEK_CUR)  # skip other header data since it's not changed
    print("Unpacking", num_pat, "patterns")

    for i in range(num_pat):
        # copy pattern header properties
        outf.write(inf.read(5))
        pat_len = unpack_io1(inf, "<h")
        outf.write(pack("<h", pat_len))

        pat_size = unpack_io1(inf, "<h")  # onto pattern data itself
        out_pat_size_start = outf.tell()
        outf.write(pack("<h", pat_size))

        if pat_size == 0:
            continue  # no empty reads

        pat_start_in, pat_start_out = inf.tell(), outf.tell()
        for r in range(pat_len):
            row_notes = (XM_Note * 32)()  # more for safety

            while True:
                # don't overflow reading
                if (inf.tell() - pat_start_in) >= pat_size:
                    break

                patdat = unpack_io1(inf, "<B")
                if patdat == 0xFF:  # channel end
                    break

                xmnote = row_notes[patdat]

                # unpack it fully
                note = unpack_io1(inf, "<B")
                if note & XM_RowPackedFlag.packed:
                    xmnote.note = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.note else 0
                    xmnote.inst = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.inst else 0
                    xmnote.volc = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.volc else 0
                    xmnote.efft = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.efft else 0
                    xmnote.effp = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.effp else 0
                else:
                    xmnote.note = note
                    xmnote.inst, xmnote.volc, xmnote.efft, xmnote.effp = unpack_io(inf, "<BBBB")

            # pack notes again
            for c in range(num_chnl):
                xmnote: XM_Note = row_notes[c]

                if xmnote.note > 0 and xmnote.inst > 0 and xmnote.volc > 0 and xmnote.efft > 0 and xmnote.effp > 0:
                    # write full note
                    outf.write(bytes(xmnote))
                else:
                    packed_flag_start = outf.tell()
                    outf.write(b"\x00")

                    packed_flag = XM_RowPackedFlag.packed
                    if xmnote.note > 0:
                        packed_flag |= XM_RowPackedFlag.note
                        outf.write(pack("<B", xmnote.note))
                    if xmnote.inst > 0:
                        packed_flag |= XM_RowPackedFlag.inst
                        outf.write(pack("<B", xmnote.inst))
                    if xmnote.volc > 0:
                        packed_flag |= XM_RowPackedFlag.volc
                        outf.write(pack("<B", xmnote.volc))
                    if xmnote.efft > 0:
                        packed_flag |= XM_RowPackedFlag.efft
                        outf.write(pack("<B", xmnote.efft))
                    if xmnote.effp > 0:
                        packed_flag |= XM_RowPackedFlag.effp
                        outf.write(pack("<B", xmnote.effp))

                    poke(outf, packed_flag_start, pack("<B", packed_flag))

        poke(outf, out_pat_size_start, pack("<h", outf.tell() - pat_start_out))

    # copy remaining data
    outf.write(inf.read())


SONGDATA_DIR = "nascarheat"

if __name__ == "__main__":
    os.chdir(path.join(path.dirname(path.abspath(__file__)), ".."))
    os.chdir("songdata/" + SONGDATA_DIR)
    os.makedirs("timing", exist_ok=True)

    for fp in glob.iglob("*.xm"):
        fn = path.basename(fp)
        print(fn)
        with open(fp, "rb") as inf, open("timing/" + fn, "wb") as outf:
            decompress_xm(inf, outf)
        print()
