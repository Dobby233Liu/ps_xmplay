import glob
import os
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


class XM_Note:
    note: int = 0
    inst: int = 0
    volc: int = 0
    efft: int = 0
    effp: int = 0


class XM_RowPackedFlag(IntFlag):
    packed = 0x80
    note = 0x01
    inst = 0x02
    volc = 0x04
    efft = 0x08
    effp = 0x10


# ported from: https://github.com/OpenDriver2/OpenDriver2Tools/blob/89009f7f4f48f37a886b376292432cdffab4a136/DriverSoundTool/driver_sound.cpp#L181
# unreadability is preserved because I don't quite understand what it's doing fully
# samples are not restored because it doesn't matter here
def decompress_xm(inf: BufferedReader, outf: BufferedWriter):
    ver_ptr = 58
    pat_ptr = 336

    inf.seek(ver_ptr)
    in_ver = unpack_io1(inf, "<H")
    inf.seek(0)
    if in_ver != 0xDDBA:
        print("Not super-packed")
        outf.write(inf.read())
        return

    outf.write(inf.read(ver_ptr))
    ver_size = outf.write(pack("<H", 0x104))  # convert XM to standard version
    inf.seek(ver_size, os.SEEK_CUR)
    outf.write(inf.read(pat_ptr - ver_ptr - ver_size))  # until pattern data

    inf.seek(ver_ptr + 10)
    num_chnl, num_pat = unpack_io(inf, "<HH")
    inf.seek(pat_ptr)  # skip other header data since they don't change
    print("Unpacking", num_pat, "patterns")

    for pat in range(num_pat):
        # copy pattern header properties
        outf.write(inf.read(5))
        num_rows = unpack_io1(inf, "<h")
        outf.write(pack("<h", num_rows))

        pat_size = unpack_io1(inf, "<h")  # onto pattern data itself
        final_pat_size_ptr = outf.tell()
        outf.write(pack("<h", pat_size))

        if pat_size == 0:
            continue  # no empty reads

        data_start_in, data_start_out = inf.tell(), outf.tell()

        for row in range(num_rows):
            notes_per_chnl = [XM_Note() for _ in range(num_chnl)]

            # apparently instead of simply laying out all channels per row, "super-packed" XM
            # only lays out channels that have note data?
            # read notes of layed out channels
            while (inf.tell() - data_start_in) < pat_size:  # don't overflow reading
                chnl = unpack_io1(inf, "<B")
                if chnl == 0xFF:  # end of data
                    break

                # unpack note
                note_struct = notes_per_chnl[chnl]
                note = unpack_io1(inf, "<B")
                if note & XM_RowPackedFlag.packed:
                    note_struct.note = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.note else 0
                    note_struct.inst = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.inst else 0
                    note_struct.volc = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.volc else 0
                    note_struct.efft = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.efft else 0
                    note_struct.effp = unpack_io1(inf, "<B") if note & XM_RowPackedFlag.effp else 0
                else:
                    note_struct.note = note
                    note_struct.inst, note_struct.volc, note_struct.efft, note_struct.effp = unpack_io(inf, "<BBBB")

            # then pack notes, this time for all channels
            for chnl in range(num_chnl):
                note_struct = notes_per_chnl[chnl]
                if (
                    note_struct.note > 0
                    and note_struct.inst > 0
                    and note_struct.volc > 0
                    and note_struct.efft > 0
                    and note_struct.effp > 0
                ):
                    # write full note
                    outf.write(
                        pack(
                            "<BBBBB",
                            note_struct.note,
                            note_struct.inst,
                            note_struct.volc,
                            note_struct.efft,
                            note_struct.effp,
                        )
                    )
                else:
                    packed_flag = XM_RowPackedFlag.packed
                    if note_struct.note > 0:
                        packed_flag |= XM_RowPackedFlag.note
                    if note_struct.inst > 0:
                        packed_flag |= XM_RowPackedFlag.inst
                    if note_struct.volc > 0:
                        packed_flag |= XM_RowPackedFlag.volc
                    if note_struct.efft > 0:
                        packed_flag |= XM_RowPackedFlag.efft
                    if note_struct.effp > 0:
                        packed_flag |= XM_RowPackedFlag.effp
                    outf.write(pack("<B", packed_flag))

                    if packed_flag & XM_RowPackedFlag.note:
                        outf.write(pack("<B", note_struct.note))
                    if packed_flag & XM_RowPackedFlag.inst:
                        outf.write(pack("<B", note_struct.inst))
                    if packed_flag & XM_RowPackedFlag.volc:
                        outf.write(pack("<B", note_struct.volc))
                    if packed_flag & XM_RowPackedFlag.efft:
                        outf.write(pack("<B", note_struct.efft))
                    if packed_flag & XM_RowPackedFlag.effp:
                        outf.write(pack("<B", note_struct.effp))

        poke(outf, final_pat_size_ptr, pack("<h", outf.tell() - data_start_out))

    # copy remaining data
    outf.write(inf.read())


if __name__ == "__main__":
    SONGDATA_DIR = "nascarheat"

    os.chdir(path.join(path.dirname(path.abspath(__file__)), ".."))
    os.chdir("songdata/" + SONGDATA_DIR)
    os.makedirs("timing", exist_ok=True)

    for fp in glob.iglob("*.xm"):
        fn = path.basename(fp)
        print(fn)
        with open(fp, "rb") as inf, open("timing/" + fn, "wb") as outf:
            decompress_xm(inf, outf)
        print()
