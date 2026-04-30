import glob
import os
from enum import IntFlag
from io import BufferedReader, BufferedWriter
from os import path
from struct import calcsize, pack, unpack


def unpack_io(reader: BufferedReader, format: str, peek: bool = False) -> tuple:
    data_size = calcsize(format)
    if not peek:
        buffer = reader.read(data_size)
    else:
        buffer = reader.peek(data_size)[:data_size]
    if len(buffer) != data_size:
        if not peek:
            reader.seek(-len(buffer), os.SEEK_CUR)
        raise EOFError()
    return unpack(format, buffer)


def unpack1(format: str, *args, **kwargs):
    data = unpack(format, *args, **kwargs)
    assert len(data) == 1
    return data[0]


def unpack_io1(reader: BufferedReader, format: str, peek: bool = False):
    data = unpack_io(reader, format, peek=peek)
    assert len(data) == 1
    return data[0]


class XM_RowWrittenFieldsFlag(IntFlag):
    packed = 0x80
    note = 0x01
    inst = 0x02
    volc = 0x04
    efft = 0x08
    effp = 0x10


# ported from: https://github.com/OpenDriver2/OpenDriver2Tools/blob/89009f7f4f48f37a886b376292432cdffab4a136/DriverSoundTool/driver_sound.cpp#L181
# slightly more readable, though hardcoded struct sizes are still present
# samples are not restored because they don't matter to us
def decompress_xm(inf: BufferedReader, outf: BufferedWriter):
    outf.write(inf.read(58))
    in_ver = unpack_io1(inf, "<H")
    if in_ver != 0xDDBA:
        print("Not super-packed")
        outf.write(pack("<H", in_ver))
        outf.write(inf.read())
        return

    outf.write(pack("<H", 0x104))  # change version to a standard one
    outf.write(inf.read(8))  # skip
    chnl_pat_bytes = inf.read(calcsize("<HH"))
    num_chnl, num_pat = unpack("<HH", chnl_pat_bytes)
    outf.write(chnl_pat_bytes)
    outf.write(inf.read(336 - inf.tell()))  # skip the remaining header data, we don't need to change them
    print("Unpacking", num_pat, "patterns")

    CHARSIZE = calcsize("<B")
    NO_DATA = pack("<B", XM_RowWrittenFieldsFlag.packed)
    for pat in range(num_pat):
        # copy pattern header
        outf.write(inf.read(5))
        num_rows = unpack_io1(inf, "<h")
        outf.write(pack("<h", num_rows))

        pat_size = unpack_io1(inf, "<h")  # proceed to the pattern data
        if pat_size == 0:
            continue  # nothing to read

        data_start_in = inf.tell()
        new_pat_data_by_row = [b""] * num_rows

        for row in range(num_rows):
            note_per_chnl: list[bytes] = [NO_DATA] * num_chnl

            # instead of simply laying out all channels per row, "super-packed" XM apparently
            # only lays out channels that have note data, in order to save memory
            # read notes of laid out channels
            while (inf.tell() - data_start_in) < pat_size:  # avoid overflow
                chnl = unpack_io1(inf, "<B")
                if chnl == 0xFF:  # end of data
                    break

                # copy note data
                note_byte = inf.read(CHARSIZE)
                note = unpack1("<B", note_byte)
                note_size = 5
                if note & XM_RowWrittenFieldsFlag.packed:
                    note_size = 1
                    note_size += 1 if (note & XM_RowWrittenFieldsFlag.note) else 0
                    note_size += 1 if (note & XM_RowWrittenFieldsFlag.inst) else 0
                    note_size += 1 if (note & XM_RowWrittenFieldsFlag.volc) else 0
                    note_size += 1 if (note & XM_RowWrittenFieldsFlag.efft) else 0
                    note_size += 1 if (note & XM_RowWrittenFieldsFlag.effp) else 0
                note_per_chnl[chnl] = note_byte + inf.read((note_size - 1) * CHARSIZE)

            new_pat_data_by_row[row] = b"".join(note_per_chnl)

        # then write notes of all channels
        new_pat_data = b"".join(new_pat_data_by_row)
        outf.write(pack("<h", len(new_pat_data)))
        outf.write(new_pat_data)

    # copy the remaining data
    outf.write(inf.read())


if __name__ == "__main__":
    import sys
    SONGDATA_DIR = sys.argv[1] if len(sys.argv) > 1 else "nascarheat"

    os.chdir(path.join(path.dirname(path.abspath(__file__)), ".."))
    os.chdir("songdata/" + SONGDATA_DIR)
    os.makedirs("timing", exist_ok=True)

    for fp in glob.iglob("*.xm"):
        fn = path.basename(fp)
        print(fn)
        with open(fp, "rb") as inf, open("timing/" + fn, "wb") as outf:
            decompress_xm(inf, outf)
        print()
