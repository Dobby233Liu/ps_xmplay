from lump import GAZ
import itertools


XM_MAGIC = b'Extended Module:'
VAB_MAGIC = b'pBAV'


with open("debiglump/BIGLUMP.BIN", "rb") as bls:
    bl = GAZ.from_stream(bls)

    for id, fat in enumerate(itertools.chain(bl.fat_immediate, bl.fat_streamed)):
        if fat.size == 0: continue
        ext = "bin"
        initial_four = fat.read(bls, len(VAB_MAGIC))
        if initial_four == VAB_MAGIC:
            ext = "vh"
        sequel_twelve = fat.read(bls, len(XM_MAGIC))
        if sequel_twelve == XM_MAGIC:
            ext = "xm"
        empty_bytes_challenge = fat.read(bls, 0x11)
        if len(empty_bytes_challenge) == 0x11 and empty_bytes_challenge[:0x10] == b'\0' * 0x10 and fat.size != 0x40000 and fat.size != 0x20000:
            ext = "likely.vb"
        if True and ext == "bin":
            continue
        with open(f"debiglump/out3/{id}.{ext}", "wb") as f:
            f.write(fat.read(bls))