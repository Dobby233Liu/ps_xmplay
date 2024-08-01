from lump import BigLump, FAT


XM_MAGIC = b'Extended Module:'
VAB_MAGIC = b'pBAV'
KNOWN_XM_NAMES = ["CHAPTER1", "CHAPTER2", "CHAPTER3", "CHAPTER4", "CHAPTER5", "CHAPTER6", "SB-TITLE", "INGAME"]


with open("debiglump/BIGLUMP.BIN", "rb") as bls:
    bl = BigLump.from_stream_guess_fat_size(bls)

    known_modules: dict[int, tuple[FAT, FAT, FAT]] = {}

    for id, fat in enumerate(bl.fat):
        if fat.read(bls, len(XM_MAGIC)) != XM_MAGIC:
            continue
        # xm -> vb -> vh
        known_modules[id] = (fat, bl.fat[id + 2], bl.fat[id + 1])
        assert known_modules[id][1].read(bls, 4) == VAB_MAGIC

    for (id, (xm, vh, vb)), i in zip(known_modules.items(), range(len(known_modules))):
        outname = KNOWN_XM_NAMES[i]
        with open(f"debiglump/out2/{outname}.xm", "wb") as f:
            f.write(xm.read(bls))
        with open(f"debiglump/out2/{outname}.vh", "wb") as f:
            f.write(vh.read(bls))
        with open(f"debiglump/out2/{outname}.vb", "wb") as f:
            f.write(vb.read(bls))