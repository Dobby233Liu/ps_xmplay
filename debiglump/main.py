from equates import FILE_EQUATES
from lump import BigLump


with open("debiglump/BIGLUMP.BIN", "rb") as bls:
    bl = BigLump.from_stream(bls, FILE_EQUATES)
    for name, fat in bl.fat.items():
        with open("debiglump/out/" + name, "wb") as f:
            f.write(fat.read(bls))