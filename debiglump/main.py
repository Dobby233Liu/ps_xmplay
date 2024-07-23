from typing import Any
from equates import FILE_EQUATES
from ctypes import *
import io


class FAT(LittleEndianStructure):
    _fields_ = [
        ("pos", c_int32),
        ("size", c_int32),
    ]

    def read(self, stream: io.BytesIO) -> bytes:
        stream.seek(self.pos)
        return stream.read(self.size)


class BigLump():
    fat: dict[str, FAT]

    def __init__(self, stream: io.BytesIO, equates: list[str]) -> None:
        self.stream = stream
        files_type = FAT * len(equates)
        files = files_type.from_buffer_copy(self.stream.read(sizeof(files_type)))
        self.fat = { equates[i]: files[i] for i in range(len(equates)) }


with open("debiglump/BIGLUMP.BIN", "rb") as bls:
    bl = BigLump(bls, FILE_EQUATES)
    for name, fat in bl.fat.items():
        with open("debiglump/out/" + name, "wb") as f:
            f.write(fat.read(bls))