from ctypes import *
import io
from typing import Optional


class FAT(LittleEndianStructure):
    _fields_ = [
        ("pos", c_int32),
        ("size", c_int32),
    ]

    def read(self, stream: io.BytesIO, size: Optional[int] = None) -> bytes:
        stream.seek(self.pos)
        return stream.read(size if size is not None else self.size)


class BigLump():
    fat: dict[str, FAT]|list[FAT]

    @classmethod
    def from_stream(cls, stream: io.BytesIO, equates: list[str]) -> None:
        self = cls()
        self.stream = stream
        files_type = FAT * len(equates)
        files = files_type.from_buffer_copy(self.stream.read(sizeof(files_type)))
        self.fat = { equates[i]: files[i] for i in range(len(equates)) }
        return self

    @classmethod
    def from_stream_guess_fat_size(cls, stream: io.BytesIO):
        self = cls()
        self.stream = stream
        # the first thing that comes up in the file must be a FAT, so we try to interpret it as such
        first_fat = FAT.from_buffer_copy(self.stream.read(sizeof(FAT)))
        fat_size = first_fat.pos // sizeof(FAT)
        files_type = FAT * fat_size
        self.stream.seek(-sizeof(FAT), 1)
        files = files_type.from_buffer_copy(self.stream.read(sizeof(files_type)))
        assert files[0].pos == first_fat.pos and files[0].size == first_fat.size
        self.fat = list(files)
        return self