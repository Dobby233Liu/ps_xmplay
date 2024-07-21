from abc import abstractmethod
import collections
import enum
import io
import struct
from typing import Self, Any, Optional
import zlib
import datetime


class PSFType(enum.IntEnum):
    PSF1 = 0x01
    PSF2 = 0x02
    SSF = 0x11
    DSF = 0x12

class PSFTags(collections.UserDict):
    @staticmethod
    def _value_transliterate(value: Any, key: Optional[Any] = None) -> str:
        a = 1
        if isinstance(value, bool):
            return value and "1" or "0"
        elif key in ["length", "fade"]:
            if isinstance(value, datetime.timedelta):
                seconds = value.seconds + value.days * 86400
                if seconds < 60:
                    return f"{seconds:02}.{value.microseconds // 100000:02}"
                if seconds < 3600:
                    return f"{seconds // 60 % 60:02}:{seconds % 60:02}.{value.microseconds // 100000:02}"
                return f"{seconds // 3600:02}:{seconds // 60 % 60:02}:{seconds % 60:02}.{value.microseconds // 100000:02}"

        return str(value)

    def __setitem__(self, key: Any, value: Any) -> None:
        keystr = str(key)
        if keystr in ["filedir", "filename", "fileext"]:
            raise KeyError("Reserved tag name")

        return self.data.__setitem__(keystr, self._value_transliterate(value, key))

class PSF():
    _magic = b'PSF'
    _type: PSFType

    program: bytes
    reserved: bytes

    tags: PSFTags[str, str]

    def __init__(self) -> None:
        super().__init__()

        self.program = b''
        self.reserved = b''
        self.tags = PSFTags()

    @abstractmethod
    def _build_tags_extension(self: Self, tags: PSFTags[str, str]) -> None:
        pass

    def _build_tags(self: Self) -> str:
        tags = self.tags.copy()
        self._build_tags_extension(tags)

        if len(tags) == 0:
            return None

        tags["utf8"] = True

        return "\n".join(
            "\n".join(
                f"{key}={line}" for line in value.splitlines(False)
            )
            for key, value in tags.items()
        )

    def write(self: Self, of: io.BytesIO) -> None:
        of.write(self._magic + struct.pack("<B", self._type))

        of.write(struct.pack("<L", len(self.reserved)))

        compressed_program = zlib.compress(self.program, 9)
        of.write(struct.pack("<L", len(compressed_program)))
        of.write(struct.pack("<L", zlib.crc32(compressed_program)))

        of.write(self.reserved)
        of.write(compressed_program)

        tags = self._build_tags()
        if tags:
            tags = tags.encode("utf-8")
            of.write(b"[TAG]")
            of.write(tags)


class PSF1RefreshRates(enum.IntEnum):
    PAL = 50
    NTSC = 60

class PSF1(PSF):
    _type = PSFType.PSF1
    refresh_rate: PSF1RefreshRates

    def __init__(self) -> None:
        super().__init__()

        self.refresh_rate = PSF1RefreshRates.NTSC

    def _build_tags_extension(self: Self, tags: PSFTags[str, str]) -> None:
        tags["_refresh"] = self.refresh_rate


if __name__ == "__main__":
    import psexe
    import lief

    lets_go_gambling_aw_dangit = lief.ELF.ParserConfig()
    lets_go_gambling_aw_dangit.parse_notes = False
    elf: lief.ELF.Binary = lief.ELF.parse("psexe/xmplayer.elf", lets_go_gambling_aw_dangit)
    elf.strip()

    with psexe.elf_to_psexe(elf) as p:
        psf1 = PSF1()
        psf1.program = p.read()
        with open("xmplayer.psf", "wb") as psf_out:
            psf1.write(psf_out)