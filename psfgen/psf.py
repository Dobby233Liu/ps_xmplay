from abc import abstractmethod
import collections
import enum
import io
from math import floor
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
        if isinstance(value, bool):
            return value and "1" or "0"
        elif key in ["length", "fade"] and not isinstance(value, str):
            if isinstance(value, datetime.timedelta):
                seconds = value.total_seconds()
            elif isinstance(value, float):
                seconds = value
            elif isinstance(value, int):
                seconds = float(value)
            if seconds < 60:
                return f"{seconds:06.3f}"
            elif seconds < 3600:
                minutes = seconds // 60
                seconds -= minutes * 60
                return f"{floor(minutes):02}:{seconds:06.3f}"
            else:
                hours = seconds // 3600
                seconds -= hours * 3600
                minutes = seconds // 60
                seconds -= minutes * 60
                return f"{floor(hours):02}:{floor(minutes):02}:{seconds:06.3f}"

        return str(value)

    def __setitem__(self, key: Any, value: Any) -> None:
        keystr = str(key)
        if keystr.startswith("_") or keystr in ["filedir", "filename", "fileext"]:
            raise KeyError("Reserved tag name")

        return self.data.__setitem__(keystr, self._value_transliterate(value, key))

class PSF():
    _magic = b'PSF'
    _type: PSFType

    libs: list[str]

    program: bytes
    reserved: bytes

    tags: PSFTags[str, str]

    def __init__(self) -> None:
        super().__init__()

        self.libs = []
        self.program = b''
        self.reserved = b''
        self.tags = PSFTags()

    @abstractmethod
    def _build_tags_internal(self: Self) -> None:
        tags = { "utf8": True }

        if len(self.libs) == 1:
            tags["_lib"] = self.libs[0]
        else:
            for i, lib in enumerate(self.libs):
                tags[f"_lib{i + 2}"] = lib

        return tags

    def _build_tags(self: Self) -> str:
        tags = {}
        tags.update({ key: PSFTags._value_transliterate(value) for key, value in self._build_tags_internal().items() })
        tags.update(self.tags)

        if len(tags) == 0:
            return None

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

    def _build_tags_internal(self: Self) -> None:
        ret = super()._build_tags_internal()
        ret.update({ "_refresh": self.refresh_rate })
        return ret