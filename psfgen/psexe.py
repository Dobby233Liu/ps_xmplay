import io
import os
import lief
import tempfile
import subprocess
from ctypes import *

_PREFIX = "mipsel-none-elf"
PREFIX = _PREFIX
_PREFIX_GNU = "mipsel-linux-gnu"
if os.name != "nt" and shutil.which(_PREFIX_GNU + "-gcc") is not None:
    PREFIX = _PREFIX_GNU
OBJCOPY = "objcopy"

MAGIC = b"PS-X EXE"



class PSXExeHeader(LittleEndianStructure):
    _fields_ = [
        ("magic", c_char * 8),
        ("text_off", c_uint32), # zeroed
        ("data_off", c_uint32), # zeroed
        ("entrypoint", c_uint32), # where our data starts??
        ("gp_init", c_uint32), # zeroed
        ("text_addr", c_uint32), ("text_size", c_uint32),
        ("data_addr", c_uint32), ("data_size", c_uint32), # zeroed
        ("bss_addr", c_uint32), ("bss_size", c_uint32), # zeroed
        ("stack_addr", c_uint32), # 0x801FFF00
        ("stack_size", c_uint32), # zeroed
        ("padding", c_char * 1992) # zeroed
    ]

    def __init__(self, entrypoint: int, text_addr: int, text_size: int):
        super().__init__()

        self.magic = MAGIC
        self.text_off = 0
        self.data_off = 0
        self.entrypoint = entrypoint
        self.gp_init = 0
        self.text_addr = text_addr
        self.text_size = text_size
        self.data_addr = 0
        self.data_size = 0
        self.bss_addr = 0
        self.bss_size = 0
        self.stack_addr = 0x801FFF00
        self.stack_size = 0
        self.padding = b"\0" * 1992

# This is wholeheartedly a hack
def elf_to_psexe(elf: lief.ELF.Binary) -> io.BytesIO:
    fd, exe_fn = tempfile.mkstemp()

    try:
        elf.write(exe_fn)
        # Here we expect objcopy to overwrite our temp file
        subprocess.run([PREFIX + "-" + OBJCOPY, "-O", "binary", exe_fn], check=True)

        with open(exe_fn, "rb") as exe:
            exe_dat = exe.read()
    finally:
        os.close(fd)
        os.remove(exe_fn)

    assert exe_dat[:len(MAGIC)] == MAGIC

    return io.BytesIO(exe_dat)