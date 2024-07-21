import io
import os
import lief
import tempfile
import subprocess

_PREFIX = "mipsel-none-elf"
PREFIX = _PREFIX
_PREFIX_GNU = "mipsel-linux-gnu"
if os.name != "nt" and shutil.which(_PREFIX_GNU + "-gcc") is not None:
    PREFIX = _PREFIX_GNU
OBJCOPY = "objcopy"

PSX_EXE_MAGIC = b"PS-X EXE"

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

    assert exe_dat[:len(PSX_EXE_MAGIC)] == PSX_EXE_MAGIC

    return io.BytesIO(exe_dat)