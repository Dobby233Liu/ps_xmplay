# ps_xmplay

Extremely duct-tapey PSF driver and maker kit for SpongeBob SquarePants: SuperSponge.
Possibly applible to other games using the Jason Page XMPlay library.

SBSPSS BigLump extractor included as a bonus.

> [!NOTE]
> The following documentation is a best-effort attempt to describe my process.
> It has been 3 days I forgot how I set this up in the first place

## Prerequisites

Software:
* grumpycoders's GCC-based MIPS toolchain.
  - If I went with the inject-song-data-with-LIEF solution I could just include xmplayer.elf and objcopy in the repo,
    but alas, I ended up having to rebuild the driver for every psflib, sorry.
* Nugget SDK (init submodules or clone with --recursive and you should have it)
* Python, tested on 3.12. Install dependencies:
```shell
pip install -r requirements.txt
```
* libopenmpt in system; if you're on Windows, you can also drop the DLLs in psfgen/lib
* VSCode could make development slightly easier.

Data:
* All data reside in a subfolder of the songdata folder, repo comes with SBSPSS data files.
** Change subfolder name in psfgen/gen.py
* Root of the folder should contain the pxm/vb/vh's. All filenames should be in lowercase, and the pxm's has to be have the xm extension.
* timing folder should contain \[conv\]'d/original xm files in correspondence to the pxm files, this is used for timing the PSFs.
* /index.json should contain:
```json
{
    "song minipsf filename": {
        "xm": "xm name (used in psflib filename)",
        "position": [int] position of the order corresponding to the song,
        "rough_xm_subsong": [int optional] subsong in timing xm that roughly corresponds to this song,
        "loop": [boolean optional]
    },
    // and so on
}
```

## Usage

```shell
cd path/to/ps_xmplay
python psfgen/gen.py
```

Output goes in out/ folder

> [!WARNING]
> You **must** run gen.py in the project root

## Flaws

Compatibility with emulators is spotty.
* **OK:** Mednafen (standalone), DuckStation, PCSX-Redux, Highly Experimental
** foo_input_mdfnpsf is broken in main somehow
* **No:** Play! (PsfPlayer)
* **Unknown:** nocash, psxfin

I provide three versions of the library to use. Each has their own flaws.
SBSPSS's xmplay.lib appears to be newer than the SDK 4.6 one,
but has some glaring bugs you can hear. REDriver2's appears to be adapted from
[a version for PS2][1], and at least doesn't have the bug plauging SBSPSS's.

[1]: https://www.psxdev.net/forum/viewtopic.php?f=64&t=358&p=11754#p11754

Other known issues include:
- Timing code is off, so the speed of the playback might not be what you except.
  If you enable XMPLAY_ENABLE_FIXES, there will be a mitigation.
- As Jason Page said in the readme of the PS2 version, samples with a very short
  looping period will be detuned. He said this is related to the ADPCM format,
  so encoding the VAB differently might help?
- E1/E2 works incorrectly. If you use the REDriver2 lib, you can manually enable
  XMPLAY_ENABLE_FIXES in xmplay.c to fix it, which also enables support for the
  finer portamento adjusting commands.
- Not all commands are implemented. XMPLAY_ENABLE_FIXES mode implements some more.
- If a non-looping track doesn't stop properly, the driver will not try to stop it
  by itself.

If a PSF crashes before it even tries to play the song, try running it in PCSX-Redux.
If it's caused by an assertion failure a message should show up in TTY then.
The debugger may or may not be able to help.

You will need to tag the PSFs yourself.

This was never supposed for anybody else to use, if you hit any issues, feel free to
open an issue or ask on the HCS64 Discord server, and I'll try to help you out.
PRs are also welcome.

## License

For any code and data in this repo that is mine [0-Clause BSD License](LICENSE) applies.

There obviously is a lot of Sony/SN Systems code in this and I don't claim any rights to it.
Original driver specifically is by Jason Page.