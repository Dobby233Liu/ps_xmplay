# ps_xmplay

Extremely duct-tapey PSF driver and maker kit for SpongeBob SquarePants: SuperSponge.
Possibly applible to other games using the Jason Page XMPlay library.

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
* All data reside in songdata folder, repo comes with SBSPSS data files.
* Root of the folder should contain the pxm/vb/vh's. All filenames should be in lowercase, and the pxm's has to be have the xm extension.
* timing folder should contain \[conv\]'d/original xm files in correspondence to the pxm files, this is used for timing the PSFs.
* /index.json should contain:
```json
{
    "song minipsf filename": {
        "xm": "xm name (used in psflib filename)",
        "position": [int] song start position in the order,
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

You **must** run gen.py in the project root

## Flaws

SBSPSS PSFs are half-broken in DuckStation as of July 2024, I don't really care though - as long as it works in the two
fb2k PSF players.

You will need to tag the PSFs yourself.

This was never supposed for anybody else to use, if you hit any issues, feel free to open an issue and I'll try to help you out.
PRs are also welcome.

## License

For any code and data in this repo that is mine [0-Clause BSD License](LICENSE) applies.

There obviously is a lot of Sony/SN Systems code in this and I don't claim any rights to it.
Original driver specifically is by Jason Page.