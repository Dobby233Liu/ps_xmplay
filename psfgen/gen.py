import json
import modify_driver
import os
from os import path
import libopenmpt
import lief
import sys


SONGDATA_DIR = sys.argv[1] if len(sys.argv) > 1 else "test"
XMPLAY_VARIANT = sys.argv[2] if len(sys.argv) > 2 else "redriver2"
LICENSES = [
    ("nugget", "psexe/nugget/LICENSE"),
    ("REDriver2", "psexe/xmplay/src/LICENSE.REDriver2") if XMPLAY_VARIANT == "redriver2" else (None, None)
]
# TODO: make these a part of the global set config
USE_ZOPFLI = sys.argv[3] == "1" if len(sys.argv) > 3 else False
XMPLAY_ENABLE_FIXES = True


# cd to script directory / .. because otherwise everything will explode
# (i don't want to fix it)
os.chdir(path.join(path.dirname(path.abspath(__file__)), ".."))


def main():
    modify_driver._clean_src()

    with open(f"songdata/{SONGDATA_DIR}/index.json", "r") as f:
        index = json.load(f)

    outdir = f"out/{SONGDATA_DIR}"
    os.makedirs(outdir, exist_ok=True)

    xm_ref_count: dict[str, int] = {}
    for song_name, info in index.items():
        xm_ref_count[info["xm"]] = xm_ref_count.get(info["xm"], 0) + 1

    bank_info: dict[str, tuple[lief.ELF.Binary, str, libopenmpt.Module]] = {}
    for song_name, info in index.items():
        assert info["xm"]

        making_psf = xm_ref_count[info["xm"]] == 1
        lib = None
        lib_fn = None
        mod = None

        if bank_info.get(info["xm"], None) is None:
            print("")

            mod = None
            path_timing = f"songdata/{SONGDATA_DIR}/timing/{info["xm"]}.{info.get("module_ext", "xm")}"
            if info.get("use_orig_as_timing", False):
                path_timing = f"songdata/{SONGDATA_DIR}/{info["xm"]}.xm"

            if not making_psf:
                lib_fn = f"{info["xm"]}.psflib"
                print(lib_fn)
            else:
                print(song_name)

            lib = modify_driver._make_psflib_elf(info["xm"], SONGDATA_DIR,
                                                # TODO: variant should not be located there in info json
                                                 info.get("xmplay_variant", XMPLAY_VARIANT),
                                                 XMPLAY_ENABLE_FIXES
                                                )
            if not making_psf:
                lib_psf = modify_driver.make_psflib_psf(lib)
                with open(f"{outdir}/{lib_fn}", "wb") as libf:
                    lib_psf.write(libf, use_zopfli=USE_ZOPFLI)

            if path.exists(path_timing):
                with open(path_timing, "rb") as mod_f:
                    mod = libopenmpt.Module(mod_f, {
                        "load.skip_samples": True,
                        "play.at_end": "stop"
                    })

            bank_info[info["xm"]] = (lib, lib_fn, mod)

            print("")
        else:
            lib, lib_fn, mod = bank_info[info["xm"]]

        if not making_psf:
            print(song_name)

        sound_type = modify_driver.XMType.Music

        song_length = info.get("length", None)
        loop_option = info.get("loop", True)
        loop_count = info.get("loop_count", 1)
        fade = info.get("fade", 10)
        loop = True
        if loop_option == "force_stop":
            loop = False
        elif not loop_option:
            loop_count = 0
            fade = 0
        if not song_length:
            if mod and (subsong := info.get("rough_xm_subsong", None)) is not None:
                mod.subsong = subsong
                mod.repeat_count = loop_count if loop else 0
                song_length = mod.estimate_duration() or song_length
            else:
                song_length = 3.0 * 60

        panning_type: modify_driver.XMPanningType = info.get("panning_type", modify_driver.XMPanningType.XM)

        with open(f"{outdir}/{song_name}.{"mini" if not making_psf else ""}psf", "wb") as outf:
            if not making_psf:
                psf1 = modify_driver.make_minipsf(lib, lib_fn, sound_type, loop, info.get("position", 0), panning_type)
            else:
                psf1 = modify_driver._make_psf_patch_lib(lib, sound_type, loop, info.get("position", 0), panning_type)
            if song_length:
                psf1.tags["length"] = song_length
            psf1.tags["fade"] = fade if loop else 0
            psf1.tags["psfby"] = "ps_xmplay psfgen"
            #psf1.tags["origfilename"] = song_name
            psf1.write(outf, use_zopfli=USE_ZOPFLI)

    with open(f"{outdir}/!PSFDRV_LICENSES.txt", "w") as f:
        for (sw_name, license_fp) in LICENSES:
            if license_fp is None: continue
            print(sw_name, file=f)
            print("-"*80, file=f)
            with open(license_fp, "r") as f2:
                print(f2.read().strip(), file=f)
            print(file=f)

if __name__ == "__main__":
    main()