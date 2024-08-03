import json
import modify_driver
import os
import libopenmpt
import lief


SONGDATA_DIR = "songdata/themepark"
XMPLAY_VARIANT = "sbspss"


def main():
    with open(f"{SONGDATA_DIR}/index.json", "r") as f:
        index = json.load(f)

    os.makedirs("out", exist_ok=True)

    xm_ref_count: dict[str, int] = {}
    for song_name, info in index.items():
        xm_ref_count[info["xm"]] = xm_ref_count.get(info["xm"], 0) + 1

    bank_info: list[tuple[lief.ELF.Binary, str, libopenmpt.Module]] = {}
    for song_name, info in index.items():
        making_psf = xm_ref_count[info["xm"]] == 1
        lib = None
        lib_fn = None
        mod = None

        if bank_info.get(info["xm"], None) is None:
            print("")

            mod = None
            path_timing = f"{SONGDATA_DIR}/timing/{info["xm"]}.{info.get("module_ext", "xm")}"

            if not making_psf:
                lib_fn = f"{info["xm"]}.psflib"
                print(lib_fn)
            else:
                print(song_name)

            # TODO: variant setting should not be here
            lib, lib_psf = modify_driver.make_psflib(info["xm"], SONGDATA_DIR, info.get("xmplay_variant", XMPLAY_VARIANT))
            if not making_psf:
                with open("out/" + lib_fn, "wb") as libf:
                    lib_psf.write(libf)

            if os.path.exists(path_timing):
                mod = libopenmpt.Module(open(path_timing, "rb"))
                mod.ctl["play.at_end"] = "stop"

            bank_info[info["xm"]] = (lib, lib_fn, mod)

            print("")
        else:
            lib, lib_fn, mod = bank_info[info["xm"]]

        if not making_psf:
            print(song_name)

        sound_type = modify_driver.XMType.Music

        song_length = info.get("length", None)
        loop = info.get("loop", True)
        if not song_length:
            if mod and (subsong := info.get("rough_xm_subsong", None)) is not None:
                mod.subsong = subsong
                mod.repeat_count = info.get("loop_count", 1) if loop else 0
                song_length = mod.estimate_duration() or song_length
            else:
                song_length = 3.0 * 60

        panning_type: modify_driver.XMPanningType = info.get("panning_type", modify_driver.XMPanningType.XM)

        with open(f"out/{song_name}.{"mini" if not making_psf else ""}psf", "wb") as outf:
            if not making_psf:
                psf1 = modify_driver.make_minipsf(lib, lib_fn, sound_type, loop, info.get("position", 0), panning_type)
            else:
                song_info, info_str = modify_driver.make_patched_songinfo(lib, sound_type, loop, info.get("position", 0), panning_type)
                lib.patch_address(song_info.value, list(bytes(info_str)))
                psf1 = modify_driver.make_psflib_psf(lib)
            psf1.tags["origfilename"] = song_name
            if song_length:
                psf1.tags["length"] = song_length
            psf1.tags["fade"] = info.get("fade", 10) if loop else 0
            psf1.write(outf)

if __name__ == "__main__":
    main()