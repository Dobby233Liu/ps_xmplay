import json
import modify_driver
import os
import libopenmpt
import lief


def main():
    with open("songdata/index.json", "r") as f:
        index = json.load(f)

    bank_info: list[tuple[lief.ELF.Binary, str, libopenmpt.Module]] = {}
    for song_name, info in index.items():
        print(song_name)

        if bank_info.get(info["xm"], None) is None:
            lib = None
            mod = None

            lib_fn = f"{info["xm"]}.psflib"
            print(lib_fn)
            path_timing = f"songdata/timing/{info["xm"]}.xm"
            os.makedirs("out", exist_ok=True)
            with open("out/" + lib_fn, "wb") as libf:
                lib, lib_psf = modify_driver.make_psflib(info["xm"])
                lib_psf.write(libf)

            if os.path.exists(path_timing):
                mod = libopenmpt.Module(open(path_timing, "rb"))

            bank_info[info["xm"]] = (lib, lib_fn, mod)

        song_length = 3.0 * 60
        loop = info.get("loop", True)
        mod = bank_info[info["xm"]][2]
        if (subsong := info.get("rough_xm_subsong", None)) is not None and mod:
            mod.subsong = subsong
            if loop:
                mod.repeat_count = 1
            else:
                mod.repeat_count = 0
            mod.ctl["play.at_end"] = "stop"
            song_length = mod.estimate_duration() or song_length

        with open(f"out/{song_name}.minipsf", "wb") as minif:
            psf1 = modify_driver.make_minipsf(lib, lib_fn, modify_driver.XMType.Music, loop, info["position"], modify_driver.XMPanningType.XM)
            if song_length:
                psf1.tags["length"] = song_length
            if loop:
                psf1.tags["fade"] = 10
            psf1.write(minif)

if __name__ == "__main__":
    main()