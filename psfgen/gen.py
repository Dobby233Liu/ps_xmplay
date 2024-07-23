import json
import modify_driver
import os
import libopenmpt


def main():
    with open("songdata/index.json", "r") as f:
        index = json.load(f)

    xm = {}
    for song_name, info in index.items():
        print(song_name)

        if xm.get(info["xm"], None) is None:
            xm[info["xm"]] = [None, None, None]

            lib_fn = f"{info["xm"]}.psflib"
            print(lib_fn)
            path_timing = f"songdata/timing/{info["xm"]}.xm"
            with open("out/" + lib_fn, "wb") as libf:
                lib, lib_psf = modify_driver.make_psflib(info["xm"])
                lib_psf.write(libf)
                xm[info["xm"]][0] = lib
                xm[info["xm"]][1] = lib_fn

            if os.path.exists(path_timing):
                xm[info["xm"]][2] = libopenmpt.Module(open(path_timing, "rb"))

        song_length = 180.0
        loop = info.get("loop", True)
        if (subsong := info.get("rough_xm_subsong", None)) is not None:
            mod = xm[info["xm"]][2]
            mod.subsong = subsong
            if loop:
                mod.repeat_count = 1
            else:
                mod.repeat_count = 0
            mod.ctl["play.at_end"] = "stop"
            song_length = mod.estimate_duration() or 180.0

        with open(f"out/{song_name}.minipsf", "wb") as minif:
            psf1 = modify_driver.make_minipsf(lib, lib_fn, modify_driver.XMType.Music, loop, info["position"], modify_driver.XMPanningType.XM)
            if song_length:
                psf1.tags["length"] = song_length
            if loop:
                psf1.tags["fade"] = 10
            psf1.write(minif)

if __name__ == "__main__":
    main()