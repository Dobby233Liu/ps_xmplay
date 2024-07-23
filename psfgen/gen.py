import json
import modify_driver
import os
import libopenmpt


def main():
    with open("songdata/index.json", "r") as f:
        index = json.load(f)

    xm = {}
    for song_name, info in index.items():
        if xm.get(info["xm"], None) is None:
            xm[info["xm"]] = [None, None, None]

            lib_fn = f"{info["xm"]}.psflib"
            lib_fn2 = f"out/{info["xm"]}.psflib"
            path_pre = f"songdata/{info["xm"]}"
            path_timing = f"songdata/timing/{info["xm"]}.xm"
            with open(path_pre+".xm", "rb") as pxm, open(path_pre+".vh", "rb") as vh, open(path_pre+".vb", "rb") as vb, \
                open(lib_fn2, "wb") as libf:
                lib, lib_psf = modify_driver.make_psflib(pxm, vh, vb)
                lib_psf.write(libf)
                xm[info["xm"]][0] = lib
                xm[info["xm"]][1] = lib_fn

            if os.path.exists(path_timing):
                xm[info["xm"]][2] = libopenmpt.Module(open(path_timing, "rb"))

        song_length = 180
        if (subsong := info.get("rough_xm_subsong", None)) is not None:
            mod = xm[info["xm"]][2]
            mod.subsong = subsong
            mod.repeat_count = 1 # FIXME the song length from libopenmpt doesn't respect this??
            mod.ctl["play.at_end"] = "stop"
            song_length = mod.length

        with open(f"out/{song_name}.minipsf", "wb") as minif:
            loop = info.get("loop", True)
            psf1 = modify_driver.make_minipsf(lib, lib_fn, modify_driver.XMType.Music, loop, info["position"], modify_driver.XMPanningType.XM)
            if song_length:
                psf1.tags["length"] = song_length
            if loop:
                psf1.tags["fade"] = 10
            psf1.write(minif)

if __name__ == "__main__":
    main()