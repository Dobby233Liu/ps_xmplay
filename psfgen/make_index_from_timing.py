import glob
import json
from os import path

import libopenmpt

SONGDATA_DIR = "honeyhunt"


def main():
    index = {}
    use_orig_as_timing = SONGDATA_DIR in ["returntoneverland", "honeyhunt"]
    for timing_fn in glob.glob(
        f"songdata/{SONGDATA_DIR}/{'timing/' if not use_orig_as_timing else ''}*.{'*' if not use_orig_as_timing else 'xm'}"
    ):
        if path.splitext(timing_fn)[1] == ".bak":
            continue
        with open(timing_fn, "rb") as timing_f:
            timing_fnn = path.splitext(path.basename(timing_fn))[0]
            timing_fnn2 = timing_fnn
            # torment = glob.glob(f"out/{SONGDATA_DIR}/*{timing_fnn}.psf")
            # if len(torment) > 0:
            #    timing_fnn2 = path.splitext(path.basename(torment[0]))[0]
            timing = libopenmpt.Module(timing_f)
            for i in range(timing.num_subsongs):
                minipsf_fn = timing_fnn2 + ("_" + str(i) if timing.num_subsongs != 1 else "")
                index[minipsf_fn] = {
                    "xm": timing_fnn,
                    "module_ext": path.splitext(timing_fn)[1][1:],
                    "rough_xm_subsong": i,
                    "loop": True,  # till the shelve is ablaze
                    "use_orig_as_timing": use_orig_as_timing,
                }
                timing.subsong = i
                index[minipsf_fn]["position"] = timing.current_order
    with open("songdata/" + SONGDATA_DIR + "/index.json", "w", encoding="utf-8") as index_f:
        json.dump(index, index_f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
