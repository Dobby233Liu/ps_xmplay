import libopenmpt
import glob
from os import path
import json

SONGDATA_DIR = "songdata/prslr"

def main():
    index = {}
    for timing_fn in glob.glob(SONGDATA_DIR + "/timing/*.xm"):
        with open(timing_fn, "rb") as timing_f:
            timing_fnn = path.splitext(path.basename(timing_fn))[0]
            timing = libopenmpt.Module(timing_f)
            only_one_subsong = timing.num_subsongs == 1
            for i in range(timing.num_subsongs):
                minipsf_fn = timing_fnn + ("_" + str(i) if not only_one_subsong else "")
                index[minipsf_fn] = {
                    "xm": timing_fnn,
                    "rough_xm_subsong": i,
                    "loop": True # till the shelve is ablaze
                }
                timing.subsong = i
                index[minipsf_fn]["position"] = timing.current_order
    with open(SONGDATA_DIR + "/index.json", "w", encoding="utf-8") as index_f:
        json.dump(index, index_f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()