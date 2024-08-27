import libopenmpt
import glob
from os import path
import json

SONGDATA_DIR = "returntoneverland"

def main():
    index = {}
    use_orig_as_timing = SONGDATA_DIR == "returntoneverland"
    for timing_fn in glob.glob(f"songdata/{SONGDATA_DIR}/{"timing/" if not use_orig_as_timing else ""}*.{"*" if not use_orig_as_timing else "xm"}"):
        if path.splitext(timing_fn)[1] == ".bak":
            continue
        with open(timing_fn, "rb") as timing_f:
            timing_fnn = path.splitext(path.basename(timing_fn))[0]
            timing = libopenmpt.Module(timing_f)
            for i in range(timing.num_subsongs):
                minipsf_fn = timing_fnn + ("_" + str(i) if timing.num_subsongs != 1 else "")
                index[minipsf_fn] = {
                    "xm": timing_fnn,
                    "module_ext": path.splitext(timing_fn)[1][1:],
                    "rough_xm_subsong": i,
                    "loop": True, # till the shelve is ablaze
                    "use_orig_as_timing": use_orig_as_timing
                }
                timing.subsong = i
                index[minipsf_fn]["position"] = timing.current_order
    with open("songdata/" + SONGDATA_DIR + "/index.json", "w", encoding="utf-8") as index_f:
        json.dump(index, index_f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()