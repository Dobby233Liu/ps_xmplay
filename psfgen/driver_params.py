from ctypes import *

class SongInfoStruct(Structure):
    _fields_ = [
        ("pxm_ptr", POINTER(c_ubyte)),
        ("vh_ptr", POINTER(c_ubyte)),
        ("vb_ptr", POINTER(c_ubyte)),
        ("type", c_int),
        ("loop", c_int),
        ("position", c_int),
        ("panning_type", c_int),
    ]