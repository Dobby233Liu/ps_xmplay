from ctypes import *
import enum
import os
import io
from typing import Any, Self
import types

"""
Very incomplete libopenmpt interop
"""

LIB = None
try:
    if os.name == "nt":
        LIB = CDLL("libopenmpt.dll")
    else:
        LIB = CDLL("libopenmpt.so")
except OSError:
    if os.name == "nt":
        LIB = CDLL(os.path.join(os.path.dirname(__file__), "lib/libopenmpt.dll"))
if not LIB:
    raise OSError("Please install libopenmpt")


LOG_CB = CFUNCTYPE(None, c_char_p, c_void_p)

class ErrorFuncResult(enum.IntEnum):
    DoNothing = 0
    Log = 1 << 0
    Store = 1 << 1
    Default = Log | Store

ERR_CB = CFUNCTYPE(c_int, c_int, c_void_p)


openmpt_stream_read_func = CFUNCTYPE(c_size_t, c_void_p, c_void_p, c_size_t)
openmpt_stream_seek_func = CFUNCTYPE(c_int, c_void_p, c_int64, c_int)
openmpt_stream_tell_proc = CFUNCTYPE(c_int64, c_void_p)

class _StreamCallbacks(Structure):
    _fields_ = [
        ("_read", openmpt_stream_read_func),
        ("_seek", openmpt_stream_seek_func),
        ("_tell", openmpt_stream_tell_proc)
    ]

    _stream: io.BytesIO

    def __init__(self) -> None:
        super().__init__()

        self.hash = c_int(id(self))
        self.hash_ptr = pointer(self.hash)

        self._stream = None

        self._read = openmpt_stream_read_func(self._read_impl)
        self._seek = openmpt_stream_seek_func(self._seek_impl)
        self._tell = openmpt_stream_tell_proc(self._tell_impl)

    def _read_impl(self: Self, ptr: int, dst: c_void_p, size: c_size_t) -> c_size_t:
        if cast(ptr, c_void_p).value != cast(self.hash_ptr, c_void_p).value:
            raise ValueError("Invalid stream pointer")

        return self._stream.readinto((c_char * size).from_address(dst))

    def _seek_impl(self: Self, ptr: int, pos: c_int64, whence: c_int) -> c_int:
        if cast(ptr, c_void_p).value != cast(self.hash_ptr, c_void_p).value:
            raise ValueError("Invalid stream pointer")

        try:
            self._stream.seek(pos, whence)
        except OSError:
            return -1
        return 0

    def _tell_impl(self: Self, ptr: int) -> c_int64:
        if cast(ptr, c_void_p).value != cast(self.hash_ptr, c_void_p).value:
            raise ValueError("Invalid stream pointer")

        try:
            return self._stream.tell()
        except OSError:
            return -1

    @classmethod
    def from_stream(cls, stream: io.BytesIO):
        self = cls()

        self._stream = stream

        return self

    def __del__(self):
        if self._stream is not None and not self._stream.closed:
            self._stream.close()


c_openmpt_module = c_void_p # it's some kind of struct alright

class _InitialCtl(Structure):
    _fields_ = [
        ("ctl", c_char_p),
        ("value", c_char_p),
    ]

LIB.openmpt_module_create2.argtypes = [
    _StreamCallbacks, c_void_p,
    LOG_CB, c_void_p,
    ERR_CB, c_void_p,
    POINTER(c_int), POINTER(c_char_p),
    POINTER(_InitialCtl)
]
LIB.openmpt_module_create2.restype = c_openmpt_module

LIB.openmpt_module_destroy.argtypes = [c_openmpt_module]


LIB.openmpt_free_string.argtypes = [c_char_p]
LIB.openmpt_module_error_clear.argtypes = [c_openmpt_module]

class OpenMPTException(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


LIB.openmpt_module_get_current_order.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_current_order.restype = c_int32
LIB.openmpt_module_get_current_row.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_current_row.restype = c_int32
LIB.openmpt_module_set_position_order_row.argtypes = [c_openmpt_module, c_int32, c_int32]
LIB.openmpt_module_set_position_order_row.restype = c_double


LIB.openmpt_module_get_duration_seconds.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_duration_seconds.restype = c_double


LIB.openmpt_module_ctl_get.argtypes = [c_openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get.restype = c_char_p
LIB.openmpt_module_ctl_get_boolean.argtypes = [c_openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_boolean.restype = c_bool
LIB.openmpt_module_ctl_get_floatingpoint.argtypes = [c_openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_floatingpoint.restype = c_double
LIB.openmpt_module_ctl_get_integer.argtypes = [c_openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_integer.restype = c_int64
LIB.openmpt_module_ctl_get_text.argtypes = [c_openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_text.restype = c_char_p

LIB.openmpt_free_string.argtypes = [c_char_p]

LIB.openmpt_module_ctl_set_boolean.argtypes = [c_openmpt_module, c_char_p, c_bool]
LIB.openmpt_module_ctl_set_boolean.restype = c_bool
LIB.openmpt_module_ctl_set_floatingpoint.argtypes = [c_openmpt_module, c_char_p, c_double]
LIB.openmpt_module_ctl_set_floatingpoint.restype = c_bool
LIB.openmpt_module_ctl_set_integer.argtypes = [c_openmpt_module, c_char_p, c_int64]
LIB.openmpt_module_ctl_set_integer.restype = c_bool
LIB.openmpt_module_ctl_set_text.argtypes = [c_openmpt_module, c_char_p, c_char_p]
LIB.openmpt_module_ctl_set_text.restype = c_bool


LIB.openmpt_module_get_num_subsongs.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_num_subsongs.restype = c_int32
LIB.openmpt_module_get_selected_subsong.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_selected_subsong.restype = c_int32
LIB.openmpt_module_select_subsong.argtypes = [c_openmpt_module, c_int32]
LIB.openmpt_module_select_subsong.restype = c_bool


LIB.openmpt_module_get_repeat_count.argtypes = [c_openmpt_module]
LIB.openmpt_module_get_repeat_count.restype = c_int32
LIB.openmpt_module_set_repeat_count.argtypes = [c_openmpt_module, c_int32]
LIB.openmpt_module_set_repeat_count.restype = c_bool


LIB.openmpt_module_read_mono.argtypes = [c_openmpt_module, c_int32, c_size_t, POINTER(c_int16)]
LIB.openmpt_module_read_mono.restype = c_size_t


class Module():
    class _Ctl():
        def __init__(self, module: "Module", *args: Any, **kwargs: Any) -> None:
            self._module = module

        def __getitem__(self, key: str) -> Any:
            item_type = None

            match key:
                case "load.skip_samples": item_type = "boolean"
                case "play.at_end": item_type = "text"

            if item_type is None: # ffs do i have to guess the ctl type
                raise NotImplementedError()

            value = None
            match item_type:
                case "boolean": value = LIB.openmpt_module_ctl_get_boolean(self._module._module, key.encode("utf-8"))
                case "floatingpoint": value = LIB.openmpt_module_ctl_get_floatingpoint(self._module._module, key.encode("utf-8"))
                case "integer": value = LIB.openmpt_module_ctl_get_integer(self._module._module, key.encode("utf-8"))
                case "text": value = LIB.openmpt_module_ctl_get_text(self._module._module, key.encode("utf-8")).decode("utf-8")
            if value is None:
                self._module._raise_last_error()
            return value

        def __setitem__(self, key: str, value: str|float|int|bool) -> None:
            ok = False
            if isinstance(value, str):
                ok = LIB.openmpt_module_ctl_set_text(self._module._module, key.encode("utf-8"), value.encode("utf-8"))
            elif isinstance(value, float):
                ok = LIB.openmpt_module_ctl_set_floatingpoint(self._module._module, key.encode("utf-8"), value)
            elif isinstance(value, bool):
                ok = LIB.openmpt_module_ctl_set_boolean(self._module._module, key.encode("utf-8"), value)
            elif isinstance(value, int):
                ok = LIB.openmpt_module_ctl_set_integer(self._module._module, key.encode("utf-8"), value)
            else:
                raise TypeError(f"Unsupported type {type(value)}")
            if not ok:
                self._module._raise_last_error()

    @classmethod
    def _build_initial_ctls(cls, ctls: dict[str, str|float|int|bool]) -> c_void_p:
        initial_ctls = (_InitialCtl * (len(ctls) + 1))()

        for i, (ctl, value) in enumerate(ctls.items()):
            initial_ctls[i].ctl = ctl.encode("utf-8")
            if value is not None:
                value_str = str(value)
                if isinstance(value, bool):
                    value_str = value and "1" or "0"
                initial_ctls[i].value = value_str.encode("utf-8")
            else:
                initial_ctls[i].value = None

        initial_ctls[-1].ctl = None
        initial_ctls[-1].value = None

        return pointer(initial_ctls)


    def __init__(self, stream: io.BytesIO, initial_ctls: dict[str, str|float|int|bool] = None) -> None:
        self._last_error = c_int()
        self._last_error_msg = c_char_p()
        self._hash_ptr = pointer(c_int(id(self)))
        self._stream_cb = _StreamCallbacks.from_stream(stream)
        self._log_cb = LOG_CB(self._log)
        self._err_cb = ERR_CB(self._err)

        self._module = None
        self._module = LIB.openmpt_module_create2(
            self._stream_cb, self._stream_cb.hash_ptr,
            self._log_cb, self._hash_ptr, self._err_cb, self._hash_ptr,
            pointer(self._last_error), pointer(self._last_error_msg),
            cast(self._build_initial_ctls(initial_ctls), POINTER(_InitialCtl)) if initial_ctls is not None else None
        )
        if self._module is None:
            self._raise_last_error()

        self.ctl = self._Ctl(self)

    def __del__(self):
        if self._module is not None:
            LIB.openmpt_module_destroy(self._module)

    def _log(self, message: c_char_p, user: c_void_p):
        print(message.decode("utf-8"))

    def _err(self, code: c_int, user: c_void_p) -> c_int:
        # TODO
        return ErrorFuncResult.Default.value

    def _raise_last_error(self):
        code = self._last_error.value
        assert code is not None and code != 0
        msg = None
        if self._last_error_msg.value is not None:
            msg = self._last_error_msg.value.decode("utf-8")
            LIB.openmpt_free_string(self._last_error_msg)
        if self._module is not None:
            LIB.openmpt_module_error_clear(self._module)
        raise OpenMPTException(msg, code)


    @property
    def current_order(self) -> int:
        return LIB.openmpt_module_get_current_order(self._module)

    @current_order.setter
    def current_order(self, value: int) -> None:
        LIB.openmpt_module_set_position_order_row(self._module, value, self.current_row)

    @property
    def current_row(self) -> int:
        return LIB.openmpt_module_get_current_row(self._module)

    @current_row.setter
    def current_row(self, value: int) -> None:
        LIB.openmpt_module_set_position_order_row(self._module, self.current_order, value)


    @property
    def length(self) -> float:
        return LIB.openmpt_module_get_duration_seconds(self._module)


    @property
    def num_subsongs(self) -> int:
        return LIB.openmpt_module_get_num_subsongs(self._module)


    @property
    def subsong(self) -> int:
        return LIB.openmpt_module_get_selected_subsong(self._module)

    @subsong.setter
    def subsong(self, value: int) -> None:
        if not LIB.openmpt_module_select_subsong(self._module, value):
            self._raise_last_error()


    @property
    def repeat_count(self) -> int:
        return LIB.openmpt_module_get_repeat_count(self._module)

    @repeat_count.setter
    def repeat_count(self, value: int) -> None:
        LIB.openmpt_module_set_repeat_count(self._module, value)


    # i'm sorry
    def estimate_duration(self) -> float:
        sample_rate = 44100
        sample_buffer = (c_int16 * (sample_rate // 10))()
        total_samples = 0

        while (rendered_samples := LIB.openmpt_module_read_mono(self._module, sample_rate, len(sample_buffer), sample_buffer)) != 0:
            if rendered_samples < 0:
                self._raise_last_error()
            total_samples += rendered_samples

        return total_samples / sample_rate