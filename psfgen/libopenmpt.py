from ctypes import *
import enum
import os
import io
from typing import Any

LIB = None
try:
    if os.name == "nt":
        LIB = CDLL("libopenmpt.dll")
    else:
        LIB = CDLL("libopenmpt.so")
except OSError:
    if os.name == "nt":
        LIB = CDLL(os.path.join(os.path.dirname(__file__), "libopenmpt.dll"))
if not LIB:
    raise OSError("Please install libopenmpt")


LOG_CB = CFUNCTYPE(None, c_char_p, c_void_p)

class ErrorFuncResult(enum.IntEnum):
    DoNothing = 0
    Log = 1 << 0
    Store = 1 << 1
    Default = Log | Store

ERR_CB = CFUNCTYPE(c_int, c_int, c_void_p)


class _StreamCallbacks(Structure):
    _read_proc = CFUNCTYPE(c_size_t, c_void_p, c_void_p, c_size_t)
    _seek_proc = CFUNCTYPE(c_int, c_void_p, c_int64, c_int)
    _tell_proc = CFUNCTYPE(c_int64, c_void_p)
    _fields_ = [
        ("_read", _read_proc),
        ("_seek", _seek_proc),
        ("_tell", _tell_proc)
    ]

    _stream: io.BytesIO

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    @classmethod
    def from_stream(cls, stream: io.BytesIO):
        self = cls()
        self._stream = stream

        self._read = cls._read_proc(lambda ptr, dst, size: stream.readinto((c_char * size).from_address(dst)))
        self._seek = cls._seek_proc(lambda ptr, pos, whence: stream.seek(pos, whence))
        self._tell = cls._tell_proc(lambda ptr: stream.tell())
        return self


openmpt_module = c_void_p # it's some kind of struct alright

LIB.openmpt_module_create2.argtypes = [
    _StreamCallbacks, c_void_p,
    LOG_CB, c_void_p,
    ERR_CB, c_void_p,
    POINTER(c_int), c_char_p,
    c_void_p
]
LIB.openmpt_module_create2.restype = openmpt_module

LIB.openmpt_module_destroy.argtypes = [openmpt_module]


LIB.openmpt_module_error_clear.argtypes = [openmpt_module]

class OpenMPTException(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


LIB.openmpt_module_get_current_order.argtypes = [openmpt_module]
LIB.openmpt_module_get_current_order.restype = c_int32
LIB.openmpt_module_get_current_row.argtypes = [openmpt_module]
LIB.openmpt_module_get_current_row.restype = c_int32
LIB.openmpt_module_set_position_order_row.argtypes = [openmpt_module, c_int32, c_int32]
LIB.openmpt_module_set_position_order_row.restype = c_double


LIB.openmpt_module_get_duration_seconds.argtypes = [openmpt_module]
LIB.openmpt_module_get_duration_seconds.restype = c_double


LIB.openmpt_module_ctl_get_boolean.argtypes = [openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_boolean.restype = c_bool
LIB.openmpt_module_ctl_get_floatingpoint.argtypes = [openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_floatingpoint.restype = c_double
LIB.openmpt_module_ctl_get_integer.argtypes = [openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_integer.restype = c_int64
LIB.openmpt_module_ctl_get_text.argtypes = [openmpt_module, c_char_p]
LIB.openmpt_module_ctl_get_text.restype = c_char_p

LIB.openmpt_free_string.argtypes = [c_char_p]

LIB.openmpt_module_ctl_set_boolean.argtypes = [openmpt_module, c_char_p, c_bool]
LIB.openmpt_module_ctl_get_boolean.restype = c_bool
LIB.openmpt_module_ctl_set_floatingpoint.argtypes = [openmpt_module, c_char_p, c_double]
LIB.openmpt_module_ctl_set_floatingpoint.restype = c_bool
LIB.openmpt_module_ctl_set_integer.argtypes = [openmpt_module, c_char_p, c_int64]
LIB.openmpt_module_ctl_set_integer.restype = c_bool
LIB.openmpt_module_ctl_set_text.argtypes = [openmpt_module, c_char_p, c_char_p]
LIB.openmpt_module_ctl_set_text.restype = c_bool


LIB.openmpt_module_get_num_subsongs.argtypes = [openmpt_module]
LIB.openmpt_module_get_num_subsongs.restype = c_int32
LIB.openmpt_module_get_selected_subsong.argtypes = [openmpt_module]
LIB.openmpt_module_get_selected_subsong.restype = c_int32
LIB.openmpt_module_select_subsong.argtypes = [openmpt_module, c_int32]
LIB.openmpt_module_select_subsong.restype = c_bool


LIB.openmpt_module_get_repeat_count.argtypes = [openmpt_module]
LIB.openmpt_module_get_repeat_count.restype = c_int32
LIB.openmpt_module_set_repeat_count.argtypes = [openmpt_module, c_int32]
LIB.openmpt_module_set_repeat_count.restype = c_bool


class Module():
    class _Ctl():
        def __init__(self, module: "Module", *args: Any, **kwargs: Any) -> None:
            self._module = module

        def __getitem__(self, key: str) -> Any:
            item_type = None

            match key:
                case "load.skip_samples": item_type = "boolean"

            if item_type is None: # ffs do i have to guess the ctl type
                raise NotImplementedError()

            value = None
            match item_type:
                case "boolean": LIB.openmpt_module_ctl_get_boolean(self._module._module, key.encode("utf-8"))
                case "floatingpoint": value = LIB.openmpt_module_ctl_get_floatingpoint(self._module._module, key.encode("utf-8"))
                case "integer": value = LIB.openmpt_module_ctl_get_integer(self._module._module, key.encode("utf-8"))
                case "text": value = LIB.openmpt_module_ctl_get_text(self._module._module, key.encode("utf-8"))
            if value is None:
                self._module._raise_last_error()
            return value

        def __setitem__(self, key: str, value: str|float|int|bool) -> None:
            ok = False
            if isinstance(value, str):
                ok = LIB.openmpt_module_ctl_set_text(self._module._module, key.encode("utf-8"), value.encode("utf-8"))
            elif isinstance(value, float):
                ok = LIB.openmpt_module_ctl_set_floatingpoint(self._module._module, key.encode("utf-8"), value)
            elif isinstance(value, int):
                ok = LIB.openmpt_module_ctl_set_integer(self._module._module, key.encode("utf-8"), value)
            elif isinstance(value, bool):
                ok = LIB.openmpt_module_ctl_set_boolean(self._module._module, key.encode("utf-8"), value)
            else:
                raise TypeError(f"Unsupported type {type(value)}")
            if not ok:
                self._module._raise_last_error()


    def __init__(self, stream: io.BytesIO) -> None:
        self._last_error_ptr = pointer(c_int(0))
        self._last_error_msg_ptr = create_string_buffer(512)
        self._hash_ptr = pointer(c_int(hash(self)))
        self._stream_cb = _StreamCallbacks.from_stream(stream)
        self._log_cb = LOG_CB(self._log)
        self._err_cb = ERR_CB(self._err)

        self._module = LIB.openmpt_module_create2(
            self._stream_cb, self._hash_ptr,
            self._log_cb, self._hash_ptr, self._err_cb, self._hash_ptr,
            self._last_error_ptr, self._last_error_msg_ptr,
            None # any ctl would have to be configured later
        )
        if self._module is None:
            self._raise_last_error()

        self.ctl = self._Ctl(self)

    def __del__(self):
        LIB.openmpt_module_destroy(self._module)

    def _log(message: c_char_p, user: c_void_p):
        print(message.value.decode("utf-8"))

    def _err(code: c_int, user: c_void_p) -> c_int:
        # TODO
        return ErrorFuncResult.value

    def _raise_last_error(self):
        code = self._last_error_ptr.value
        if code == 0:
            assert False
        msg = self._last_error_msg_ptr.value.decode("utf-8")
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