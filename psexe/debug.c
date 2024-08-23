#include <common/syscalls/syscalls.h>
#include <common/hardware/pcsxhw.h>

__attribute__((noreturn)) void abort(const char* msg) {
    enterCriticalSection();
    if (msg) {
        ramsyscall_printf("Aborted: %s\n", msg);
        pcsx_message(msg);
    } else ramsyscall_printf("Aborted\n");
    pcsx_debugbreak();
    __builtin_trap();
    while (1)
        asm("");
}