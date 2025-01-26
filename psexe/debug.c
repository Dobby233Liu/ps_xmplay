#include <common/syscalls/syscalls.h>
#include <common/hardware/pcsxhw.h>

__attribute__((noreturn)) void abort(const char* msg) {
    enterCriticalSection();

    ramsyscall_printf("Aborted");
    if (msg) {
        ramsyscall_printf(": %s\n", msg);
        pcsx_message(msg);
    }
    ramsyscall_printf("\n");

    pcsx_debugbreak();
    pcsx_exit(-1);

    while (1);
    __builtin_unreachable();
}