#include <common/syscalls/syscalls.h>
#include <common/hardware/pcsxhw.h>

__attribute__((noreturn)) void abort(const char* msg) {
    enterCriticalSection();
    pcsx_debugbreak();

    ramsyscall_printf("Aborted");
    if (msg) {
        ramsyscall_printf(": %s\n", msg);
        pcsx_message(msg);
    }
    ramsyscall_printf("\n");

    while (1)
        asm("");
}