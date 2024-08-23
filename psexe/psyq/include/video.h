#pragma once

#define MODE_NTSC 0
#define MODE_PAL 1
extern long GetVideoMode();
extern long SetVideoMode(long mode);

#define BIOS_VERSION_STRING 0xBFC7FF32
#define BIOS_PAL ((char *)BIOS_VERSION_STRING)[32] == 'E'

extern int VSync(int mode);
extern void VSyncCallback(void (*func)());