#include <stdint.h>
#include <common/syscalls/syscalls.h>
#include <malloc3.h>
#include <video.h>
#include <libspu.h>
#include <xmplay.h>
#include "song.h"
#include "debug.h"

#include <common/hardware/pcsxhw.h>

static unsigned char heap[0x40000];

#define MAX_SPU_MALLOC 200 // in sync with SBSPSS
static char spu_heap[SPU_MALLOC_RECSIZ * (MAX_SPU_MALLOC + 1)];

#define BIOS_VERSION_STRING 0xBFC7FF32

void main() {
    assert(song_info.pxm_ptr && song_info.vh_ptr && song_info.vb_ptr, "xm/voice pointer unset");
    assert(syscall_strncmp(song_info.pxm_ptr, "Extended Module:", 16) == 0, "xm invalid");
    assert(syscall_strncmp(song_info.vh_ptr, "pBAV", 4) == 0, "vab invalid");

    int crit_section_already_entered = enterCriticalSection();
    InitHeap3((unsigned long*)heap, sizeof(heap));
    if (!crit_section_already_entered) leaveCriticalSection();

    SpuInit();

#if 0 // FIXME
    // this clears SPU memory
    // appears to help the DuckStation situation? but is kind of slow
    SpuSetTransferStartAddr(0);
    SpuSetTransferMode(SPU_TRANSFER_BY_DMA);
    SpuSetTransferCallback(NULL);
    SpuWrite0(512 * 1024);
    SpuIsTransferCompleted(SPU_TRANSFER_WAIT);
#endif

    SpuInitMalloc(MAX_SPU_MALLOC, spu_heap);
    SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

#ifndef XMPLAY_WORSE_TIMING
    XM_OnceOffInit(((char *)BIOS_VERSION_STRING)[32] == 'E' ? XM_PAL : XM_NTSC);
#else // we make a bold assumption here
    XM_OnceOffInit(XM_NTSC);
#endif
    XM_SetStereo();

    uint8_t *song_addr = malloc(XM_GetSongSize());
    XM_SetSongAddress(song_addr);

    uint8_t *file_header_addr = malloc(XM_GetFileHeaderSize());
    XM_SetFileHeaderAddress(file_header_addr);

    int voice_bank_id = XM_VABInit(song_info.vh_ptr, song_info.vb_ptr);
    assert(voice_bank_id != -1, "voice load failed");

    int xm_data_id = InitXMData(song_info.pxm_ptr, 0, song_info.panning_type);

    int song_id = XM_Init(
        voice_bank_id, xm_data_id, -1,
        1, // HACK: this leaves ch0 empty but gets rid of a terrible bug
        song_info.loop, -1, song_info.type, song_info.position
    );
    assert(song_id != -1, "song init failed");

#ifndef XMPLAY_WORSE_TIMING
    VSyncCallback(XM_Update);
    while (1)
        asm("");
#else
#ifndef XMPLAY_VARIANT_SBSPSS
#error Only the SBSPSS version of xmplay.lib includes XM_Update2, which is necessary for this hack to function
#endif
    while (1) {
        XM_Update2(2);
        VSync(0);
    }
#endif

    XM_Exit();
    free(file_header_addr);
    free(song_addr);
    XM_FreeAllSongIDs();
    XM_FreeFileHeaderID();
}