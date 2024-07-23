#include <stdint.h>
#include <common/syscalls/syscalls.h>
#include <malloc3.h>
#include <video.h>
#include <libspu.h>
#include <xmplay.h>
#include "song.h"
#include "debug.h"

#include <common/hardware/pcsxhw.h>

static unsigned long heap[0x8000];

#define MAX_SPU_MALLOC 200 // in sync with SBSPSS
static char spu_heap[SPU_MALLOC_RECSIZ * (MAX_SPU_MALLOC + 1)];

#define BIOS_VERSION_STRING 0xBFC7FF32

void main() {
    assert(song_info.pxm_ptr && song_info.vh_ptr && song_info.vb_ptr, "xm/voice pointer unset");
    assert(syscall_strncmp(song_info.pxm_ptr, "Extended Module:", 16) == 0, "xm invalid");
    assert(syscall_strncmp(song_info.vh_ptr, "pBAV", 4) == 0, "vab invalid");

    int crit_section_already_entered = enterCriticalSection();
    InitHeap3(heap, sizeof(heap));
    if (!crit_section_already_entered) leaveCriticalSection();

    SpuInit();
	SpuInitMalloc(MAX_SPU_MALLOC, spu_heap);
	SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

    XM_OnceOffInit(((char *)BIOS_VERSION_STRING)[32] == 'E' ? XM_PAL : XM_NTSC);
    VSyncCallback(XM_Update);
    XM_SetStereo();

    uint8_t *song_addr = malloc(XM_GetSongSize());
    XM_SetSongAddress(song_addr);

    uint8_t *file_header_addr = malloc(XM_GetFileHeaderSize());
    XM_SetFileHeaderAddress(file_header_addr);

    int voice_bank_id = XM_VABInit(song_info.vh_ptr, song_info.vb_ptr);
    assert(voice_bank_id != -1, "voice load failed");

    InitXMData(song_info.pxm_ptr, 0, song_info.panning_type);

    int song_id = XM_Init(voice_bank_id, 0, 0, 0, song_info.loop, -1, song_info.type, song_info.position);
    assert(song_id != -1, "song init failed");

    while (1) ;

    XM_Exit();
    XM_FreeAllSongIDs();
    XM_FreeFileHeaderID();

    free(file_header_addr);
    free(song_addr);
}