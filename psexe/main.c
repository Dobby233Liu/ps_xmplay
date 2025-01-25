#include <stdint.h>
#include <stdbool.h>
#include <common/syscalls/syscalls.h>
#include <malloc.h>
#include <etc.h>
#include <video.h>
#include <libspu.h>
#include <libsnd.h>
#include <xmplay.h>
#include "song.h"
#include "debug.h"


static char heap[0x2000] = {0};

// max in one VAB allowed by xmplay
// SBSPSS uses 200 likely to accomodate the use of SFXs
#define MAX_SPU_BANKS 0x80
static char spu_heap[SPU_MALLOC_RECSIZ * (MAX_SPU_BANKS + 1)] = {0};


#ifdef XMPLAY_VARIANT_REDRIVER2
static int vab_init(unsigned char *vh_ptr, unsigned char *vb_ptr) {
    int ret = -1;

    SsInit();

    int vab_id_xmplay = XM_GetFreeVAB();
    if (vab_id_xmplay == -1) goto done;

    int vab_id_libsnd = SsVabTransfer(vh_ptr, vb_ptr, 0, SS_WAIT_COMPLETED);
    if (vab_id_libsnd < 0) goto done;

    VabHdr vh;
    if (SsUtGetVabHdr(vab_id_libsnd, &vh) != 0) goto done;

    assert(vh.vs <= 0x80, "too many voices");
    for (int i = 0; i < vh.vs; i++)
        XM_SetVAGAddress(vab_id_xmplay, i, SsUtGetVagAddr(vab_id_libsnd, i + 1));

    ret = vab_id_xmplay;

done:
    if (vab_id_libsnd >= 0) SsVabClose(vab_id_libsnd);
    if (vab_id_xmplay != -1 && ret == -1) XM_CloseVAB2(vab_id_xmplay);
    SsQuit();
    return ret;
}
#endif


void main() {
    ResetCallback();

    assert(song_info.pxm_ptr && song_info.vh_ptr && song_info.vb_ptr, "xm/voice is null");
    assert(syscall_strncmp(song_info.pxm_ptr, "Extended Module:", 16) == 0, "invalid xm");
    assert(syscall_strncmp(song_info.vh_ptr, "pBAV", 4) == 0, "invalid vab");

    int crit_section_already_entered = enterCriticalSection();
    InitHeap((unsigned long*)heap, sizeof(heap));
    if (!crit_section_already_entered) leaveCriticalSection();

#ifndef XMPLAY_WORSE_TIMING
    SetVideoMode(BIOS_PAL ? MODE_PAL : MODE_NTSC);
#endif

    SpuInit();

    SpuInitMalloc(MAX_SPU_BANKS, spu_heap);
    SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

    XM_OnceOffInit(GetVideoMode());

    uint8_t *song_addr = malloc(XM_GetSongSize());
    XM_SetSongAddress(song_addr);

    uint8_t *file_header_addr = malloc(XM_GetFileHeaderSize());
    XM_SetFileHeaderAddress(file_header_addr);

    int xm_id = 0;
    InitXMData(song_info.pxm_ptr, xm_id, song_info.panning_type);

    SpuSetTransferCallback(NULL);
#ifndef XMPLAY_VARIANT_REDRIVER2
    int voice_bank_id = XM_VABInit(song_info.vh_ptr, song_info.vb_ptr);
#else
    int voice_bank_id = vab_init(song_info.vh_ptr, song_info.vb_ptr);
#endif
    assert(voice_bank_id != -1, "cant load voice");

    int song_id = XM_Init(
        voice_bank_id, xm_id, -1,
        #ifndef XMPLAY_VARIANT_SBSPSS
        0,
        #else
        // HACK: this leaves ch0 empty but gets rid of a terrible bug
        // Specifically, buggy volume automation with the flute in May14 Options theme
        1,
        #endif
        song_info.loop, -1, song_info.type, song_info.position
    );
    assert(song_id != -1, "cant init song");

#ifndef XMPLAY_WORSE_TIMING
    VSyncCallback(XM_Update);
    while (true)
        asm("");
#else
    while (true) {
        XM_Update();
        VSync(0);
    }
#endif

    // TODO: let there be some way to reach this
    // test/revx_unused1 ends in an absolutely ugly way otherwise
    XM_Exit();
    free(file_header_addr);
    free(song_addr);
    XM_FreeAllSongIDs();
    XM_FreeFileHeaderID();
}