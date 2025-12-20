#include <stdint.h>
#include <stdbool.h>
#include <common/syscalls/syscalls.h>
#include <common/hardware/pcsxhw.h>
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
    if (vab_id_libsnd < 0) {
        ret = vab_id_libsnd - 1;
        goto done;
    }

    VabHdr vh;
    if (SsUtGetVabHdr(vab_id_libsnd, &vh) != 0) goto done;

    assert(vh.vs <= 0x80, "too many voices");
    for (int i = 0; i < vh.vs; i++)
        XM_SetVAGAddress(vab_id_xmplay, i, SsUtGetVagAddr(vab_id_libsnd, i + 1));

    ret = vab_id_xmplay;

done:
    if (vab_id_libsnd >= 0) SsVabClose(vab_id_libsnd);
    if (vab_id_xmplay != -1 && ret == -1) XM_CloseVAB(vab_id_xmplay);
    SsQuit();
    return ret;
}
#endif


static int song_id = -1;
static volatile bool stop = false;

static void on_vsync() {
    if (song_id < 0 || stop) return;

    XM_Feedback feedback;
    assert(XM_GetFeedback(song_id, &feedback), "cant get feedback");
    if (!stop)
        stop = feedback.Status == XM_STOPPED;
    if (stop) return;

    XM_Update();
}

void main() {
    int locked;
    ResetCallback();

    assert(song_info.pxm_ptr && song_info.vh_ptr && song_info.vb_ptr, "xm/voice is null");
    assert(syscall_strncmp(song_info.pxm_ptr, "Extended Module:", 16) == 0, "invalid xm");
    assert(syscall_strncmp(song_info.vh_ptr, "pBAV", 4) == 0, "invalid vab");

    locked = enterCriticalSection();
    InitHeap((unsigned long*)heap, sizeof(heap));
    if (!locked) leaveCriticalSection();

    SetVideoMode(BIOS_PAL ? MODE_PAL : MODE_NTSC);

    SpuInit();
    SpuInitMalloc(MAX_SPU_BANKS, spu_heap);
    SpuSetTransferCallback(NULL);
    SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

#if 0
    // init once to alloc reverb work area
    SpuReverbAttr reverb_attr;
    reverb_attr.mask = SPU_REV_MODE | SPU_REV_DEPTHL | SPU_REV_DEPTHR;
    reverb_attr.mode = SPU_REV_MODE_STUDIO_A;
    reverb_attr.depth.left = 0x1fff;
    reverb_attr.depth.right = 0x1fff;
    SpuSetReverbModeParam(&reverb_attr);
    SpuReserveReverbWorkArea(SPU_ON);
#endif

    XM_OnceOffInit(GetVideoMode());

    uint8_t *song_addr = malloc(XM_GetSongSize());
    XM_SetSongAddress(song_addr);

    uint8_t *file_header_addr = malloc(XM_GetFileHeaderSize());
    XM_SetFileHeaderAddress(file_header_addr);

    int xm_id = 0;
    InitXMData(song_info.pxm_ptr, xm_id, song_info.panning_type);

#ifndef XMPLAY_VARIANT_REDRIVER2
    int voice_bank_id = XM_VABInit(song_info.vh_ptr, song_info.vb_ptr);
#else
    int voice_bank_id = vab_init(song_info.vh_ptr, song_info.vb_ptr);
    assert(voice_bank_id != -2, "oom/invalid vab");
#endif
    assert(voice_bank_id >= 0, "cant load voice");

#if 0
    // then twice due to how vab_init works
    SpuSetReverb(SPU_ON);
    SpuSetReverbModeParam(&reverb_attr);
    SpuSetReverbDepth(&reverb_attr); // why though
    SpuSetReverbVoice(SPU_ON, SPU_ALLCH);
#endif

    song_id = XM_Init(
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

    if (song_info.loop) {
        // The song will never end, so let's idle to not confuse HE
        VSyncCallback(XM_Update);
        while (true);
    } else {
        VSyncCallback(on_vsync);
        do
            VSync(0);
        while (!stop);
    }

    // Quit XMPlay
#if defined(XMPLAY_VARIANT_REDRIVER2) && defined(XMPLAY_ENABLE_FIXES)
    // Calling XM_Exit is not enough to make sure all channels are keyed off
    SilenceXM(song_id);
#endif
    XM_Exit();
    VSyncCallback(NULL);
    song_id = -1;

    free(file_header_addr);
    free(song_addr);
    XM_FreeAllSongIDs();
    XM_FreeAllFileHeaderIDs();

    // Quit SPU processing
    // FIXME: free self-allocated vab resources
#if !defined(XMPLAY_VARIANT_REDRIVER2) || !defined(XMPLAY_ENABLE_FIXES)
    // Calling XM_Exit is not enough to make sure all channels are keyed off
    SpuSetKey(SPU_OFF, SPU_ALLCH);
#endif
#if 0
    reverb_attr.mask = SPU_REV_MODE;
    reverb_attr.mode = SPU_REV_MODE_OFF; // idk if we should clear work area
    SpuSetReverbModeParam(&reverb_attr);
    SpuSetReverb(SPU_OFF);
#endif
    SpuQuit();

    pcsx_exit(0);
    syscall__exit(0);
}
