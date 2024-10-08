#include <stdint.h>
#include <stdbool.h>
#include <common/syscalls/syscalls.h>
#include <malloc.h>
#include <etc.h>
#include <video.h>
#include <libspu.h>
#include <xmplay.h>
#include "song.h"
#include "debug.h"
#include "vab.h"
#include <common/hardware/pcsxhw.h>

#include <common/hardware/pcsxhw.h>

static unsigned char heap[0x20000] = {0};

#define MAX_SPU_BANKS 128 // realistic number; SBSPSS uses 200
static unsigned char spu_heap[SPU_MALLOC_RECSIZ * (MAX_SPU_BANKS + 1)] = {0};


#ifdef XMPLAY_VARIANT_REDRIVER2
static int vab_init(unsigned char *vh_ptr, unsigned char *vb_ptr) {
    int vab_id = XM_GetFreeVAB();
    if (vab_id == -1) return -1;

    struct vab_header *vh = (struct vab_header*)vh_ptr;
    unsigned char *vag_sizes_ptr = vh_ptr;
    vag_sizes_ptr += sizeof(struct vab_header);
    vag_sizes_ptr += 0x10 * 0x80; // program attrs
    vag_sizes_ptr += 0x200 * vh->num_programs; // tone attrs
    // skip null
    vag_sizes_ptr += sizeof(uint16_t);

    unsigned char *cur_vag_data_ptr = vb_ptr;
    for (int16_t slot = 0; slot < vh->num_samples; ++slot) {
        long true_size = *((uint16_t*)vag_sizes_ptr + slot) * 8;
        // For revx, XM2PSX appears to trim some samples, but then proceed to
        // write the previous amount of samples for whatever reason
        // Thus, carry on if we hit a empty sample or everything can explode
        // FIXME: Am I reading the wrong value from vh?
        if (true_size <= 0)
            continue;
        long vag_spu_addr = SpuMalloc(true_size);
        assert(vag_spu_addr != 0, "vag malloc failed");

        SpuSetTransferStartAddr(vag_spu_addr);
        SpuWrite(cur_vag_data_ptr, true_size);
        SpuIsTransferCompleted(SPU_TRANSFER_WAIT);
        XM_SetVAGAddress(vab_id, slot, vag_spu_addr);

        cur_vag_data_ptr += true_size;
    }

    return vab_id;
}
#endif


void main() {
    ResetCallback();

    assert(song_info.pxm_ptr && song_info.vh_ptr && song_info.vb_ptr, "xm/voice pointer unset");
    assert(syscall_strncmp(song_info.pxm_ptr, "Extended Module:", 16) == 0, "xm invalid");
    assert(syscall_strncmp(((struct vab_header*)song_info.vh_ptr)->magic, "pBAV", 4) == 0, "vab invalid");

    int crit_section_already_entered = enterCriticalSection();
    InitHeap((unsigned long*)heap, sizeof(heap));
    if (!crit_section_already_entered) leaveCriticalSection();

    SpuInit();

    SpuInitMalloc(MAX_SPU_BANKS, spu_heap);
    SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

/*
    // clear SPU memory
    SpuSetTransferMode(SPU_TRANSFER_BY_DMA);
    SpuSetTransferStartAddr(0);
    SpuWrite0(512 * 1024);
    SpuIsTransferCompleted(SPU_TRANSFER_WAIT);
*/

#ifndef XMPLAY_WORSE_TIMING
    SetVideoMode(BIOS_PAL ? MODE_PAL : MODE_NTSC);
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
#endif
    assert(voice_bank_id != -1, "voice load failed");

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
    assert(song_id != -1, "song init failed");

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