#include <stdint.h>
#include <stdbool.h>
#include <common/syscalls/syscalls.h>
#include <malloc3.h>
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

#define MAX_SPU_BANKS 200 // in sync with SBSPSS
static unsigned char spu_heap[SPU_MALLOC_RECSIZ * (MAX_SPU_BANKS + 1)] = {0};

#define BIOS_VERSION_STRING 0xBFC7FF32


#ifdef XMPLAY_VARIANT_REDRIVER2
// FIXME: nonfunctional
int vab_init(unsigned char *vh_ptr, unsigned char *vb_ptr) {
    int vab_id = XM_GetFreeVAB();
    if (vab_id == -1) return -1;

    unsigned char *vag_sizes_ptr = vh_ptr;
    vag_sizes_ptr += sizeof(struct vab_header);
    vag_sizes_ptr += 0x10 * 0x80; // program attrs
    vag_sizes_ptr += 0x200 * ((struct vab_header*)vh_ptr)->num_programs; // tone attrs
    // first vag is always null
    vag_sizes_ptr += sizeof(uint16_t);
    int a = 1;

    unsigned char *cur_vag_data_ptr = vb_ptr;
    for (int16_t slot = 0; slot < ((struct vab_header*)vh_ptr)->num_samples; ++slot) {
        long true_size = *((uint16_t*)vag_sizes_ptr + slot) * 8;
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
    InitHeap3((unsigned long*)heap, sizeof(heap));
    if (!crit_section_already_entered) leaveCriticalSection();

    SpuInit();

#ifdef XMPLAY_VARIANT_REDRIVER2
    // clear SPU memory
    SpuSetTransferMode(SPU_TRANSFER_BY_DMA);
    SpuSetTransferStartAddr(0);
    SpuWrite0(512 * 1024);
    SpuIsTransferCompleted(SPU_TRANSFER_WAIT);
#endif

    SpuInitMalloc(MAX_SPU_BANKS, spu_heap);
    SpuSetCommonMasterVolume(0x3FFF, 0x3FFF);

#ifndef XMPLAY_WORSE_TIMING
    SetVideoMode(BIOS_PAL ? MODE_PAL : MODE_NTSC);
#endif

#ifndef XMPLAY_WORSE_TIMING
    XM_OnceOffInit(BIOS_PAL ? XM_PAL : XM_NTSC);
#else // we make a bold assumption here
    XM_OnceOffInit(XM_NTSC);
#endif
#ifndef XMPLAY_VARIANT_REDRIVER2
    XM_SetStereo();
#endif

    uint8_t *song_addr = malloc(XM_GetSongSize());
    XM_SetSongAddress(song_addr);

    uint8_t *file_header_addr = malloc(XM_GetFileHeaderSize());
    XM_SetFileHeaderAddress(file_header_addr);

#ifndef XMPLAY_VARIANT_REDRIVER2
    int voice_bank_id = XM_VABInit(song_info.vh_ptr, song_info.vb_ptr);
#else
    int voice_bank_id = vab_init(song_info.vh_ptr, song_info.vb_ptr);
#endif
    assert(voice_bank_id != -1, "voice load failed");

    int xm_data_id = InitXMData(song_info.pxm_ptr, 0, song_info.panning_type);

    int song_id = XM_Init(
        voice_bank_id, xm_data_id, -1,
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
#ifndef XMPLAY_VARIANT_SBSPSS
#error Only the SBSPSS version of xmplay.lib include XM_Update2, which is necessary for this hack to function
#endif
    while (true) {
        XM_Update2(2);
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