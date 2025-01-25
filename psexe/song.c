#include <xmplay.h>
#include "song.h"

song_info_t song_info __attribute__((__used__)) =
{
    .version = 1,

#ifdef XM_BUILTIN
    .pxm_ptr = _song_xm_start,
    .vh_ptr = _song_vh_start,
    .vb_ptr = _song_vb_start,

    .type = XM_TYPE,
    .loop = XM_LOOP,
    .position = XM_POSITION,
    .panning_type = XM_PANNING_TYPE
#else
    // these will get substituted by the PSF maker
    .pxm_ptr = NULL,
    .vh_ptr = NULL,
    .vb_ptr = NULL,

    .type = XM_Music,
    .loop = 1,
    .position = 0,
    .panning_type = XM_UseXMPanning
#endif
};