#include <xmplay.h>
#include "song.h"

struct _song_info song_info =
{
#ifdef XM_FILENAME
    .pxm_ptr = PXM_FILE,
    .vh_ptr = VH_FILE,
    .vb_ptr = VB_FILE,

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