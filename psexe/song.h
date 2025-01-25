#include <stdint.h>
#include <stddef.h>
#pragma once

struct _song_info {
    unsigned char *pxm_ptr;
    unsigned char *vh_ptr;
    unsigned char *vb_ptr;

    int type;
    int loop;
    int position;
    int panning_type;
};
extern struct _song_info song_info;

#ifdef XM_BUILTIN
extern unsigned char _song_xm_start[];
extern unsigned char _song_vh_start[];
extern unsigned char _song_vb_start[];
#endif