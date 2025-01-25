#include <stdint.h>
#include <stddef.h>
#pragma once

struct _song_info_t {
    int version;

    unsigned char *pxm_ptr;
    unsigned char *vh_ptr;
    unsigned char *vb_ptr;

    int type;
    int loop;
    int position;
    int panning_type;
};
typedef struct _song_info_t song_info_t;
extern song_info_t song_info __attribute__((__used__));

#ifdef XM_BUILTIN
extern unsigned char _song_xm_start[];
extern unsigned char _song_vh_start[];
extern unsigned char _song_vb_start[];
#endif