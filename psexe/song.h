#include <stdint.h>
#include <stddef.h>
#pragma once

struct _song_info_t {
    const int version;

    unsigned char *pxm_ptr;
    unsigned char *vh_ptr;
    unsigned char *vb_ptr;

    const int type;
    const int loop;
    const int position;
    const int panning_type;
};
typedef struct _song_info_t song_info_t;
extern song_info_t song_info __attribute__((__used__));
