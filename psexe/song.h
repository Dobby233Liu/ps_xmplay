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

#ifdef XM_FILENAME
// I hate this
#define _SONG_CONCAT_(a, b, c) a##b##c
#define _SONG_CONCAT(b, c) _SONG_CONCAT_(_binary_songdata_, b, c)
#define PXM_FILE _SONG_CONCAT(XM_FILENAME, _xm_start)
#define VH_FILE _SONG_CONCAT(XM_FILENAME, _vh_start)
#define VB_FILE _SONG_CONCAT(XM_FILENAME, _vb_start)

extern unsigned char PXM_FILE[];
extern unsigned char VH_FILE[];
extern unsigned char VB_FILE[];
#endif