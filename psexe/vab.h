#include <stdint.h>
#pragma once

struct __attribute__((packed)) vab_header {
    char magic[4];
    int32_t version;
    int32_t vab_id;
    int32_t total_size;

    uint16_t reserved;
    int16_t num_programs;
    int16_t num_tones;
    int16_t num_samples;
    int8_t master_volume;
    int8_t master_pan;
    uint8_t user1;
    uint8_t user2;
    uint32_t reserved2;
};

// program_attrs_STUB : 0x10 * 0x80;
// tone_attrs_STUB : 0x200 * num_programs;
// uint16_t vag_sizes[0x100]; // / 8
// unsigned char vag_data[0x7E000];