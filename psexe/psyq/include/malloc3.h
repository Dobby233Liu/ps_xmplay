#include <stdint.h>
#pragma once

extern void InitHeap3(unsigned long *head, unsigned long size);
extern void *malloc3(size_t);
extern void free3(void *);

#define InitHeap InitHeap3
#define malloc malloc3
#define free free3