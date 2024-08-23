#include <stdint.h>
#pragma once

extern void InitHeap(unsigned long *head, unsigned long size);
extern void *malloc(size_t);
extern void free(void*);

/*#define InitHeap InitHeap3
#define malloc malloc3
#define free free3*/