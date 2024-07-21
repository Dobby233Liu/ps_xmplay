#pragma once

extern void abort(const char* msg);

static inline void assert(int cond, const char* msg) { if (!cond) abort(msg); }