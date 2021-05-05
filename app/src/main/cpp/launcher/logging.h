#pragma once

#include <stdio.h>

#define TRY(fn, msg, ...) ({ auto res = fn; if (res == -1) { fprintf(stderr, "[%s:%d] " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); std::cerr.flush(); abort(); } res; })
#define TRYSYSFATAL(fn) TRY(fn, "errno %d: %s", errno, strerror(errno))
