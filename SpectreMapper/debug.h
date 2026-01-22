#pragma once
#include <stdio.h>

// Uncomment the following line to enable debug logging
#define ENABLE_DEBUG

#ifdef ENABLE_DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while(0)
#endif
