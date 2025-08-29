#ifndef __CONFIG_H__
#define __CONFIG_H__

// Set to 1 to enable debug printing, 0 to disable
#define DEBUG 1

#if DEBUG
#include <stdio.h>
#define DPRINTF(fmt, ...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

#endif // __CONFIG_H__
