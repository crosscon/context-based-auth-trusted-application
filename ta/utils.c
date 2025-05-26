#include <stddef.h>

#include "utils.h"


char* str_cat(char* dest, const char* src, size_t n) {
    char* d = dest;
    while (*d != '\0') {
        d++;
    }
    while (n-- > 0 && *src != '\0') {
        *d++ = *src++;
    }
    *d = '\0';

    return dest;
}
