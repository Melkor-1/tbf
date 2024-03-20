#ifndef TBF_UTIL_H 
#define TBF_UTIL_H 1

#define C2X_PLACEHOLDER 202000L

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= C2X_PLACEHOLDER
    /* Coast is clear. */
#else
    #include <assert.h>             /* static_assert */
    #include <stdbool.h>            /* bool, true, and false. */
    #define nullptr ((void *)0)
#endif                          /* nullptr */

#include <stdint.h>
#include <stdio.h>

bool tbf_strtoi64(int64_t value[static 1], const char s[static 1]);

bool tbf_strtou64(uint64_t value[static 1], const char s[static 1]);

FILE *tbf_xfopen(const char path[restrict static 1],
                 const char mode[restrict static 1]);


bool tbf_grow_array_and_append(void *restrict *      ptr,
                               size_t                capacity[restrict static 1],
                               size_t                count[restrict static 1], 
                               size_t                elem_size, 
                               const void *restrict  elem);

char *tbf_xread_file(const char  path[restrict static 1],
                     FILE        stream[restrict static 1], 
                     size_t      nbytes[restrict static 1]);

int tbf_xfputs(const char s[static 1], FILE stream[static 1]);

int tbf_xprintf(const char format[static 1], ...);

int tbf_xfprintf(FILE stream[static 1], const char format[static 1], ...);

#endif                          /* TBF_UTIL_H */
