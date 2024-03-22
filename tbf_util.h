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

#if defined(__GNUC__) || defined(__clang__) || defined(__INTEL_LLVM_COMPILER)
    #define ATTRIB_PRINTF(...)      __attribute__((format (printf, __VA_ARGS__)))
    #define ATTRIB_MALLOC(...)      __attribute__((malloc, malloc (__VA_ARGS__)))
#else
    #define ATTRIB_PRINTF(...)      /**/
    #define ATTRIB_MALLOC(...)      /**/
#endif 

#include <stdint.h>
#include <stdio.h>

FILE *tbf_xfopen(const char path[restrict static 1],
                 const char mode[restrict static 1])
    ATTRIB_MALLOC(fclose, 1);

bool tbf_grow_array_and_append(void *restrict *     ptr,
                               size_t               capacity[restrict static 1],
                               size_t               count[restrict static 1],
                               size_t               elem_size, 
                               const void *restrict elem, 
                               size_t initial_count);

char *tbf_xread_file(const char path[restrict static 1],
                     FILE       stream[restrict static 1], 
                     size_t     nbytes[restrict static 1]);

int tbf_xfputs(const char s[static 1], FILE stream[static 1]);

int tbf_xprintf(const char format[static 1], ...) ATTRIB_PRINTF(1, 2);

int tbf_xfprintf(FILE stream[static 1], const char format[static 1], ...) 
    ATTRIB_PRINTF(2, 3);

int colored_fprintf(bool        color,
                    FILE        stream[static 1], 
                    const char  format[static 1], 
                    ...) ATTRIB_PRINTF(3, 4);

#endif                          /* TBF_UTIL_H */
