#include "tbf_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#define GROW_CAPACITY(capacity, initial) \
        ((capacity) < initial ? initial : (capacity) * 2)

#define INITIAL_CHUNK_SIZE      1024 * 64
#define INITIAL_ARRAY_COUNT     1024 * 4

/* Reference: https://stackoverflow.com/a/66046867/20017547 
 * @chux - Reinstate Monica
 */
bool tbf_strtoi64(int64_t value[static 1], const char s[static 1])
{
    char *endptr = nullptr;

    errno = 0;
    long long v = strtoll(s, &endptr, 0);

    /* Optional code for future growth of `long long`: */
    #if LLONG_MIN < INT64_MIN || LLONG_MAX > INT64_MAX
    if (v < INT64_MIN) {
        v = INT64_MIN;
        errno = ERANGE;
    } else if (v > INT64_MIN) {
        v = INT64_MAX;
        errno = ERANGE;
    }
    #endif

    *value = (int64_t) v;

    /* The check for errno goes suffices for both ERANGE and others. */
    if (s == endptr || errno) {
        return false;
    }

    while (isspace(*(unsigned char *) endptr)) {
        ++endptr;
    }

    /* Non-numeric trailing text? */
    return *endptr ? false : true;
}

/* Reference: https://stackoverflow.com/a/72980376/20017547
 * @chux - Reinstate Monica
 */
bool tbf_strtou64(uint64_t value[static 1], const char s[static 1])
{
    char *endptr = nullptr;

    errno = 0;
    long long ival = strtoull(s, &endptr, 0);

    if (ival < 0) {
        errno = ERANGE;
        return false;
    }
    
    /* We are done for positive numbers under INT64_MAX. */
    if (endptr > s && ival <= INT64_MAX && errno == 0) {
        *value = (uint64_t) ival;
        return true;
    }
    
    /* Input may still be a valid value in the range [INT64_MAX, UINT64_MAX]. */
    errno = 0;
    unsigned long long uval = strtoull(s, &endptr, 0);

    #if ULLONG_MAX > UINT64_MAX
    if (uval > UINT64_MAX) {
        uval = UINT64_MAX;
        errno = ERANGE;
    }     
    #endif

    *value = (uint64_t) uval;

    /* The check for errno goes suffices for both ERANGE and others. */
    if (s == endptr || errno) {
        return false;
    }

    while (isspace(*(unsigned char *) endptr)) {
        ++endptr;
    }

    /* Non-numeric trailing text? */
    return *endptr ? false : true;
}

FILE *tbf_xfopen(const char path[restrict static 1],
                 const char mode[restrict static 1])

{
    errno = 0;
    FILE *const f = fopen(path, mode);

    if (f == nullptr) {
        fprintf(stderr, "Error: failed to process file %s: %s.\n",
            path, errno ? strerror(errno) : "unknown error");
        exit(EXIT_FAILURE);
    }

    return f;
}

bool tbf_grow_array_and_append(void *restrict *      ptr,
                               size_t                capacity[restrict static 1],
                               size_t                count[restrict static 1], 
                               size_t                elem_size, 
                               const void *restrict  elem)
{
    if (*count >= *capacity) {
        *capacity = GROW_CAPACITY(*capacity, INITIAL_ARRAY_COUNT);
        void *const tmp = realloc(*ptr, *capacity * elem_size);

        if (tmp == nullptr) {
            return false;
        }
        *ptr = tmp;
    }

    memcpy((char *) *ptr + (*count * elem_size), elem, elem_size);
    *count += 1;
    return true;
}

char *tbf_xread_file(const char  path[restrict static 1],
                     FILE        stream[restrict static 1], 
                     size_t      nbytes[restrict static 1])
{
    char *content = nullptr;
    size_t len = 0;
    size_t capacity = 0;

    for (size_t rcount = 1; rcount > 0; len += rcount) {
        capacity = GROW_CAPACITY(capacity, INITIAL_CHUNK_SIZE);

        errno = 0;
        void *const tmp = realloc(content, capacity + 1);

        if (tmp == nullptr) {
            fprintf(stderr, "Error: failed to read file %s: %s.\n",
                path, errno ? strerror(errno) : "unknown error");
            exit(EXIT_FAILURE);
        }
        content = tmp;
        errno = 0;
        rcount = fread(content + len, 1, capacity - len, stream);

        if (rcount < capacity - len) {
            if (!feof(stream)) {
                fprintf(stderr, "Error: failed to read file %s: %s.\n",
                    path, errno ? strerror(errno) : "unknown error");
                exit(EXIT_FAILURE);
            }
            /* If we break on the first iteration. */
            len += rcount;
            break;
        }
    }

    *nbytes = len;
    content[len] = '\0';
    return content;
}

int tbf_xfputs(const char s[static 1], FILE stream[static 1])
{
    int rv = fputs(s, stream);

    if (rv == EOF) {
        /* This too would likely fail if `stream` was stderr. */
        fprintf(stderr, "Fatal: A write operation failed.\n");
        exit(EXIT_FAILURE);
    }

    return rv;
}

int tbf_xprintf(const char format[static 1], ...) 
{
    va_list args;
    va_start(args, format);
    int rv = vprintf(format, args);
    va_end(args);

    if (rv < 0) {
        /* If stdout got errors, stderr could still be writable.  Redirection 
         * is a common example (you could redirect stdout using a shell or
         * freopen, whilst leaving stderr connected to the console.)
         */
        fprintf(stderr, "Fatal: A write operation failed.\n");
        exit(EXIT_FAILURE);
    }

    return rv;
}

int tbf_xfprintf(FILE stream[static 1], const char format[static 1], ...) 
{
    va_list args;
    va_start(args, format);
    int rv = vfprintf(stream, format, args);
    va_end(args);

    if (rv < 0) {
        /* This too would likely fail if `stream` was stderr. */
        fprintf(stderr, "Fatal: A write operation failed.\n");
        exit(EXIT_FAILURE);
    }

    return rv;
}
