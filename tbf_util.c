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

#define ANSI_COLOR_RED      "\x1b[31m"
#define ANSI_COLOR_RESET    "\x1b[0m"

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

bool tbf_grow_array_and_append(void *restrict *     ptr,
                               size_t               capacity[restrict static 1],
                               size_t               count[restrict static 1],
                               size_t               elem_size, 
                               const void *restrict elem, 
                               size_t initial_count)
{
    if (*count >= *capacity) {
        *capacity = GROW_CAPACITY(*capacity, initial_count);
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

char *tbf_xread_file(const char path[restrict static 1],
                     FILE       stream[restrict static 1], 
                     size_t     nbytes[restrict static 1])
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

int colored_fprintf(bool        color,
                    FILE        stream[static 1], 
                    const char  format[static 1], 
                    ...)
{
    if (color) {
        fprintf(stderr, ANSI_COLOR_RED);
    }

    va_list args;

    va_start(args, format);
    int rv = vfprintf(stream, format, args);

    va_end(args);

    if (color) {
        fprintf(stderr, ANSI_COLOR_RESET);
    }

    return rv;
}
