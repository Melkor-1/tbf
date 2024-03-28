# An Optimizing Brainfuck Interpreter and Transpiler 

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://https://github.com/Melkor-1/pyva/edit/main/LICENSE)

## Language:

The Brainfuck programming language consists of eight commands:
```none
> Increment the pointer.
< Decrement the pointer.
+ Increment the byte at the pointer.
- Decrement the byte at the pointer.
. Output the byte at the pointer.
, Input a byte and store it in the byte at the pointer.
[ Jump forward past the matching ] if the byte at the pointer is zero.
] Jump backward to the matching [ unless the byte at the pointer is zero.
```
 
 These commands translate to (assuming that `p` has been declared as a `char *`):
```c
> == ++p;
< == --p;
+ == ++*p;
- == ++-p;
. == putchar(*p);
, == *p = getchar();
[ == while (*p) {
] == }
```

## Implementation:

The implementation attempts to conform to the [The Unofficial Constraints on Portable Brainfuck Implementations](https://www.muppetlabs.com/~breadbox/bf/standards.html).

It first converts the source code to an intermediate representation -  which can be disassembled and printed to `stdout` in debug mode - and then interprets it. Sequences like `++++++++++` are collapsed to a single instruction `OP_INC (10)`. Each command is represented as a `struct` containing two fields `Op_Kind` and `operand`. For `+-.,><`, the operand holds the number of times the corresponding command is to be performed. For `[`, it holds the address of the location following the corresponding `]`. And for `]`, it holds the address of the location following the corresponding `[`.

There's another option to skip interpretation and transpile to C. The output for a sample program that prints "Hello World!" in Brainfuck:

```c
/*
 * XXX: This translation unit was automatically generated with
 *      tbf - The One Brainfuck Interpreter to Rule Them All.
 *      @Melkor-1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

typedef enum {
    BF_END_ERROR,
    BF_END_WRAP 
} Ov_Behavior;

#define INITIAL_TAPE_SIZE 30000
#define GROW_CAPACITY(capacity, initial) \
      ((capacity) < initial ? initial : (capacity) * 2)

typedef struct {
    unsigned char *mem;
    size_t head;
    size_t count;
    size_t capacity;
} Mem_Tape;

static void grow_tape_and_append(Mem_Tape t[static 1], unsigned char item)
{
    if (t->count >= t->capacity) {
        t->capacity = GROW_CAPACITY(t->capacity, INITIAL_TAPE_SIZE);
        void *const tmp = realloc(t->mem, t->capacity * sizeof t->mem[0]);

        if (!tmp) {
            fprintf(stderr, "Error: out of memory!\n");
            exit(EXIT_FAILURE);
        }
        t->mem = tmp;
    }
    memcpy(t->mem + (t->count * sizeof item), &item, sizeof item);
    t->count += 1;
}

static void grow_tape_and_append_many_zeroes(Mem_Tape t[static 1])
{
    while (t->head >= t->count) {
        grow_tape_and_append(t, 0);
    }
}
unsigned char chkd_mul(Ov_Behavior ov, unsigned char a, unsigned char b)
{
    if (ov == BF_END_ERROR) {
        if (a != 0 && b > UCHAR_MAX / a) {
            fprintf(stderr, "Error: cell value overflow.\n");
            exit(EXIT_FAILURE);
        }
    }
    return a * b;
}
static void dec_cell_val(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char subtrahend)
{
    if (ob == BF_END_ERROR) {
        if (t->mem[t->head] < subtrahend) {
            fprintf(stderr, "Error: cell value underflow.\n");
                exit(EXIT_FAILURE);
        }
    }
    t->mem[t->head] -= subtrahend;
}

static void inc_cell_val(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char addend)
{
    if (ob == BF_END_ERROR) {
        if (t->mem[t->head] + addend < t->mem[t->head]) {
            fprintf(stderr, "Error: cell value overflow.\n");
            exit(EXIT_FAILURE);
        }
    }
    t->mem[t->head] += addend;
}

static void inc_cell_ptr(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char addend)
{
    if (ob == BF_END_ERROR) {
        if (t->head + addend < t->head) {
            fprintf(stderr, "Error: cell pointer overflow.\n");
            exit(EXIT_FAILURE);
        }
    }
    t->head += addend;
    grow_tape_and_append_many_zeroes(t);
}

static void dec_cell_ptr(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char subtrahend) 
{
    if (ob == BF_END_ERROR) {
        if (t->head < subtrahend) {
            fprintf(stderr, "Error: cell pointer underflow.\n");
            exit(EXIT_FAILURE);
        }
        t->head -= subtrahend;
        return;
    }
    t->head = t->head < subtrahend ? t->count - (subtrahend - t->head) : t->head - subtrahend;
}

static void xgetchar_many(Mem_Tape t[static 1], size_t ncycles)
{
    clearerr(stdin);
    errno = 0;

    for (size_t i = 0; i < ncycles; ++i) {
        int c = getchar();

        if (c == EOF) {
            if (ferror(stdin)) {
                fprintf(stderr, "Error: A read operation failed: %s.\n",
                    errno ? strerror(errno) : "unknown error");
                exit(EXIT_FAILURE);
            }
        } else {
            t->mem[t->head] = (unsigned char) c;
        }
    }
}

void xgenerate_buf_and_fwrite(size_t size, int c)
{
    if (size > 1) {
        errno = 0;
        char *const buf = malloc(size);  

        if (buf == NULL) {
            if (errno) {
                perror("malloc()");
            } else {
                fprintf(stderr, "Fatal: Cannot allocate memory.\n");
            }
            exit(EXIT_FAILURE);
        }

        memset(buf, c, size);
        
        if (fwrite(buf, 1, size, stdout) != size) {
            free(buf);
            fprintf(stderr, "Fatal: A write operation failed.\n");
            exit(EXIT_FAILURE);
        }
        free(buf);
        fflush(stdout);
        return;
    }

    if (putchar(c) == EOF) {
        fprintf(stderr, "Fatal: A write operation failed.\n");
        exit(EXIT_FAILURE);
    }
    fflush(stdout);
}

int main(void)
{
    Mem_Tape t = {0};
    grow_tape_and_append(&t, 0);
    Ov_Behavior cell_val_ob = BF_END_WRAP;
    Ov_Behavior cell_ptr_ob = BF_END_WRAP;
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 9);
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, 8, t.mem[t.head + 1]));
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    t.mem[t.head] = 0;
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 7);
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, 4, t.mem[t.head + 1]));
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    t.mem[t.head] = 0;
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 1);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    inc_cell_val(cell_val_ob, &t, 7);
    xgenerate_buf_and_fwrite(2, t.mem[t.head]);
    inc_cell_val(cell_val_ob, &t, 3);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    if (cell_val_ob == BF_END_ERROR) {
        fprintf(stderr, "Error: cell value overflowed\n.");
        return EXIT_FAILURE;
    }
    t.mem[t.head] = 0;
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 8);
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, 4, t.mem[t.head + 1]));
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    t.mem[t.head] = 0;
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 11);
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, 8, t.mem[t.head + 1]));
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    t.mem[t.head] = 0;
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    dec_cell_val(cell_val_ob, &t, 1);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    dec_cell_val(cell_val_ob, &t, 8);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    inc_cell_val(cell_val_ob, &t, 3);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    dec_cell_val(cell_val_ob, &t, 6);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    dec_cell_val(cell_val_ob, &t, 8);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    if (cell_val_ob == BF_END_ERROR) {
        fprintf(stderr, "Error: cell value overflowed\n.");
        return EXIT_FAILURE;
    }
    t.mem[t.head] = 0;
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 8);
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, 4, t.mem[t.head + 1]));
    inc_cell_ptr(cell_ptr_ob, &t, 1);
    t.mem[t.head] = 0;
    dec_cell_ptr(cell_ptr_ob, &t, 1);
    inc_cell_val(cell_val_ob, &t, 1);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    if (cell_val_ob == BF_END_ERROR) {
        fprintf(stderr, "Error: cell value overflowed\n.");
        return EXIT_FAILURE;
    }
    t.mem[t.head] = 0;
    inc_cell_val(cell_val_ob, &t, 10);
    xgenerate_buf_and_fwrite(1, t.mem[t.head]);
    free(t.mem);
    return EXIT_SUCCESS;
}
```

Optimizations consisting of replacing simple loops like `[-]` and `[+]` with `*p = 0`, replacing loops doing addition, multiplication, or subtraction have been done. (But only whilst transpiling as of now)

Both the interpreter and transpiler have been tested on almost 20 different programs from [The Brainfuck Archive](https://sange.fi/esoteric/brainfuck/bf-source/prog/) and some others which claimed to be pathological and likely to break the interpreter/transpiler, and the code works correctly for them.

