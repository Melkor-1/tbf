/*
 * LOC: 970. (*.c, *.h)
 *
 */

#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#define _POSIX_C_SOURCE 200819L
#define _XOPEN_SOURCE   700

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include "assert.h"

#include <getopt.h>

#include "tbf_util.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ < 199901L
    #error "This program uses ISO C99. Upgrade to a better compiler."
#endif

#define INITIAL_TAPE_COUNT      32 * 1024
#define INITIAL_STACK_COUNT     1  * 1024
#define INITIAL_OP_COUNT        8  * 1024

/* *INDENT-OFF* */
typedef enum {
    BF_UNBALANCED_LOOP,
    BF_LOOP_END_BEFORE_START,
    BF_CELL_VAL_OVERFLOW,
    BF_CELL_VAL_UNDERFLOW,
    BF_CELL_PTR_OVERFLOW,
    BF_CELL_PTR_UNDERFLOW,
    BF_OUT_OF_MEMORY,
    BF_READ_FAILED,
    BF_WRITE_FAILED,
    BF_OK,
} Bf_Codes;

static const char *const error_msgs[] = {
    /* See: [Byte Positions Are Better Than Line
     * Numbers](https::/www.computerenhance.com/p/byte-positions-are-better-than-line)
     */
    [BF_UNBALANCED_LOOP]           = "%s[%zu]: error: unbalanced loop instruction '['.\n",
    [BF_LOOP_END_BEFORE_START]     = "%s[%zu]: error: trailing loop instruction ']'.\n",
    [BF_CELL_VAL_OVERFLOW]         = "%s: error: cell value overflowed.\n",
    [BF_CELL_VAL_UNDERFLOW]        = "%s: error: cell value underflowed.\n",
    [BF_CELL_PTR_OVERFLOW]         = "%s: error: cell pointer underflowed.\n",
    [BF_CELL_PTR_UNDERFLOW]        = "%s: error: cell pointer overflowed.\n",
    [BF_OUT_OF_MEMORY]             = "%s: error: out of memory.\n",
    [BF_READ_FAILED]               = "%s: error: a read operation failed: %s.\n",
    [BF_WRITE_FAILED]              = "%s: error: a write operation failed: %s.\n",
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    static_assert((sizeof error_msgs / sizeof error_msgs[0]) ==
        BF_OK, "Bf_Codes and error_msgs must kept be in sync!");
#endif

typedef enum {
    C_NONE,
    C_CLEAR,
    C_ADD_OR_MUL_TYPE1,
    C_ADD_OR_MUL_TYPE2,
    C_SUB_TYPE1,
    C_SUB_TYPE2
} C_Op_Kind;

typedef enum {
    OP_INC        = '+',
    OP_DEC        = '-',
    OP_GET        = ',',
    OP_PUT        = '.',
    OP_NEXT       = '>',
    OP_PREV       = '<',
    OP_LOOP_START = '[',
    OP_LOOP_END   = ']',
} Op_Kind;

typedef struct {
    const Op_Kind kind;
    size_t operand;
} Op;

typedef struct {
    Op *items;
    size_t count;
    size_t capacity;
} Ops;

typedef struct {
    const char *const content;
    size_t pos;
    const size_t count;
} Lexer;

typedef struct {
    size_t *items;
    size_t count;
    size_t capacity;
} Addr_Stack;

typedef struct {
    unsigned char *items;
    size_t count;
    size_t capacity;
} Mem_Tape;

typedef enum {
    BF_END_ERROR = 'e',
    BF_END_WRAP  = 'w'
} Ov_Behavior;

/* *INDENT-ON* */

typedef struct {
    FILE *output;               /* Output C source to FILE. Required with tflag. */
    Ov_Behavior vflag;          /* Cell value overflow behavior. */
    Ov_Behavior cflag;          /* Cell pointer overflow behavior. */
    bool tflag;                 /* Transpile to C. */
    bool pflag;                 /* Print colorful error messages. */
} flags;

#define OPSTRING    "v:c:tpo:h"

// There's a disrepancy between the transpiler and the interpreter in that the
// optimizations aren't done for the interpreter.
static void help(void)
{
    puts("Usage: tbf [OPTIONS] SRC\n\n"
        "  The uncompromising brainfuck interpreter.\n\n"
        "Options:\n"
        "    -v      value overflow/underflow behavior\n"
        "    -c      cell pointer overflow/underflow behavior\n"
        "    -t      skip interpretation and transpile to C\n"
        "    -p      print colorful error messages\n"
        "    -o      output C source file name (required with -t)\n"
        "    -h      this help message\n"
        "\n"
        "Overflow/Underflow behaviours can be one of:\n"
        "  e    throw an error and quit upon overflow/underflow\n"
        "  w    wrap-around to other end upon overflow/underflow (default)\n"
        "\n"
        "Note:\n"
        "    The -p flag assumes that the terminal supports ANSI escape\n"
        "    sequences.\n");
    exit(EXIT_SUCCESS);
}

static void err_and_exit(void)
{
    fprintf(stderr, "The syntax of the command is incorrect.\n"
        "Try tbf -h for more information.\n");
    exit(EXIT_FAILURE);
}

/* *INDENT-OFF* */
static void parse_options(int           argc,
                          char *        argv[static argc], 
                          const char    opstring[static 1], 
                          flags         opt_ptr[static 1])
/* *INDENT-ON* */

{
    int c = 0;

    while ((c = getopt(argc, argv, opstring)) != -1) {
        switch (c) {
            case 'v':
            case 'c': {
                int arg = optarg[0];

                if (arg != BF_END_WRAP && arg != BF_END_ERROR) {
                    fprintf(stderr, "Error: invalid argument for -%c.\n", c);
                    
                    if (opt_ptr->output != stdout) {
                        fclose(opt_ptr->output);
                    }
                    err_and_exit();
                }

                *(c == 'v' ? &opt_ptr->vflag : &opt_ptr->cflag) = arg;
            } break;

            case 't':
                opt_ptr->tflag = true;
                break;

            case 'o':
                /* Multiple -o flags? Which one to use? Not checking this would 
                 * cause a resource leak. 
                 */
                if (opt_ptr->output != stdout) {
                    fprintf(stderr, "Error: multiple -o flags provided.\n");
                    fclose(opt_ptr->output);
                    err_and_exit();
                }
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
                /* Fail if file already exists. */
                opt_ptr->output = tbf_xfopen(optarg, "wbx");
#else
                /* Overwrite it for now. We could open it in append mode later
                 * during transpilation.
                 */
                opt_ptr->output = tbf_xfopen(optarg, "wb");
#endif
                break;

            case 'p':
                opt_ptr->pflag = true;
                break;

            case 'h':
                if (opt_ptr->output != stdout) {
                    fclose(opt_ptr->output);
                }

                help();
                /* FALLTHROUGH */

                /* case '?' */
            default:
                if (opt_ptr->output != stdout) {
                    fclose(opt_ptr->output);
                }

                err_and_exit();
        }
    }

    /* If -o was provided without -t: */
    if (opt_ptr->output != stdout && !opt_ptr->tflag) {
        fprintf(stderr, "Error: -o provided without -t.\n");
        fclose(opt_ptr->output);
        err_and_exit();
    }
}

static C_Op_Kind check_is_sub(size_t ip, Ops ops[static 1])
{
    if (ip + 5 < ip || ip + 5 > ops->count) {
        return C_NONE;
    }

    /* Check `[<->-]` pattern.
     *
     * This sets the first cell to the difference of the first and second cells.
     * It is destructive in that the value in the second cell is lost and
     * cleared .It further increments the head pointer by 1.
     *
     */
    if (ops->items[ip + 1].kind == OP_PREV
        && ops->items[ip + 1].operand == 1
        && ops->items[ip + 2].kind == OP_DEC
        && ops->items[ip + 2].operand == 1 
        && ops->items[ip + 3].kind == OP_NEXT
        && ops->items[ip + 3].operand == 1
        && ops->items[ip + 4].kind == OP_DEC
        && ops->items[ip + 4].operand == 1
        && ops->items[ip + 5].kind == OP_LOOP_END) {
        return C_SUB_TYPE1;
    }

    /* Check `[>-<-]` pattern.
     *
     * This sets the second cell to the difference of the first and second cells.
     * It is destructive in that the value in the first cell is lost and cleared. 
     * It leaves the head pointer in its original place.
     */
    if (ops->items[ip + 1].kind == OP_NEXT
        && ops->items[ip + 1].operand == 1
        && ops->items[ip + 2].kind == OP_DEC
        && ops->items[ip + 2].operand == 1
        && ops->items[ip + 3].kind == OP_PREV
        && ops->items[ip + 3].operand == 1
        && ops->items[ip + 4].kind == OP_DEC
        && ops->items[ip + 4].operand == 1
        && ops->items[ip + 5].kind == OP_LOOP_END) {
        return C_SUB_TYPE2;
    }

    return C_NONE;

}

static C_Op_Kind check_is_clear(size_t ip, Ops ops[static 1])
{
    if ((ip + 2) < ip || ip + 2 > ops->count) {
        return C_NONE;
    }

    /* Check both `[-]` and `[+]`. As the values wrap-around on overflow, the 
     * second one would stop looping when the current cell becomes zero. 
     */
    if ((ops->items[ip + 1].kind == OP_DEC || ops->items[ip + 1].kind == OP_INC)
        && ops->items[ip + 1].operand == 1
        && ops->items[ip + 2].kind == OP_LOOP_END) {
        return C_CLEAR;
    }
    return C_NONE;
}

/* The only difference between multiplication's and addition's patterns is that 
 * in addition, the '+' command only appears once.
 */
static C_Op_Kind check_is_add_or_mul(size_t ip, Ops ops[static 1])
{
    if ((ip + 5) < ip || ip + 5 > ops->count) {
        return C_NONE;
    }

    /* Check `[<++++>-]` pattern.
     *
     * This sets the first cell to the product of the first and second cells.
     * It is destructive in that the value in the second cell is lost and
     * cleared .It further increments the head pointer by 1.
     *
     */
    if (ops->items[ip + 1].kind == OP_PREV
        && ops->items[ip + 1].operand == 1
        && ops->items[ip + 2].kind == OP_INC
        && ops->items[ip + 3].kind == OP_NEXT
        && ops->items[ip + 3].operand == 1
        && ops->items[ip + 4].kind == OP_DEC
        && ops->items[ip + 4].operand == 1
        && ops->items[ip + 5].kind == OP_LOOP_END) {
        return C_ADD_OR_MUL_TYPE1;
    }

    /* Check `[>++++<-]` pattern.
     *
     * This sets the second cell to the product of the first and second cells.
     * It is destructive in that the value in the first cell is lost and cleared. 
     * It leaves the head pointer in its original place.
     */
    if (ops->items[ip + 1].kind == OP_NEXT
        && ops->items[ip + 1].operand == 1
        && ops->items[ip + 2].kind == OP_INC
        && ops->items[ip + 3].kind == OP_PREV
        && ops->items[ip + 3].operand == 1
        && ops->items[ip + 4].kind == OP_DEC
        && ops->items[ip + 4].operand == 1
        && ops->items[ip + 5].kind == OP_LOOP_END) {
        return C_ADD_OR_MUL_TYPE2;
    }

    return C_NONE;
}

static inline bool append_op(Ops ops[static 1], Op item)
{
    return tbf_grow_array_and_append((void **) &ops->items, &ops->capacity,
        &ops->count, sizeof ops->items[0], &item, INITIAL_OP_COUNT);
}

static inline bool push_addr_stack(Addr_Stack s[static 1], size_t item)
{
    return tbf_grow_array_and_append((void **) &s->items, &s->capacity,
        &s->count, sizeof s->items[0], &item, INITIAL_STACK_COUNT);
}

static inline size_t pop_addr_stack(Addr_Stack s[static 1])
{
    /* We check if the stack is empty before calling this function, so the 
     * following is fine. 
     */
    return s->items[--s->count];
}

static inline bool append_tape(Mem_Tape tape[static 1], unsigned char item)
{
    return tbf_grow_array_and_append((void **) &tape->items, &tape->capacity,
        &tape->count, sizeof tape->items[0], &item, INITIAL_TAPE_COUNT);
}

static Bf_Codes transpile(Ops ops[static 1], flags options[static 1])
{
    tbf_xfputs(
        "/*\n"
        " * XXX: This translation unit was automatically generated with\n"
        " *      tbf - The One Brainfuck Interpreter to Rule Them All.\n"
        " *      @Melkor-1\n"
        " */\n"
        "\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <stdint.h>\n"
        "#include <errno.h>\n"
        "#include <limits.h>\n"
        "\n"
        "typedef enum {\n"
        "    BF_END_ERROR,\n"
        "    BF_END_WRAP \n"
        "} Ov_Behavior;\n"
        "\n"
        "#define INITIAL_TAPE_SIZE 30000\n"
        "#define GROW_CAPACITY(capacity, initial) \\\n"
        "      ((capacity) < initial ? initial : (capacity) * 2)\n"
        "\n"
        "typedef struct {\n"
        "    unsigned char *mem;\n"
        "    size_t head;\n"
        "    size_t count;\n"
        "    size_t capacity;\n"
        "} Mem_Tape;\n"
        "\n"
        "static void grow_tape_and_append(Mem_Tape t[static 1], unsigned char item)\n"
        "{\n"
        "    if (t->count >= t->capacity) {\n"
        "        t->capacity = GROW_CAPACITY(t->capacity, INITIAL_TAPE_SIZE);\n"
        "        void *const tmp = realloc(t->mem, t->capacity * sizeof t->mem[0]);\n"
        "\n"
        "        if (!tmp) {\n"
        "            fprintf(stderr, \"Error: out of memory!\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "        t->mem = tmp;\n"
        "    }\n"
        "    memcpy(t->mem + (t->count * sizeof item), &item, sizeof item);\n"
        "    t->count += 1;\n"
        "}\n"
        "\n"
        "static void grow_tape_and_append_many_zeroes(Mem_Tape t[static 1])\n"
        "{\n"
        "    while (t->head >= t->count) {\n"
        "        grow_tape_and_append(t, 0);\n"
        "    }\n"
        "}\n"
        "unsigned char chkd_mul(Ov_Behavior ov, unsigned char a, unsigned char b)\n"
        "{\n"
        "    if (ov == BF_END_ERROR) {\n"
        "        if (a != 0 && b > UCHAR_MAX / a) {\n"
        "            fprintf(stderr, \"Error: cell value overflowed.\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "    }\n"
        "    return a * b;\n"
        "}\n"
        "static void dec_cell_val(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char subtrahend)\n"
        "{\n"
        "    if (ob == BF_END_ERROR) {\n"
        "        if (t->mem[t->head] < subtrahend) {\n"
        "            fprintf(stderr, \"Error: cell value underflowed.\\n\");\n"
        "                exit(EXIT_FAILURE);\n"
        "        }\n"
        "    }\n"
        "    t->mem[t->head] -= subtrahend;\n"
        "}\n"
        "\n"
        "static void inc_cell_val(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char addend)\n"
        "{\n"
        "    if (ob == BF_END_ERROR) {\n"
        "        if (t->mem[t->head] + addend < t->mem[t->head]) {\n"
        "            fprintf(stderr, \"Error: cell value overflowed.\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "    }\n"
        "    t->mem[t->head] += addend;\n"
        "}\n"
        "\n"
        "static void inc_cell_ptr(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char addend)\n"
        "{\n"
        "    if (ob == BF_END_ERROR) {\n"
        "        if (t->head + addend < t->head) {\n"
        "            fprintf(stderr, \"Error: cell pointer overflowed.\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "    }\n"
        "    t->head += addend;\n"
        "    grow_tape_and_append_many_zeroes(t);\n"
        "}\n"
        "\n"
        "static void dec_cell_ptr(Ov_Behavior ob, Mem_Tape t[static 1], unsigned char subtrahend) \n"
        "{\n"
        "    if (ob == BF_END_ERROR) {\n"
        "        if (t->head < subtrahend) {\n"
        "            fprintf(stderr, \"Error: cell pointer u7nderflow.\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "        t->head -= subtrahend;\n"
        "        return;\n"
        "    }\n"
        "    t->head = t->head < subtrahend ? t->count - (subtrahend - t->head) : t->head - subtrahend;\n"
        "}\n"
        "\n"
        "static void xgetchar_many(Mem_Tape t[static 1], size_t ncycles)\n"
        "{\n"
        "    clearerr(stdin);\n"
        "    errno = 0;\n"
        "\n"
        "    for (size_t i = 0; i < ncycles; ++i) {\n"
        "        int c = getchar();\n"
        "\n"
        "        if (c == EOF) {\n"
        "            if (ferror(stdin)) {\n"
        "                fprintf(stderr, \"Error: A read operation failed: %s.\\n\",\n"
        "                    errno ? strerror(errno) : \"unknown error\");\n"
        "                exit(EXIT_FAILURE);\n"
        "            }\n"
        "        } else {\n"
        "            t->mem[t->head] = (unsigned char) c;\n"
        "        }\n"
        "    }\n"
        "}\n"
        "\n", options->output);

    tbf_xfprintf(options->output,
        "void xgenerate_buf_and_fwrite(size_t size, int c)\n"
        "{\n"
        "    if (size > 1) {\n"
        "        errno = 0;\n"
        "        char *const buf = malloc(size);  \n"
        "\n"
        "        if (buf == NULL) {\n"
        "            if (errno) {\n"
        "                perror(\"malloc()\");\n"
        "            } else {\n"
        "                fprintf(stderr, \"Fatal: Cannot allocate memory.\\n\");\n"
        "            }\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "\n"
        "        memset(buf, c, size);\n"
        "        \n"
        "        if (fwrite(buf, 1, size, stdout) != size) {\n"
        "            free(buf);\n"
        "            fprintf(stderr, \"Fatal: A write operation failed.\\n\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "        free(buf);\n"
        "        fflush(stdout);\n"
        "        return;\n"
        "    }\n"
        "\n"
        "    if (putchar(c) == EOF) {\n"
        "        fprintf(stderr, \"Fatal: A write operation failed.\\n\");\n"
        "        exit(EXIT_FAILURE);\n"
        "    }\n"
        "    fflush(stdout);\n"
        "}\n"
        "\n"
        "int main(void)\n"
        "{\n"
        "    Mem_Tape t = {0};\n"
        "    grow_tape_and_append(&t, 0);\n"
        "    Ov_Behavior cell_val_ob = %s;\n"
        "    Ov_Behavior cell_ptr_ob = %s;\n",
        options->vflag == BF_END_ERROR ? "BF_END_ERROR" : "BF_END_WRAP",
        options->cflag == BF_END_ERROR ? "BF_END_ERROR" : "BF_END_WRAP");

    size_t ip = 0;

    while (ip < ops->count) {
        Op op = ops->items[ip];

        switch (op.kind) {
            case OP_INC:
                /* Exit on failure. Else we'd have to check 8 calls individually. */
                tbf_xfprintf(options->output,
                    "    inc_cell_val(cell_val_ob, &t, %zu);\n", op.operand);
                ++ip;
                break;

            case OP_DEC:
                tbf_xfprintf(options->output,
                    "    dec_cell_val(cell_val_ob, &t, %zu);\n", op.operand);
                ++ip;
                break;

            case OP_PUT:
                tbf_xfprintf(options->output,
                    "    xgenerate_buf_and_fwrite(%zu, t.mem[t.head]);\n",
                    op.operand);
                ++ip;
                break;

            case OP_GET:
                tbf_xfprintf(options->output, "    xgetchar_many(&t, %zu);\n",
                    op.operand);
                ++ip;
                break;

            case OP_NEXT:
                tbf_xfprintf(options->output,
                    "    inc_cell_ptr(cell_ptr_ob, &t, %zu);\n", op.operand);
                ++ip;
                break;

            case OP_PREV:
                tbf_xfprintf(options->output,
                    "    dec_cell_ptr(cell_ptr_ob, &t, %zu);\n", op.operand);
                ++ip;
                break;

            case OP_LOOP_START: {
                C_Op_Kind rv = 0;

                if (rv = check_is_clear(ip, ops)) {
                    tbf_xfputs("    if (cell_val_ob == BF_END_ERROR) {\n"
                               "        fprintf(stderr, \"Error: cell value overflowed\\n.\");\n"
                               "        return EXIT_FAILURE;\n"
                               "    }\n"
                               "    t.mem[t.head] = 0;\n", 
                               options->output);
                    ip = op.operand;
                } else if (rv = check_is_add_or_mul(ip, ops)) {
                    if (rv == C_ADD_OR_MUL_TYPE1) {
                        tbf_xfprintf(options->output,
                            "    dec_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, %zu, t.mem[t.head + 1]));\n"
                            "    inc_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    t.mem[t.head] = 0;\n",
                            ops->items[ip + 2].operand);

                    } else {
                        tbf_xfprintf(options->output,
                            "    inc_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    inc_cell_val(cell_val_ob, &t, chkd_mul(cell_val_ob, %zu, t.mem[t.head - 1]));\n" 
                            "    dec_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    t.mem[t.head] = 0;\n",
                            ops->items[ip + 2].operand);
                    }
                    ip = op.operand;
                } else if (rv = check_is_sub(ip, ops)) {
                    if (rv == C_SUB_TYPE1) {
                        tbf_xfprintf(options->output,
                            "    dec_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    dec_cell_val(cell_val_ob, &t, t.mem[t.head + 1]);\n"
                            "    inc_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    t.mem[t.head] = 0;\n");
                    } else {
                        tbf_xfprintf(options->output,
                            "    inc_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    dec_cell_val(cell_val_ob, &t, t.mem[t.head - 1]);\n"
                            "    dec_cell_ptr(cell_ptr_ob, &t, 1);\n"
                            "    t.mem[t.head] = 0;\n");
                    }
                    ip = op.operand;
                } else {
                    tbf_xfputs("    while (t.mem[t.head] != 0) {\n",
                        options->output);
                    ++ip;
                }
            } break;

            case OP_LOOP_END:
                tbf_xfputs("    }\n", options->output);
                ++ip;
                break;
        }
    }
    tbf_xfputs("    free(t.mem);\n"
        "    return EXIT_SUCCESS;\n" "}\n", options->output);
    return BF_OK;
}

static Bf_Codes interpret(Ops ops[static 1], flags options[static 1])
{
    Mem_Tape tape = { 0 };

    if (!append_tape(&tape, 0)) {
        return BF_OUT_OF_MEMORY;
    }

    /* Should head and ip be part of the Mem_Tape structure? */
    size_t head = 0;
    size_t ip = 0;

    while (ip < ops->count) {
        Op op = ops->items[ip];

        switch (op.kind) {
            case OP_INC:
                if (options->vflag == BF_END_ERROR
                    && (tape.items[head] + op.operand < tape.items[head])) {
                    free(tape.items);
                    return BF_CELL_VAL_OVERFLOW;
                }
                tape.items[head] += (unsigned char) op.operand;
                ++ip;
                break;

            case OP_DEC:
                if (options->vflag == BF_END_ERROR
                    && tape.items[head] < op.operand) {
                    free(tape.items);
                    return BF_CELL_VAL_UNDERFLOW;
                }
                tape.items[head] -= (unsigned char) op.operand;
                ++ip;
                break;

            case OP_GET:
                clearerr(stdin);

                for (size_t i = 0; i < op.operand; ++i) {
                    int c = getchar();

                    /* An argument for leaving the cell's value unchanged:
                     * brainfuck.org/epistle.html
                     */
                    if (c == EOF) {
                        if (ferror(stdin)) {
                            free(tape.items);
                            return BF_READ_FAILED;
                        }
                    } else {
                        tape.items[head] = (unsigned char) c;
                    }
                }
                ++ip;
                break;

            case OP_PUT:
                for (size_t i = 0; i < op.operand; ++i) {
                    if (putchar(tape.items[head]) == EOF) {
                        free(tape.items);
                        return BF_WRITE_FAILED;
                    }
                }
                fflush(stdout);
                ++ip;
                break;

            case OP_NEXT:
                /* Check for patterns here. */
                if ((options->cflag == BF_END_ERROR)
                    && (head + op.operand < head)) {
                    free(tape.items);
                    return BF_CELL_PTR_OVERFLOW;
                }
                head += op.operand;

                while (head >= tape.count) {
                    if (!append_tape(&tape, 0)) {
                        free(tape.items);
                        return BF_OUT_OF_MEMORY;
                    }
                }
                ++ip;
                break;

            case OP_PREV:
                if (head < op.operand) {
                    if (options->cflag == BF_END_ERROR) {
                        free(tape.items);
                        return BF_CELL_PTR_UNDERFLOW;
                    }
                    head = tape.count - (op.operand - head);
                } else {
                    head -= op.operand;
                }

                ++ip;
                break;

            case OP_LOOP_START:
                if (tape.items[head] != 0) {
                    C_Op_Kind rv = 0;

                    if (rv = check_is_clear(ip, ops)) {
                        if (options->vflag == BF_END_ERROR) {
                            free(tape.items);
                            return BF_CELL_VAL_OVERFLOW;
                        }
                        tape.items[head] = 0;
                        ip = op.operand;
                    } else {
                        ++ip;
                    }
                } else {
                    ip = op.operand;
                } break;

                /* TODO: Replicate optimizations for add, mul, and sub like the
                 * transpiler. */

            case OP_LOOP_END:
                ip = tape.items[head] != 0 ? op.operand : ip + 1;
                break;
        }
    }
    free(tape.items);
    return BF_OK;
}

static bool is_valid_bf_cmd(int cmd)
{
    static const unsigned char bf_cmds[] = {
        OP_INC,
        OP_DEC,
        OP_GET,
        OP_PUT,
        OP_NEXT,
        OP_PREV,
        OP_LOOP_START,
        OP_LOOP_END
    };

    return memchr(bf_cmds, cmd, sizeof bf_cmds) != nullptr;
}

static char get_next_lexeme(Lexer * l)
{
    while (l->pos < l->count && !is_valid_bf_cmd(l->content[l->pos])) {
        ++l->pos;
    }

    return l->pos >= l->count ? 0 : l->content[l->pos++];
}

/* *INDENT-OFF* */
static Bf_Codes generate_ops(size_t     nbytes,
                             const char code[static restrict nbytes],
                             Ops        ops[static restrict 1], 
                             size_t     byte_offset[static restrict 1])
/* *INDENT-ON* */

{
    Lexer l = {
        .content = code,
        .pos = 0,
        .count = nbytes
    };

    Addr_Stack stack = { 0 };
    size_t prev_op_loop_start = 0;
    char lexeme = get_next_lexeme(&l);

    while (lexeme) {
        switch (lexeme) {
            case OP_INC:
            case OP_DEC:
            case OP_GET:
            case OP_PUT:
            case OP_NEXT:
            case OP_PREV: {
                size_t op_count = 1;
                char next_lexeme = get_next_lexeme(&l);

                while (lexeme == next_lexeme) {
                    ++op_count;
                    next_lexeme = get_next_lexeme(&l);
                }

                if (!append_op(ops, (Op) { lexeme, op_count})) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                lexeme = next_lexeme;
            } break;

            case OP_LOOP_START: {
                size_t addr = ops->count;

                if (!append_op(ops, (Op) { lexeme, 0})) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                if (!push_addr_stack(&stack, addr)) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }
                prev_op_loop_start = l.pos;
                lexeme = get_next_lexeme(&l);
            } break;

            case OP_LOOP_END:{
                if (stack.count == 0) {
                    *byte_offset = l.pos;
                    return BF_LOOP_END_BEFORE_START;
                }

                size_t addr = pop_addr_stack(&stack);

                if (!append_op(ops, (Op) { lexeme, addr + 1})) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                /* Backpatch. */
                ops->items[addr].operand = ops->count;
                lexeme = get_next_lexeme(&l);
            } break;
        }
    }

    free(stack.items);

    if (stack.count > 0) {
        *byte_offset = prev_op_loop_start;
        return BF_UNBALANCED_LOOP;
    }
    return BF_OK;
}

#ifdef NDEBUG
static void disassemble_ops(Ops ops[static 1])
{
    puts("== ops ==\n");

    for (size_t i = 0; i < ops->count; ++i) {
        printf("%zu: %c (%zu)\n", i, ops->items[i].kind, ops->items[i].operand);
    }

    puts("== ops ==\n");
}
#endif                          /* NDEBUG */

int main(int argc, char **argv)
{
    /* Sanity check. POSIX requires the invoking process to pass a non-null
     * argv[0].
     */
    if (!argv[0]) {
        fputs("A NULL argv[0] was passed in through an exex system call.\n",
            stderr);
        return EXIT_FAILURE;
    }

    FILE *in_file = stdin;

    /* *INDENT-OFF* */
    flags options = {
        .output   = stdout,
        .vflag    = 0,
        .cflag    = 0,
        .tflag    = false,
        .pflag    = false
    };
    /* *INDENT-ON* */

    parse_options(argc, argv, OPSTRING, &options);

    if ((optind + 1) == argc) {
        in_file = tbf_xfopen(argv[optind], "rb");
    } else if (optind > argc || argv[optind + 1] != nullptr) {
        err_and_exit();
    }

    const char *const in_fname = argv[optind];

    size_t nbytes = 0;
    char *const src = tbf_xread_file(in_fname, in_file, &nbytes);

    Ops ops = { 0 };
    size_t byte_offset = 0;
    Bf_Codes rc = generate_ops(nbytes, src, &ops, &byte_offset);
    int status = EXIT_FAILURE;

    free(src);

    if (rc != BF_OK) {
        switch (rc) {
            case BF_READ_FAILED:
            case BF_WRITE_FAILED:
                colored_fprintf(options.pflag, stderr, error_msgs[rc], in_fname,
                    errno ? strerror(errno) : "unexpected error");
                break;

            case BF_OUT_OF_MEMORY:
                colored_fprintf(options.pflag, stderr, error_msgs[rc],
                    in_fname);
                break;

            case BF_UNBALANCED_LOOP:
            case BF_LOOP_END_BEFORE_START:
                colored_fprintf(options.pflag, stderr, error_msgs[rc], in_fname,
                    byte_offset);
                break;
        }
        goto cleanup;
    }
#ifdef NDEBUG
    disassemble_ops(&ops);
#endif
    rc = (options.tflag ? transpile : interpret) (&ops, &options);

    printf("%d\n", rc);
    printf("%d\n", BF_CELL_VAL_OVERFLOW);
    if (rc != BF_OK) {
        colored_fprintf(options.pflag, stderr, error_msgs[rc], in_fname);
    }
    status = EXIT_SUCCESS;

  cleanup:
    free(ops.items);
    fclose(in_file);
    
    if (options.output != stdout) {
        fclose(options.output);
    }
    return status;
}
