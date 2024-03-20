/*
 * LOC: 750. (*.c, *.h)
 *
 * TODO: REPL? Perhaps?
 *       CLI flags customization?
 *       Native code with QBE?
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "tbf_util.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ < 199901L
    #error "This program uses ISO C99. Get a better compiler."
#endif

typedef enum {
    BF_OK,
    BF_OUT_OF_MEMORY,
    BF_UNBALANCED_LOOP,
    BF_LOOP_END_BEFORE_START,
    BF_READ_FAILED,
    BF_WRITE_FAILED,
} Bf_Codes;

static const char *const error_msgs[] = {
    /* See: [Byte Positions Are Better Than Line
     * Numbers](https::/www.computerenhance.com/p/byte-positions-are-better-than-line)
     */
    [BF_UNBALANCED_LOOP]       = "%s[%zu]: error: unbalanced loop instruction '['.\n",
    [BF_LOOP_END_BEFORE_START] = "%s[%zu]: error: trailing loop instruction ']'.\n",
    [BF_OUT_OF_MEMORY]         = "%s: error: out of memory.\n",
    [BF_READ_FAILED]           = "%s: error: a read operation failed: %s.\n",
    [BF_WRITE_FAILED]          = "%s: error: a write operation failed: %s.\n",
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    static_assert((sizeof error_msgs / sizeof error_msgs[0]) ==
        BF_WRITE_FAILED + 1, "Bf_Codes and error_msgs must kept be in sync!");
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

#define ANSI_COLOR_RED      "\x1b[31m"
#define ANSI_COLOR_RESET    "\x1b[0m"

static const char *pretty_print(bool color)
{
    return color ? ANSI_COLOR_RED "%s" ANSI_COLOR_RESET "\n" : "%s";
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
     * second one would stop looping when the currend cell becomes zero. 
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
        &ops->count, sizeof ops->items[0], &item);
}

static inline bool push_addr_stack(Addr_Stack s[static 1], size_t item)
{
    return tbf_grow_array_and_append((void **) &s->items, &s->capacity, &s->count,
        sizeof s->items[0], &item);
}

static inline bool append_tape(Mem_Tape tape[static 1], unsigned char item)
{
    return tbf_grow_array_and_append((void **) &tape->items, &tape->capacity,
        &tape->count, sizeof tape->items[0], &item);
}

static inline size_t pop_addr_stack(Addr_Stack s[static 1])
{
    /* We check if the stack is empty before calling this function, so the 
     * following is fine. 
     */
    return s->items[--s->count];
}

static bool transpile(Ops ops[static 1])
{
    /* Perhaps all of this could go into a buffer before being dumped to a 
     * FILE. 
     */
    puts("/*\n"
        " * XXX: This translation unit was automatically generated with\n"
        " *      tbf - The One Brainfuck Interpreter to Rule Them All.\n"
        " *      @Melkor-1\n"
        " */\n"
        "\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <errno.h>\n"
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
        "static void grow_tape_and_append(Mem_Tape *t, unsigned char item)\n"
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
        "static void xgetchar_many(Mem_Tape t[static 1], size_t ncycles)\n"
        "{\n"
        "    errno = 0;\n"
        "\n"
        "    for (size_t i = 0; i < ncycles; ++i) {\n"
        "        int c = 0;\n"
        "        if ((c = getchar()) == EOF) {\n"
        "            fprintf(stderr, \"Error: A read operation failed: %s.\\n\",\n"
        "                errno ? strerror(errno) : \"unknown error\");\n"
        "            exit(EXIT_FAILURE);\n"
        "        }\n"
        "        t->mem[t->head] = c;\n"
        "    }\n"
        "}\n"
        "\n"
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
        "static void grow_tape_and_append_many_zeroes(Mem_Tape t[static 1])\n"
        "{\n"
        "    while (t->head >= t->count) {\n"
        "        grow_tape_and_append(t, 0);\n"
        "    }\n"
        "}\n"
        "\n"
        "int main(void)\n"
        "{\n" "    Mem_Tape t = {0};\n" "    grow_tape_and_append(&t, 0);\n");

    Mem_Tape tape = { 0 };
    size_t ip = 0;

    if (!append_tape(&tape, 0)) {
        return BF_OUT_OF_MEMORY;
    }
    
    while (ip < ops->count) {
        Op op = ops->items[ip];

        switch (op.kind) {
            case OP_INC: 
                /* Exit on failure. Else we'd have to check 8 calls individually. */
                tbf_xprintf("    t.mem[t.head] += %zu;\n", op.operand);
                ++ip;
                break;
            case OP_DEC: 
                tbf_xprintf("    t.mem[t.head] -= %zu;\n", op.operand);
                ++ip;
                break;
            case OP_PUT: 
                tbf_xprintf("    xgenerate_buf_and_fwrite(%zu, t.mem[t.head]);\n",
                            op.operand);
                ++ip;
                break;
            case OP_GET: 
                tbf_xprintf("    xgetchar_many(&t, %zu);\n", op.operand);
                ++ip;
                break;
            case OP_NEXT: 
                tbf_xprintf("    t.head += %zu;\n\n"
                            "    grow_tape_and_append_many_zeroes(&t);\n", op.operand);
                ++ip;
                break;
            case OP_PREV: 
                tbf_xprintf("    t.head = t.head < %zu ? t.count - (%zu - t.head) : t.head - %zu;\n",
                       op.operand, op.operand, op.operand);
                ++ip;
                break;
            case OP_LOOP_START: 
                C_Op_Kind rv = 0;

                if (rv = check_is_clear(ip, ops)) {
                    tbf_xfputs("    t.mem[t.head] = 0;\n", stdout);
                    ip = op.operand;
                } else if (rv = check_is_add_or_mul(ip, ops)) {
                    if (rv == C_ADD_OR_MUL_TYPE1) {
                        tbf_xprintf("    t.head = t.head < 1 ? t.count - (1 - t.head) : t.head - 1;\n"
                                    "    t.mem[t.head] += %zu * t.mem[t.head + 1];\n"
                                    "    t.head += 1;\n"
                                    "    grow_tape_and_append_many_zeroes(&t);\n"
                                    "    t.mem[t.head] = 0;\n",
                                    ops->items[ip + 2].operand);
                    } else {
                        tbf_xprintf("    t.head += 1;\n"
                                    "    grow_tape_and_append_many_zeroes(&t);\n"
                                    "    t.mem[t.head] += t.mem[t.head - 1] * %zu;\n"
                                    "    t.head -= 1;\n"
                                    "    t.mem[t.head] = 0;\n",
                                    ops->items[ip + 2].operand);
                    }
                    ip = op.operand;
                } else if (rv = check_is_sub(ip, ops)) {
                    if (rv == C_SUB_TYPE1) {
                        tbf_xprintf("    t.head = t.head < 1 ? t.count - (1 - t.head) : t.head - 1;\n"
                                    "    t.mem[t.head] -= t.mem[t.head + 1];\n"
                                    "    t.head += 1;\n"
                                    "    grow_tape_and_append_many_zeroes(&t);\n"
                                    "    t.mem[t.head] = 0;\n");
                    } else {
                        tbf_xprintf("    t.head += 1;\n"
                                    "    grow_tape_and_append_many_zeroes(&t);\n"
                                    "    t.mem[t.head] -= t.mem[t.head - 1];\n"
                                    "    t.head -= 1;\n"
                                    "    t.mem[t.head] = 0;\n",
                                    ops->items[ip + 2].operand);
                    }
                    ip = op.operand;
                } else {
                    tbf_xfputs("    while (t.mem[t.head] != 0) {\n", stdout);
                    ++ip;
                }
                break;
            case OP_LOOP_END: 
                tbf_xfputs("    }\n", stdout);
                ++ip;
                break;
        }
    }
    tbf_xfputs("    free(t.mem);\n"
               "    return EXIT_SUCCESS;\n"
               "}\n",
               stdout);
    free(tape.items);
    return true;
}

static Bf_Codes interpret(Ops ops[static 1])
{
    Mem_Tape tape = { 0 };

    if (!append_tape(&tape, 0)) {
        return BF_OUT_OF_MEMORY;
    }

    /* Should head be part of the Mem_Tape structure? */
    size_t head = 0;
    size_t ip = 0;

    while (ip < ops->count) {
        Op op = ops->items[ip];

        switch (op.kind) {
            case OP_INC:
                tape.items[head] += (unsigned char) op.operand;
                ++ip;
                break;
            case OP_DEC:
                tape.items[head] -= (unsigned char) op.operand;
                ++ip;
                break;
            case OP_GET:
                for (size_t i = 0; i < op.operand; ++i) {
                    int c = getchar();

                    if (c == EOF) {
                        return BF_READ_FAILED;
                    }
                    tape.items[head] = (unsigned char) c;
                }
                ++ip;
                break;
            case OP_PUT:
                for (size_t i = 0; i < op.operand; ++i) {
                    if (putchar(tape.items[head]) == EOF) {
                        return BF_WRITE_FAILED;
                    }
                }
                fflush(stdout);
                ++ip;
                break;
            case OP_NEXT:
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
                /* Wrap-around on underflow. */
                head =
                    head <
                    op.operand ? tape.count - (op.operand - head) : head -
                    op.operand;
                ++ip;
                break;
            case OP_LOOP_START:
                ip = tape.items[head] == 0 ? op.operand : ip + 1;
                break;
            case OP_LOOP_END:
                ip = tape.items[head] != 0 ? op.operand : ip + 1;
                break;
        }
    }
    free(tape.items);
    return BF_OK;
}

static bool is_valid_token(int tok)
{
    static const unsigned char bf_toks[] = {
        OP_INC,
        OP_DEC,
        OP_GET,
        OP_PUT,
        OP_NEXT,
        OP_PREV,
        OP_LOOP_START,
        OP_LOOP_END
    };

    return memchr(bf_toks, tok, sizeof bf_toks) != nullptr;
}

static char get_next_lexeme(Lexer *l)
{
    while (l->pos < l->count && !is_valid_token(l->content[l->pos])) {
        ++l->pos;
    }

    return l->pos >= l->count ? 0 : l->content[l->pos++];
}

static Bf_Codes generate_ops(size_t     nbytes,
                             const char code[static restrict nbytes],
                             Ops        ops[static restrict 1], 
                             size_t     byte_offset[static restrict 1])
{
    Lexer l = {
        .content = code,
        .pos = 0,
        .count = nbytes
    };

    Addr_Stack stack = { 0 };
    size_t last_op_loop_start = 0;
    char lexeme = get_next_lexeme(&l);

    while (lexeme) {
        switch (lexeme) {
            case OP_INC:
            case OP_DEC:
            case OP_GET:
            case OP_PUT:
            case OP_NEXT:
            case OP_PREV:{
                size_t op_count = 1;
                char next_lexeme = get_next_lexeme(&l);

                while (lexeme == next_lexeme) {
                    ++op_count;
                    next_lexeme = get_next_lexeme(&l);
                }

                Op op = {
                    .kind = lexeme,
                    .operand = op_count,
                };

                if (!append_op(ops, op)) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                lexeme = next_lexeme;
            }
                break;

            case OP_LOOP_START:{
                size_t addr = ops->count;

                Op op = {
                    .kind = lexeme,
                    .operand = 0,
                };

                if (!append_op(ops, op)) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                if (!push_addr_stack(&stack, addr)) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }
                last_op_loop_start = l.pos;
                lexeme = get_next_lexeme(&l);
            }
                break;

            case OP_LOOP_END:{
                if (stack.count == 0) {
                    *byte_offset = l.pos;
                    return BF_LOOP_END_BEFORE_START;
                }

                size_t addr = pop_addr_stack(&stack);

                Op op = {
                    .kind = lexeme,
                    .operand = addr + 1,
                };

                if (!append_op(ops, op)) {
                    *byte_offset = l.pos;
                    return BF_OUT_OF_MEMORY;
                }

                /* Backpatch. */
                ops->items[addr].operand = ops->count;
                lexeme = get_next_lexeme(&l);
            }
                break;
        }
    }

    free(stack.items);

    if (stack.count > 0) {
        *byte_offset = last_op_loop_start;
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
        fputs("Error: A non-nullptr argv[0] was passed in through an "
              "exec system call.\n", stderr);
        return EXIT_FAILURE;
    }

    if (argc != 2) {
        fprintf(stderr, "Error: expected 2 arguments, received %d.\n"
                "Usage: bf FILE.\n", argc);
        return EXIT_FAILURE;
    }

    FILE *const input = tbf_xfopen(argv[1], "rb");
    size_t nbytes = 0;
    char *const src = tbf_xread_file(argv[1], input, &nbytes);

    Ops ops = { 0 };
    size_t byte_offset = 0;
    Bf_Codes rc = generate_ops(nbytes, src, &ops, &byte_offset);

    free(src);

    if (rc != BF_OK) {
        switch (rc) {
            case BF_READ_FAILED: case BF_WRITE_FAILED:
                fprintf(stderr, error_msgs[rc], argv[1],
                        errno ? strerror(errno) : "unexpected error");
                break;

            case BF_OUT_OF_MEMORY:
                fprintf(stderr, error_msgs[rc], argv[1]);
                break;

            case BF_UNBALANCED_LOOP: case BF_LOOP_END_BEFORE_START:
                fprintf(stderr, error_msgs[rc], argv[1], byte_offset);
                break;
        }
        fclose(input);
        return EXIT_FAILURE;
    }
#ifdef NDEBUG
    disassemble_ops(&ops);
#endif
    rc = interpret(&ops);

    if (rc != BF_OK) {
        fprintf(stderr, error_msgs[rc], argv[1]);
    }

    transpile(&ops);
    free(ops.items);
    fclose(input);
    return EXIT_SUCCESS;
}
