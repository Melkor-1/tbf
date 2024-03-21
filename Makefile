CC:= gcc-13 

CFLAGS += -std=c11
#CFLAGS += -DNDEBUG
CFLAGS += -g3
CFLAGS += -ggdb
CFLAGS += -fPIC
CFLAGS += -gdwarf-4
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-parentheses
CFLAGS += -Wpedantic
CFLAGS += -Warray-bounds
CFLAGS += -Wconversion
CFLAGS += -Wno-switch
CFLAGS += -Wno-unused-function
CFLAGS += -Wstrict-prototypes
CFLAGS += -fanalyzer
CFLAGS += -Wsuggest-attribute=pure
CFLAGS += -Wsuggest-attribute=const
CFLAGS += -Wsuggest-attribute=noreturn
CFLAGS += -Wsuggest-attribute=malloc 
CFLAGS += -Wsuggest-attribute=cold
CFLAGS += -Wsuggest-attribute=format 

SRCS   := tbf.c tbf_util.c
BIN	   := tbf

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(BIN)

clean:
	rm $(BIN) 
