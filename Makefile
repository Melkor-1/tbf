CC:= gcc-13 

CFLAGS += -std=c2x
#CFLAGS += -DNDEBUG
CFLAGS += -g3
CFLAGS += -ggdb
CFLAGS += -gdwarf-4
CFLAGS += -fPIC
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
#CFLAGS += -fanalyzer
CFLAGS += -Wsuggest-attribute=pure
CFLAGS += -Wsuggest-attribute=const
CFLAGS += -Wsuggest-attribute=noreturn
CFLAGS += -Wsuggest-attribute=malloc 
CFLAGS += -Wsuggest-attribute=cold
CFLAGS += -Wsuggest-attribute=format 

CFLAGS += -O2

SRCS   := tbf.c tbf_util.c
BIN	   := tbf

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(BIN)

clean:
	rm $(BIN) 
