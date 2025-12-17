# B/Makefile
CC      := gcc
CFLAGS  := -Wall -Wextra -O2
LDFLAGS := -lpcap

SRC := main.c interface.c capture.c packet_analyzer.c transport.c utils.c inspect.c
OBJ := $(SRC:.c=.o)
BIN := cshark

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c cshark.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(BIN)
