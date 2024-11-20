# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -pthread -O2
TARGET = procMonitor

all: $(TARGET)

$(TARGET): procMonitor.c
	$(CC) $(CFLAGS) -o $(TARGET) procMonitor.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
