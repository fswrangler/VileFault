CC = gcc
CFLAGS = -Wall -O2 -funroll-loops
TARGET = vfcrack
LDFLAGS = -lssl -lcrypto
OBJS = vfcrack.o\
       fpga.o\
       picodrv.o

all: vfcrack

vfcrack: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f *.o *.core $(TARGET)
