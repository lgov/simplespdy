# Makefile for the serf crawler tutorial

CC=clang
CFLAGS=-g

LIB_PATHS=-L/opt/local/lib -L/usr/local/lib
INC_PATHS=-I. -I/opt/local/include/apr-1 -I/opt/local/include/ -I/usr/local/include/serf-2

LIBS=-lapr-1 -laprutil-1 -lssl -lcrypto -lz -lserf-2

OBJS=$(addprefix $(OBJDIR)/, util.o ssl.o config_store.o\
                             spdy_protocol.o spdycompress.o spdy_buckets.o\
                             protocols.o connections.o priority_queue.o)
OBJDIR=build

simplespdy: $(OBJS) $(OBJDIR)/simplespdy.o
		$(CC) -o simplespdy  $(LIB_PATHS) $(LIBS) $(OBJS) $(OBJDIR)/simplespdy.o

$(OBJDIR)/%.o : %.c
		$(CC) $(CFLAGS) $(INC_PATHS) -o build/$*.o -c $<

simplespdy.c : simplespdy.h
util.c : simplespdy.h
ssl.c : simplespdy.h
spdyclient.c : simplespdy.h
configstore.c : simplespdy.h

test: $(OBJS) $(OBJDIR)/tests/basic_tests.o
		$(CC) -o spdytests $(LIB_PATHS) $(LIBS) $(OBJS)\
                           $(OBJDIR)/tests/basic_tests.o

clean:
		rm -f simplespdy spdytests build/*.o build/tests/*.o
