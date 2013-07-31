# Makefile for the serf crawler tutorial

CC=clang
CFLAGS=-g

LIB_PATHS=-L/opt/local/lib -L/usr/local/lib
INC_PATHS=-I/opt/local/include/apr-1 -I/opt/local/include

LIBS=-lapr-1 -laprutil-1 -lssl -lcrypto -lz

OBJS=$(addprefix $(OBJDIR)/, simplespdy.o util.o ssl.o config_store.o\
                             spdy_protocol.o spdycompress.o spdy_streams.o\
                             protocols.o connections.o)
OBJDIR=build

simplespdy.o: $(OBJS)
		$(CC) -o simplespdy  $(LIB_PATHS) $(LIBS) $(OBJS)

$(OBJDIR)/%.o : %.c
		$(CC) $(CFLAGS) $(INC_PATHS) -o build/$*.o -c $<

simplespdy.c : simplespdy.h
util.c : simplespdy.h
ssl.c : simplespdy.h
spdyclient.c : simplespdy.h
configstore.c : simplespdy.h

clean:
		rm -f simplespdy build/*.o
