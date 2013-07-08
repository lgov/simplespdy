# Makefile for the serf crawler tutorial

CC=clang
CFLAGS=-g

LIB_PATHS=-L/opt/local/lib -L/usr/local/lib
INC_PATHS=-I/opt/local/include/apr-1 -I/opt/local/include

LIBS=-lapr-1 -laprutil-1 -lssl -lcrypto

OBJS=$(addprefix $(OBJDIR)/, simplespdy.o util.o)
OBJDIR=build

simplespdy.o: $(OBJS)
		$(CC) -o simplespdy  $(LIB_PATHS) $(LIBS) $(OBJS)

$(OBJDIR)/%.o : %.c
		$(CC) $(CFLAGS) $(INC_PATHS) -o build/$*.o -c $<

simplespdy.c : simplespdy.h
util.c : simplespdy.h

clean:
		rm -f simplespdy build/simplespdy.o build/util.o