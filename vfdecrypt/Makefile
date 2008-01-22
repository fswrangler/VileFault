CC	=	gcc
CFLAGS	=	-O2
LDFLAGS	=	-lcrypto

OBJS	=	vfdecrypt.o util.o

vfdecrypt:	${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS}

clean:
	rm -f vfdecrypt ${OBJS}
