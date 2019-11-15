LOCALBASE?=	/usr/local

PROG=		mailfilterctl
SRCS=		mailfilterctl.c parser.c
SRCS+=		mailfilter.c bytebuf.c rfc5322.c rfc2047.c b64_pton.c

LUA?=		lua53
LUA_CFLAGS!!=	pkg-config --cflags ${LUA}
LUA_LDADD!!=	pkg-config --libs ${LUA}

CFLAGS+=	${LUA_CFLAGS} -I${LOCALBASE}/include
LDFLAGS+=	-L${LOCALBASE}/lib
LDADD+=		${LUA_LDADD} -levent -lcurl -liconv

NOMAN=		#
WARNINGS=	yes
DEBUG=		-O0 -g

SUBDIR=		module

.include <bsd.prog.mk>
