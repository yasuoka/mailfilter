LOCALBASE?=	/usr/local

.PATH: ${.CURDIR}/..

LIB=		mailfilter_
SRCS=		mailfilter.c bytebuf.c rfc5322.c rfc2047.c b64_pton.c
NOMAN=		#
WARNINGS=	yes
NOPROFILE=	#
NOLIBSTATIC=	#

LUA?=		lua53
LUA_CFLAGS!!=	pkg-config --cflags ${LUA}
LUA_LDADD!!=	pkg-config --libs ${LUA}

CFLAGS+=	-I${LOCALBASE}/include ${LUA_CFLAGS}
LDADD+=		-L${LOCALBASE}/lib -liconv -levent -lcurl -lnghttp2 -lssl -lcrypto -lz -lpthread


.include <bsd.lib.mk>


all: ${LIB}.so

CLEANFILES=	${LIB}.so

${LIB}.so: ${SOBJS} ${DPADD}
	@echo Building shared object XX
	${CC} -shared -Wl,-soname,${LIB}.so ${PICFLAG} -o ${.TARGET} ${SOBJS} ${LDADD}
