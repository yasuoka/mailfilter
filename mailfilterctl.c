/*
 * Copyright (c) 2019 YASUOKA Masahiko <yasuoka@yasuoka.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "parser.h"

#include "local.h"

#define DEFAULT_INTERVAL	1800
#define	NAME			"mailfilter"

struct daemon;
struct client;

static void	 daemon_stop(void);
static void	 lua_call_inc(struct client *);
static int	 lua_call_inc_write(lua_State *L);
static void	 on_signal(int, short, void *);
static void	 on_event(int, short, void *);
static void	 on_event2(int, short, void *);
static void	 client_close(struct client *);
static void	 on_timer(int, short, void *);
static void	 reset_timer(struct daemon *);
static int	 ipc_connect(const char *);
static void	 ipc_control(struct parse_result *, int);
static void	*lua_alloc(void *, void *, size_t, size_t);

static void	 vlog(const char *, va_list, const char *, bool);
static __dead void
		 log_err(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)))
			__attribute__((__unused__));
static __dead void
		 log_errx(const char *, ...)
			__attribute__((__format__ (printf, 1, 2)))
			__attribute__((__unused__));
static void	 log_warn(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)))
		    __attribute__((__unused__));
static void	 log_warnx(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)))
		    __attribute__((__unused__));
static void	 log_info(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)))
		    __attribute__((__unused__));

static FILE		*logfp = stderr;
static const char	*logfn = NULL;


enum MAILFILTERD_CMD {
	MAILFILTERD_INC,
	MAILFILTERD_STOP
};



struct daemon {
	int		 sock;
	struct event	 ev_timer;
	int		 intval;
	lua_State	*L;
	TAILQ_HEAD(,client)
			 clients;
};

struct client {
	struct daemon	*parent;
	int		 sock;
	struct event	 ev_sock;
	TAILQ_ENTRY(client)
			 next;
};
	
static void
usage(void)
{
	extern char		*__progname;

	fprintf(stderr, "usage: %s [-d] command [args...]\n", __progname);
}

int
main(int argc, char *argv[])
{
	int			 ch, sock = -1, i;
	struct daemon		 daemon_s;
	bool			 foreground = false;
	struct parse_result	*result;
	char			 pathbuf[PATH_MAX], sockpath[PATH_MAX];
	struct event		 ev_sock, ev_sighup, ev_sigint, ev_sigterm;
	struct sockaddr_un	 sun;
	lua_State		*L;
	struct client		*client, *tclient;

	while ((ch = getopt(argc, argv, "d")) != -1)
		switch (ch) {
		case 'd':
			foreground = true;
			break;
		default:
			usage();
			exit(EX_USAGE);
			break;
		}
	argc -= optind;
	argv += optind;

	if ((L = lua_newstate(lua_alloc, NULL)) == NULL)
		err(EX_OSERR, "lua_newstate()");
	luaL_openlibs(L);
	luaL_requiref(L, "mailfilter", luaopen_mailfilter, 1);
	lua_pop(L, 1);

	result = parse(argc, argv);
	if (result == NULL)
		exit(EX_USAGE);

	strlcpy(sockpath, getenv("HOME"), sizeof(sockpath));
	strlcat(sockpath, "/." NAME "/sock", sizeof(sockpath));

	sock = ipc_connect(sockpath);

	switch (result->action) {
	case RESTART:
		/* stop the daemon if exists */
		sock = ipc_connect(sockpath);
		for (i = 0; sock != -1 && i < 10; i++) {
			ipc_control(result, sock);
			usleep(100000UL);
			sock = ipc_connect(sockpath);
		}
		/* FALLTHROUGH */
	case RUN:
	case START:
		if (result->action != RUN && sock != -1)
			errx(EXIT_FAILURE, "daemon is running already");
		if (luaL_loadfile(L, result->filename) != LUA_OK)
			errx(EXIT_FAILURE, "%s", lua_tostring(L, -1));
		if (lua_pcall(L, 0, 0, 0) != LUA_OK)
			errx(EXIT_FAILURE, "%s", lua_tostring(L, -1));
		lua_getglobal(L, "inc");
		if (lua_pcall(L, 0, 0, 0) != LUA_OK)
			errx(EXIT_FAILURE, "%s", luaL_checkstring(L, 1));
		break;
	case INC:
	case STOP:
		if (sock == -1)
			errx(EXIT_FAILURE, "daemon is not running");
		ipc_control(result, sock);
		exit(EXIT_SUCCESS);
	case NONE:
		abort();
	}

	if (result->action != RUN && result->action != RESTART)
		exit(EXIT_SUCCESS);

	TAILQ_INIT(&daemon_s.clients);
	daemon_s.L = L;
	daemon_s.intval = DEFAULT_INTERVAL;

	/* daemon */
	if (getenv("HOME") == NULL)
		err(EXIT_FAILURE, "no HOME environment variable set");

	strlcpy(pathbuf, getenv("HOME"), sizeof(pathbuf));
	strlcat(pathbuf, "/." NAME, sizeof(pathbuf));
	if (mkdir(pathbuf, 0700) == -1 && errno != EEXIST)
		err(EXIT_FAILURE, "mkdir %s", pathbuf);

	if (!foreground) {
		strlcat(pathbuf, "/log", sizeof(pathbuf));
		logfn = strdup(pathbuf);
		if (logfn == NULL)
			err(EX_OSERR, "strdup");
		if ((logfp = fopen(logfn, "a")) == NULL)
			err(EXIT_FAILURE, "fopen(%s)", logfn);
		daemon(1, 1);
	}
	if (logfp != stderr) {
		dup2(fileno(logfp), STDOUT_FILENO);
		dup2(fileno(logfp), STDERR_FILENO);
	}

	event_init();

	if ((daemon_s.sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK,
	    0)) == -1)
		err(EX_OSERR, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path));

	/* IPC */
	if ((sock = ipc_connect(sockpath)) >= 0)
		errx(EXIT_FAILURE, "daemon is running already");
	unlink(sun.sun_path);
	if (bind(daemon_s.sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(EX_OSERR, "bind");
	if (listen(daemon_s.sock, 5) == -1)
		err(EX_OSERR, "listen");
	event_set(&ev_sock, daemon_s.sock, EV_READ | EV_PERSIST, on_event,
	    &daemon_s);

	/* Signals */
	signal_set(&ev_sighup,  SIGHUP,  on_signal, NULL);
	signal_set(&ev_sigint,  SIGINT,  on_signal, NULL);
	signal_set(&ev_sigterm, SIGTERM, on_signal, NULL);

	/* Timer */
	evtimer_set(&daemon_s.ev_timer, on_timer, &daemon_s);

	signal_add(&ev_sock, NULL);

	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	reset_timer(&daemon_s);

	log_info("Daemon started.  process-id=%u", (unsigned)getpid());
	event_loop(0);

	TAILQ_FOREACH_SAFE(client, &daemon_s.clients, next, tclient)
		client_close(client);

	signal_del(&daemon_s.ev_timer);
	signal_del(&ev_sigterm);
	signal_del(&ev_sigint);
	signal_del(&ev_sighup);
	signal_del(&ev_sock);

	event_loop(0);
	log_info("Daemon terminated");

	lua_close(L);
	close(daemon_s.sock);

	if (logfp != stderr)
		fclose(logfp);
	free((char *)logfn);

	exit(EXIT_SUCCESS);
}

void
daemon_stop(void)
{
	event_loopbreak();
}

void
lua_call_inc(struct client *self)
{
	lua_State	*L = self->parent->L;

	lua_getglobal(L, "inc");
	lua_pushlightuserdata(L, self);
	lua_pushcclosure(L, lua_call_inc_write, 1);
	if (lua_pcall(L, 1, 0, 0) != LUA_OK)
		log_warnx("%s", luaL_checkstring(L, 1));
}

int
lua_call_inc_write(lua_State *L)
{
	struct client	*self;
	const char	*buf;
	size_t		 bufsiz;

	if (!lua_isuserdata(L, lua_upvalueindex(1)))
		return (0);

	self = lua_touserdata(L, lua_upvalueindex(1));
	buf = luaL_checklstring(L, 1, &bufsiz);
	write(self->sock, buf, bufsiz);

	return (0);
}

void
on_signal(int fd, short ev, void *ctx)
{
	log_info("Received SIG%s", (fd == SIGINT)? "INT" : (fd == SIGHUP)?
	    "HUP" : "TERM");

	switch (fd) {
	case SIGINT:
	case SIGTERM:
		daemon_stop();
		break;
	}
}

void
on_event(int fd, short ev, void *ctx)
{
	struct daemon		*self = ctx;
	struct sockaddr_un	 sun;
	socklen_t		 sunlen;
	struct client	*client;
	int			 sock;

	sunlen = sizeof(sun);
	if ((sock = accept(self->sock, (struct sockaddr *)&sun, &sunlen))
	    == -1) {
		log_warnx("%s; accept():", __func__);
		daemon_stop();
		return;
	}
	if ((client = calloc(1, sizeof(*client))) == NULL) {
		log_warnx("%s; calloc():", __func__);
		daemon_stop();
		return;
	}
	client->sock = sock;
	client->parent = self;
	event_set(&client->ev_sock, sock, EV_READ, on_event2, client);
	event_add(&client->ev_sock, NULL);
	TAILQ_INSERT_TAIL(&self->clients, client, next);
}

void
on_event2(int fd, short ev, void *ctx)
{
	u_char			 buf[128];
	enum MAILFILTERD_CMD	 cmd;
	ssize_t			 sz;
	struct client	*self = ctx;

	if ((sz = recv(self->sock, buf, sizeof(buf), 0)) == -1) {
		log_warn("%s; recv()", __func__);
		daemon_stop();
	}
	if (sz < (int)sizeof(enum MAILFILTERD_CMD)) {
		log_warnx("%s; received a wrong message: size=%zd", __func__,
		    sz);
		return;
	}
	cmd = *(enum MAILFILTERD_CMD *)&buf;
	switch (cmd) {
	case MAILFILTERD_STOP:
		log_info("Stop requested");
		daemon_stop();
		break;
	case MAILFILTERD_INC:
		log_info("Calling `inc' requested");
		lua_call_inc(self);
		client_close(self);
		break;
	default:
		log_warnx("%s; received a wrong message: cmd=%d", __func__,
		    (int)cmd);
		return;
	}
}

void
client_close(struct client *self)
{
	TAILQ_REMOVE(&self->parent->clients, self, next);
	event_del(&self->ev_sock);
	close(self->sock);
	freezero(self, sizeof(*self));
}

void
on_timer(int fd, short ev, void *ctx)
{
	struct daemon	*self = ctx;
	lua_State	*L = self->L;

	log_info("Calling `inc' by timer");
	lua_getglobal(L, "inc");
	if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
		log_warnx("%s", luaL_checkstring(L, 1));
		daemon_stop();
		return;
	}
	reset_timer(self);
}

void
reset_timer(struct daemon *self)
{
	struct timeval	 timer;

	if (self->intval > 0) {
		timer.tv_sec = self->intval;
		timer.tv_usec = 0;
		signal_add(&self->ev_timer, &timer);
	} else
		signal_del(&self->ev_timer);
}

int
ipc_connect(const char *path)
{
	int			sock = -1;
	struct sockaddr_un	sun;

	memset(&sun, 0, sizeof(sun));
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);

	if ((sock = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1)
		err(EX_OSERR, "socket");
	if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		if (errno == EEXIST || errno == ECONNREFUSED || errno == ENOENT)
			return (-1);
		err(EX_OSERR, "connect");
	}

	return (sock);
}

void
ipc_control(struct parse_result *result, int sock)
{
	enum MAILFILTERD_CMD	cmd;
	bool			read = false;
	char			buf[BUFSIZ];
	ssize_t			sz;

	switch (result->action) {
	case INC:
		cmd = MAILFILTERD_INC;
		read = true;
		break;
	case STOP:
	case RESTART:
		cmd = MAILFILTERD_STOP;
		break;
	default:
		abort();
	}
	if (send(sock, &cmd, sizeof(cmd), 0) == -1)
		err(EX_OSERR, "send");
	if (read) {
		while ((sz = recv(sock, buf, sizeof(buf), 0)) > 0)
			write(STDOUT_FILENO, buf, sz);
	}
	close(sock);
}

static void *
lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	void	*ret;

	ret = recallocarray(ptr, osize, nsize, 1);

	return (ret);
}
/***********************************************************************
 * Logging functions
 ***********************************************************************/
void
vlog(const char *fmt, va_list ap, const char *label, bool additional)
{
	time_t		 now;
	struct tm	*lt;

	time(&now);
	lt = localtime(&now);
	fprintf(logfp, "%04d-%02d-%02d %02d:%02d:%02d:%s: ",
	    lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
	    lt->tm_hour, lt->tm_min, lt->tm_sec, label);
	vfprintf(logfp, fmt, ap);
	if (additional)
		fprintf(logfp, ": %s", strerror(errno));
	fputc('\n', logfp);
	fflush(logfp);
}

void
log_err(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(fmt, ap, "ERR", true);
	va_end(ap);
	abort();
}

void
log_errx(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(fmt, ap, "ERR", false);
	va_end(ap);
	abort();
}

void
log_warn(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(fmt, ap, "WARNING", true);
	va_end(ap);
}

void
log_warnx(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(fmt, ap, "WARNING", false);
	va_end(ap);
}

void
log_info(const char *fmt, ...)
{
	va_list	 ap;

	va_start(ap, fmt);
	vlog(fmt, ap, "INFO", false);
	va_end(ap);
}
