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
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <curl/curl.h>

#include "bytebuf.h"
#include "rfc5322.h"

/* from rfc2047.c */
int		 rfc2047_decode(const char *, const char *, char *, size_t);

int		 luaopen_mailfilter(lua_State *);
static int	 pop3_metatable(lua_State *);
static int	 l_pop3(lua_State *);
static int	 l_mbox(lua_State *);
static int	 mh_folder_metatable(lua_State *);
static int	 l_mh_folder(lua_State *);

static ssize_t	 rfc5322_read(void *, size_t, size_t, void *);
static bool	 need_decode(struct rfc5322_result *);
static const char
		*skip_ws(const char *);
static char	*decode_text(const char *);
static const char
		*str_tolower(const char *, char *, size_t);

#define	MAXIMUM(_a,_b)	(((_a) > (_b))? (_a) : (_b))

int
luaopen_mailfilter(lua_State *L)
{
	lua_newtable(L);

	lua_pushstring(L, "pop3");
	lua_pushcfunction(L, l_pop3);
	lua_settable(L, -3);

	lua_pushstring(L, "mh_folder");
	lua_pushcfunction(L, l_mh_folder);
	lua_settable(L, -3);

	lua_pushstring(L, "mbox");
	lua_pushcfunction(L, l_mbox);
	lua_settable(L, -3);

	return (1);
}

/***********************************************************************
 * POP3
 ***********************************************************************/
struct curl_pop3;
static void	 pop3_curl_init(struct curl_pop3 *);
static int	 pop3_message_metatable(lua_State *);
static int	 l_pop3_getpass(lua_State *);
static int	 l_pop3_close(lua_State *);
static int	 l_pop3_list(lua_State *);
static int	 l_pop3_gc(lua_State *);
static int	 l_pop3_message_top(lua_State *);
static int	 l_pop3_message_retr(lua_State *);
static int	 l_pop3_message_topretr(lua_State *, bool);
static int	 l_pop3_message_delete(lua_State *);

int
pop3_metatable(lua_State *L)
{
	int	 ret;

	if ((ret = luaL_newmetatable(L, "mail.pop3")) != 0) {
		lua_pushstring(L, "list");
		lua_pushcfunction(L, l_pop3_list);
		lua_settable(L, -3);

		lua_pushstring(L, "getpass");
		lua_pushcfunction(L, l_pop3_getpass);
		lua_settable(L, -3);

		lua_pushstring(L, "close");
		lua_pushcfunction(L, l_pop3_close);
		lua_settable(L, -3);

		lua_pushstring(L, "__gc");
		lua_pushcfunction(L, l_pop3_gc);
		lua_settable(L, -3);
	}

	return (ret);
}

int
pop3_message_metatable(lua_State *L)
{
	int	 ret;

	if ((ret = luaL_newmetatable(L, "mail.pop3.message")) != 0) {
		lua_pushstring(L, "top");
		lua_pushcfunction(L, l_pop3_message_top);
		lua_settable(L, -3);

		lua_pushstring(L, "retr");
		lua_pushcfunction(L, l_pop3_message_retr);
		lua_settable(L, -3);

		lua_pushstring(L, "delete");
		lua_pushcfunction(L, l_pop3_message_delete);
		lua_settable(L, -3);
	}

	return (ret);
}

struct curl_pop3 {
	CURL			*curl;
	char			*url;
	char			*username;
	char			*password;
	char			*buffer;
	size_t			 buffersiz;
	FILE			*fp;
};

int
l_pop3(lua_State *L)
{
	const char		*url, *username, *password;
	struct curl_pop3	*pop3 = NULL, **userdata;

	url = luaL_checkstring(L, 1);
	luaL_argcheck(L,
	    strncmp(url, "pop3://", 7) == 0 || strncmp(url, "pop3s://", 8) == 0,
	    1, "url should start with pop3:// or pop3s://");
	username = luaL_checkstring(L, 2);
	password = luaL_optstring(L, 3, NULL);

	userdata = lua_newuserdata(L, sizeof(pop3));

	pop3_metatable(L);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	lua_setmetatable(L, -2);

	pop3 = calloc(1, sizeof(*pop3));
	if (pop3 == NULL)
		luaL_error(L, "calloc(): %s", strerror(errno));
	*userdata = pop3;
	if ((pop3->fp = open_memstream(&pop3->buffer, &pop3->buffersiz))
	    == NULL)
		luaL_error(L, "open_memstream(): %s", strerror(errno));
	if ((pop3->url = strdup(url)) == NULL)
		luaL_error(L, "strdup(): %s", strerror(errno));
	if ((pop3->username = strdup(username)) == NULL)
		luaL_error(L, "strdup(): %s", strerror(errno));
	if (password && (pop3->password = strdup(password)) == NULL)
		luaL_error(L, "strdup(): %s", strerror(errno));

	pop3_curl_init(pop3);

	return (1);
}

void
pop3_curl_init(struct curl_pop3	*pop3)
{
	pop3->curl = curl_easy_init();
	curl_easy_setopt(pop3->curl, CURLOPT_URL, pop3->url);
	curl_easy_setopt(pop3->curl, CURLOPT_USERNAME, pop3->username);
	curl_easy_setopt(pop3->curl, CURLOPT_NOBODY, 0L);
	if (pop3->password != NULL)
		curl_easy_setopt(pop3->curl, CURLOPT_PASSWORD, pop3->password);
	curl_easy_setopt(pop3->curl, CURLOPT_WRITEDATA, pop3->fp);
}

int
l_pop3_list(lua_State *L)
{
	struct curl_pop3	*pop3;
	CURLcode		 curlcode;
	char			*line0, *line, *arg0, *arg[2];
	const char		*strerr;
	int			 idx;
	int64_t			 siz;	/* standard lua has 64 bit integer */

	lua_newtable(L);
	pop3 = *(struct curl_pop3 **)luaL_checkudata(L, 1, "mail.pop3");
	//luaL_argcheck(L, pop3->curl != NULL, 1, "connection closed already");

	if (pop3->fp == NULL) {
		if ((pop3->fp = open_memstream(&pop3->buffer,
		    &pop3->buffersiz)) == NULL)
			luaL_error(L, "open_memstream(): %s", strerror(errno));
		pop3_curl_init(pop3);
	}

	curlcode = curl_easy_perform(pop3->curl);
	if (curlcode != CURLE_OK)
		luaL_error(L, "%s", curl_easy_strerror(curlcode));
	fputc('\0', pop3->fp);
	fflush(pop3->fp);

	/* parse lines of "LIST" result */
	for (line0 = pop3->buffer;
	    (line = strsep(&line0, "\n\r")) != NULL; ) {
		if (*line == '\0')
			continue;
		idx = 0;
		for (arg0 = line;
		    idx < 2 &&
		    (arg[idx] = strsep(&arg0, " \t")) != NULL; ) {
			if (*arg[idx] == '\0')
				continue;
			idx++;
		}
		if (idx != 2)
			luaL_error(L, "could not parse the result of LIST "
			    "command");

		idx = strtonum(arg[0], 1, INT_MAX, &strerr);
		if (strerr != NULL)
			luaL_error(L, "%s: %s", arg[0], strerr);
		siz = strtonum(arg[1], 1, INT64_MAX>>1, &strerr);
		if (strerr != NULL)
			luaL_error(L, "%s: %s", arg[1], strerr);

		lua_newtable(L);

		pop3_message_metatable(L);
		lua_pushstring(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);
		lua_setmetatable(L, -2);

		lua_pushstring(L, "parent");
		lua_pushvalue(L, 1);
		lua_settable(L, -3);

		lua_pushstring(L, "size");
		lua_pushinteger(L, siz);
		lua_settable(L, -3);

		lua_pushstring(L, "index");
		lua_pushinteger(L, idx);
		lua_settable(L, -3);

		lua_rawseti(L, -2, idx);
	}
	rewind(pop3->fp);

	curl_easy_setopt(pop3->curl, CURLOPT_URL, pop3->url);
	curl_easy_setopt(pop3->curl, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(pop3->curl, CURLOPT_CUSTOMREQUEST, "UIDL");
	curlcode = curl_easy_perform(pop3->curl);

	if (curlcode == CURLE_OK) {
		/* parse lines of "UIDL" result */
		fputc('\0', pop3->fp);
		fflush(pop3->fp);
		for (line0 = pop3->buffer;
		    (line = strsep(&line0, "\n\r")) != NULL; ) {
			if (*line == '\0')
				continue;
			idx = 0;
			for (arg0 = line;
			    idx < 2 && (arg[idx] =
			    strsep(&arg0, " \t")) != NULL;) {
				if (*arg[idx] == '\0')
					continue;
				idx++;
			}
			if (idx != 2)
				luaL_error(L, "could not parse the result of "
				    "UIDL command");
			idx = strtonum(arg[0], 1, INT_MAX, &strerr);
			if (strerr != NULL)
				luaL_error(L, "%s: %s", arg[0], strerr);
			lua_rawgeti(L, -1, idx);
			if (lua_istable(L, -1)) {
				lua_pushstring(L, "uid");
				lua_pushstring(L, arg[1]);
				lua_settable(L, -3);
			}
			lua_settop(L, -2);
		}
	}

	return (1);
}

int
l_pop3_getpass(lua_State *L)
{
	struct curl_pop3	*pop3;
	char			*password, buf[128];

	pop3 = *(struct curl_pop3 **)luaL_checkudata(L, 1, "mail.pop3");

	snprintf(buf, sizeof(buf), "Password for `%s': ", pop3->url);
	password = getpass(buf);
	if (password) {
		free(pop3->password);
		if ((pop3->password = strdup(password)) == NULL)
			luaL_error(L, "strdup(): %s", strerror(errno));
		curl_easy_setopt(pop3->curl, CURLOPT_PASSWORD, pop3->password);
	}

	return (0);
}

int
l_pop3_close(lua_State *L)
{
	struct curl_pop3	*pop3;

	pop3 = *(struct curl_pop3 **)luaL_checkudata(L, 1, "mail.pop3");
	if (pop3->curl != NULL) {
		curl_easy_cleanup(pop3->curl);
		pop3->curl = NULL;
	}
	fclose(pop3->fp);
	pop3->fp = NULL;

	return (0);
}

int
l_pop3_gc(lua_State *L)
{
	struct curl_pop3	*pop3;

	pop3 = *(struct curl_pop3 **)luaL_checkudata(L, 1, "mail.pop3");
	if (pop3->curl != NULL)
		curl_easy_cleanup(pop3->curl);
	if (pop3->fp != NULL) {
		fclose(pop3->fp);
		pop3->fp = NULL;
	}
	freezero(pop3->buffer, pop3->buffersiz);
	free(pop3->url);

	freezero(pop3, sizeof(*pop3));

	return (0);
}

struct pop3_read_ctx {
	lua_State		*L;
	bytebuffer		*buffer;
	struct rfc5322_parser	*parser;
	int			 state;
};

int
l_pop3_message_top(lua_State *L)
{
	return l_pop3_message_topretr(L, true);
}

int
l_pop3_message_retr(lua_State *L)
{
	return l_pop3_message_topretr(L, false);
}

int
l_pop3_message_topretr(lua_State *L, bool top)
{
	struct curl_pop3	*pop3 = NULL, **userdata;
	char			 buf[128];
	int			 idx;
	CURLcode		 curlcode;
	struct pop3_read_ctx	 ctx;

	lua_getfield(L, 1, "parent");
	userdata = luaL_checkudata(L, -1, "mail.pop3");
	if (userdata != NULL)
		pop3 = *userdata;
	luaL_argcheck(L, pop3 != NULL && pop3->curl != NULL, 1,
	    "connection closed already");

	lua_getfield(L, 1, "index");
	idx = luaL_checkinteger(L, -1);
	lua_settop(L, -3);

	if (top)
		snprintf(buf, sizeof(buf), "TOP %d 0", idx);
	else
		snprintf(buf, sizeof(buf), "RETR %d", idx);

	curl_easy_setopt(pop3->curl, CURLOPT_URL, pop3->url);
	curl_easy_setopt(pop3->curl, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(pop3->curl, CURLOPT_CUSTOMREQUEST, buf);
	curl_easy_setopt(pop3->curl, CURLOPT_WRITEFUNCTION, rfc5322_read);
	curl_easy_setopt(pop3->curl, CURLOPT_WRITEDATA, &ctx);

	ctx.L = L;
	ctx.state = RFC5322_NONE;
	if ((ctx.parser = rfc5322_parser_new()) == NULL)
		luaL_error(L, "rfc5322_parser_new(): %s", strerror(errno));
	if ((ctx.buffer = bytebuffer_create(8192)) == NULL) {
		rfc5322_free(ctx.parser);
		luaL_error(L, "bytebuffer_create(): %s", strerror(errno));
	}

	curlcode = curl_easy_perform(pop3->curl);
	if (curlcode != CURLE_OK) {
		bytebuffer_destroy(ctx.buffer);
		rfc5322_free(ctx.parser);
		luaL_error(L, "%s", curl_easy_strerror(curlcode));
	}

	bytebuffer_destroy(ctx.buffer);
	rfc5322_free(ctx.parser);

	return (0);
}

int
l_pop3_message_delete(lua_State *L)
{
	struct curl_pop3	*pop3 = NULL, **userdata;
	char			 buf[128];
	int			 idx;
	CURLcode		 curlcode;

	lua_getfield(L, 1, "parent");
	userdata = luaL_checkudata(L, -1, "mail.pop3");
	if (userdata != NULL)
		pop3 = *userdata;
	luaL_argcheck(L, pop3 != NULL && pop3->curl != NULL, 1,
	    "connection closed already");

	lua_getfield(L, 1, "index");
	idx = luaL_checkinteger(L, -1);
	lua_settop(L, -3);

	snprintf(buf, sizeof(buf), "%s/%d", pop3->url, idx);

	curl_easy_setopt(pop3->curl, CURLOPT_URL, buf);
	curl_easy_setopt(pop3->curl, CURLOPT_CUSTOMREQUEST, "DELE");
	curl_easy_setopt(pop3->curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(pop3->curl, CURLOPT_WRITEDATA, NULL);
	curl_easy_setopt(pop3->curl, CURLOPT_NOBODY, 1L);

	curlcode = curl_easy_perform(pop3->curl);
	if (curlcode != CURLE_OK)
		luaL_error(L, "%s", curl_easy_strerror(curlcode));

	return (0);
}

/***********************************************************************
 * MH folder
 ***********************************************************************/
struct mh_folder {
	char	*name;
	char	 path[PATH_MAX];
	int	 maxseq;
};

struct direntseq {
	struct dirent	dirent;
	int		seq;
};

static int		 l_mh_folder_list(lua_State *);
static void		 mh_message(lua_State *, int, int);
static int		 l_mh_folder_get(lua_State *);
static int		 l_mh_folder_save(lua_State *);
static int		 l_mh_folder_save_on_write(lua_State *);
static int		 l_mh_folder_save_on_end_of_headers(lua_State *);
static int		 l_mh_folder_gc(lua_State *);
static int		 l_mh_folder_message_retr(lua_State *);
static int		 l_mh_folder_message_delete(lua_State *);
static int		 mh_folder_newfile(struct mh_folder *);
static int		 direntseq_compar(const void *, const void *);

int
mh_folder_metatable(lua_State *L)
{
	int	 ret;

	if ((ret = luaL_newmetatable(L, "mail.mh_folder")) != 0) {
		lua_pushstring(L, "list");
		lua_pushcfunction(L, l_mh_folder_list);
		lua_settable(L, -3);

		lua_pushstring(L, "get");
		lua_pushcfunction(L, l_mh_folder_get);
		lua_settable(L, -3);

		lua_pushstring(L, "save");
		lua_pushcfunction(L, l_mh_folder_save);
		lua_settable(L, -3);

		lua_pushstring(L, "__gc");
		lua_pushcfunction(L, l_mh_folder_gc);
		lua_settable(L, -3);
	}

	return (ret);
}

int
l_mh_folder(lua_State *L)
{
	struct mh_folder	*folder, **userdata;
	const char		*name, *home = NULL;
	struct stat		 st;

	name = luaL_checkstring(L, 1);

	lua_newtable(L);

	userdata = lua_newuserdata(L, sizeof(folder));
	folder = calloc(1, sizeof(struct mh_folder));
	if (folder == NULL)
		luaL_error(L, "calloc(): %s", strerror(errno));
	*userdata = folder;

	folder->maxseq = -1;

	mh_folder_metatable(L);

	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	lua_pushstring(L, "name");
	lua_pushstring(L, name);
	lua_settable(L, -3);

	lua_setmetatable(L, -2);

	if (*name != '/') {
		if ((home = getenv("HOME")) == NULL)
			luaL_error(L, "missing HOME environment variable");
		strlcpy(folder->path, home, sizeof(folder->path));
		strlcat(folder->path, "/Mail/", sizeof(folder->path));
		strlcat(folder->path, name, sizeof(folder->path));
	} else
		realpath(name, folder->path);
	folder->name = basename(folder->path);

	if (stat(folder->path, &st) == -1) {
		if (errno != ENOENT)
			luaL_error(L, "%s: %s", folder->path, strerror(errno));
	} else if (!S_ISDIR(st.st_mode))
		luaL_error(L, "%s: not a directory", folder->path);

	return (1);
}

void
mh_message(lua_State *L, int idx, int parent)
{
	lua_newtable(L);

	lua_pushstring(L, "parent");
	lua_pushvalue(L, parent);
	lua_settable(L, -3);

	lua_pushstring(L, "index");
	lua_pushinteger(L, idx);
	lua_settable(L, -3);

	lua_pushstring(L, "retr");
	lua_pushcfunction(L, l_mh_folder_message_retr);
	lua_settable(L, -3);

	lua_pushstring(L, "delete");
	lua_pushcfunction(L, l_mh_folder_message_delete);
	lua_settable(L, -3);
}

int
l_mh_folder_list(lua_State *L)
{
	struct mh_folder	*folder;
	DIR			*dir;
	struct dirent		*ent, entr;
	struct direntseq	*ent0 = NULL, *entn;
	const char		*strerr;
	int			 i, n, seq, maxseq, entsiz = 0, newsiz;

	folder = *(struct mh_folder **)luaL_checkudata(L, 1, "mail.mh_folder");

	lua_newtable(L);
	maxseq = 0;
	if ((dir = opendir(folder->path)) == NULL) {
		if (errno == ENOENT)
			return (1);
		luaL_error(L, "could not open the directory");
	}
	for (n = 0; readdir_r(dir, &entr, &ent) == 0 && ent != NULL; ) {
		if (ent->d_type != DT_REG)
			continue;
		seq = strtonum(ent->d_name, 1, UINT_MAX, &strerr);
		if (strerr != NULL)
			continue;
		if (n >= entsiz) {
			newsiz = (entsiz == 0)? 128 : entsiz * 2;
			if ((entn = recallocarray(ent0, entsiz, newsiz,
			    sizeof(struct direntseq))) == NULL) {
			    	free(ent0);
				luaL_error(L,
				    "recallocarray(): %s", strerror(errno));
		    	}
			entsiz = newsiz;
			ent0 = entn;
		}
		ent0[n].dirent = *ent;
		ent0[n].seq = seq;
		if (seq == 0)
			abort();
		maxseq = MAXIMUM(seq, maxseq);
		n++;
	}
	qsort(ent0, n, sizeof(struct direntseq), direntseq_compar);
	for (i = 0; i < n; i++) {
		mh_message(L, ent0[i].seq, 1);
		lua_rawseti(L, -2, i + 1);
	}
	closedir(dir);

	free(ent0);

	return (1);
}

int
l_mh_folder_get(lua_State *L)
{
	struct mh_folder	*folder;
	int			 idx;

	folder = *(struct mh_folder **)luaL_checkudata(L, 1, "mail.mh_folder");
	idx = luaL_checkinteger(L, 2);
	mh_message(L, idx, 1);

	return (1);
}

int
l_mh_folder_save(lua_State *L)
{
	struct mh_folder	*folder;
	int			 fd, seq;

	folder = *(struct mh_folder **)luaL_checkudata(L, 1, "mail.mh_folder");
	luaL_argcheck(L, lua_istable(L, 2), 2, "must be a message");

	if ((fd = mh_folder_newfile(folder)) < 0)
		luaL_error(L,
		    "could not create a new file: %s", strerror(errno));
	seq = folder->maxseq;

	lua_getfield(L, 2, "retr");
	lua_pushvalue(L, 2);

	lua_newtable(L);

	lua_pushstring(L, "on_write");
	lua_pushvalue(L, 3);
	lua_pushinteger(L, fd);
	lua_pushcclosure(L, l_mh_folder_save_on_write, 2);
	lua_settable(L, -3);

	lua_pushstring(L, "on_end_of_headers");
	lua_pushvalue(L, 3);
	lua_pushinteger(L, fd);
	lua_pushcclosure(L, l_mh_folder_save_on_end_of_headers, 2);
	lua_settable(L, -3);

	lua_call(L, 2, 0);

	close(fd);

	lua_pushinteger(L, seq);

	return (1);
}

int
l_mh_folder_save_on_write(lua_State *L)
{
	const char	*buf;
	size_t		 bufsz;
	int		 fd;

	buf = luaL_checklstring(L, 1, &bufsz);
	fd = lua_tointeger(L, lua_upvalueindex(2));
	if (fd >= 0)
		write(fd, buf, bufsz);

	return (0);
}

int
l_mh_folder_save_on_end_of_headers(lua_State *L)
{
	int		 fd;
	const char	*key, *val;

	if (!lua_istable(L, lua_upvalueindex(1)))
		return (0);
	fd = lua_tointeger(L, lua_upvalueindex(2));
	if (fd >= 0) {
		lua_pushnil(L);
		while (lua_next(L, lua_upvalueindex(1)) != 0) {
			key = luaL_checkstring(L, -2);
			val = luaL_checkstring(L, -1);
			dprintf(fd, "%s: %s\n", key, val);
			lua_settop(L, -2);
		}
	}

	return (0);
}

int
mh_folder_newfile(struct mh_folder *folder)
{
	char		 path[PATH_MAX];
	int		 maxseq = 0, seq, fd = -1, maxtries;
	DIR		*dir;
	struct dirent	*ent, ent0;
	const char	*strerr;

	do {
		if (folder->maxseq < 0) {
			if ((dir = opendir(folder->path)) == NULL)
				return (-1);
			while (readdir_r(dir, &ent0, &ent) == 0 &&
			    ent != NULL) {
				if (ent->d_type != DT_REG)
					continue;
				seq = strtonum(ent->d_name, 1, UINT_MAX,
				    &strerr);
				if (strerr != NULL)
					continue;
				maxseq = MAXIMUM(seq, maxseq);
			}
			closedir(dir);
			folder->maxseq = maxseq;
		}
		for (maxtries = 30; --maxtries > 0; ) {
			snprintf(path, sizeof(path), "%s/%d",
			    folder->path, ++folder->maxseq);
			if ((fd = open(path,
			    O_EXCL | O_WRONLY | O_CREAT, 0600)) >= 0)
				break;
		}
		if (fd >= 0)
			break;
	} while (maxseq == 0);	/* do again if max seq is not checked here */

	return (fd);
}

int
l_mh_folder_gc(lua_State *L)
{
	struct mh_folder	*folder;

	folder = *(struct mh_folder **)luaL_checkudata(L, 1, "mail.mh_folder");
	freezero(folder, sizeof(*folder));

	return (0);
}

int
l_mh_folder_message_retr(lua_State *L)
{
	struct mh_folder	*folder;
	struct pop3_read_ctx	 ctx;
	int			 idx, f;
	char			 path[PATH_MAX], buf[1024];
	ssize_t			 sz;

	luaL_argcheck(L, lua_istable(L, 1), 1, "must be a message");

	lua_getfield(L, 1, "parent");
	folder = *(struct mh_folder **)luaL_checkudata(L, -1, "mail.mh_folder");

	lua_getfield(L, 1, "index");
	idx = luaL_checkinteger(L, -1);

	snprintf(path, sizeof(path), "%s/%d", folder->path, idx);

	if ((f = open(path, O_RDONLY)) < 0)
		luaL_error(L, "%s: %s", path, strerror(errno));

	ctx.L = L;
	ctx.state = RFC5322_NONE;
	if ((ctx.parser = rfc5322_parser_new()) == NULL) {
		close(f);
		luaL_error(L, "rfc5322_parser_new(): %s", strerror(errno));
	}
	if ((ctx.buffer = bytebuffer_create(8192)) == NULL) {
	    	rfc5322_free(ctx.parser);
		close(f);
		luaL_error(L, "bytebuffer_create(): %s", strerror(errno));
	}

	while ((sz = read(f, buf, sizeof(buf))) > 0)
		rfc5322_read(buf, sz, 1, &ctx);

	bytebuffer_destroy(ctx.buffer);
	rfc5322_free(ctx.parser);
	close(f);

	return (0);
}

int
l_mh_folder_message_delete(lua_State *L)
{
	struct mh_folder	*folder;
	int			 idx;
	char			 path[PATH_MAX];

	luaL_argcheck(L, lua_istable(L, 1), 1, "must be a message");

	lua_getfield(L, 1, "parent");
	folder = *(struct mh_folder **)luaL_checkudata(L, -1, "mail.mh_folder");

	lua_getfield(L, 1, "index");
	idx = luaL_checkinteger(L, -1);

	snprintf(path, sizeof(path), "%s/%d", folder->path, idx);
	unlink(path);

	return (0);
}

int
direntseq_compar(const void *a0, const void *b0)
{
	const struct direntseq *a, *b;

	a = (const struct direntseq *)a0;
	b = (const struct direntseq *)b0;

	return (a->seq - b->seq);
}

/***********************************************************************
 * mbox
 ***********************************************************************/
struct mbox {
	int	 fd;
};

static int		 mbox_metatable(lua_State *L);
static int		 l_mbox_save(lua_State *L);
static int		 l_mbox_gc(lua_State *L);

int
mbox_metatable(lua_State *L)
{
	int	ret;

	if ((ret = luaL_newmetatable(L, "mail.mbox")) != 0) {
		lua_pushstring(L, "save");
		lua_pushcfunction(L, l_mbox_save);
		lua_settable(L, -3);

		lua_pushstring(L, "__gc");
		lua_pushcfunction(L, l_mbox_gc);
		lua_settable(L, -3);
	}
	fprintf(stderr, "%s() ret %d\n", __func__, ret);

	return (ret);
}

int
l_mbox(lua_State *L)
{
	const char	*path;


	path = luaL_checkstring(L, 1);

	lua_newtable(L);	/* returning table */
	//lua_newuserdata(L, 100);

	/* metatable */
	mbox_metatable(L);
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	lua_pushstring(L, "path");
	lua_pushvalue(L, 1);
	lua_settable(L, -3);



	lua_setmetatable(L, -2);

	return (1);
}

int
l_mbox_save(lua_State *L)
{
	fprintf(stderr, "%s()\n", __func__);
	return (0);
}

int
l_mbox_gc(lua_State *L)
{
	fprintf(stderr, "%s()\n", __func__);
	return (0);
}
/************************************************************************
 * common, miscellaneous functions
 ************************************************************************/
ssize_t
rfc5322_read(void *buf, size_t nmemb, size_t size, void *ctx0)
{
	char			*lf, *cr, *line, *decoded, hdr[128];
	struct rfc5322_result	 res;
	struct pop3_read_ctx	*ctx = ctx0;

	bytebuffer_put(ctx->buffer, buf, nmemb * size);
	bytebuffer_flip(ctx->buffer);
	while (ctx->state == RFC5322_NONE) {
		/* XXX handle if the buffer is full but no LF */
		line = bytebuffer_pointer(ctx->buffer);
		if ((lf = memchr(line, '\n',
		    bytebuffer_remaining(ctx->buffer))) == NULL)
			break;
		bytebuffer_get(ctx->buffer, BYTEBUFFER_GET_DIRECT,
		    lf - line + 1);
		*lf = '\0';
		if (line < lf && *(lf - 1) == '\r') {
			cr = lf - 1;
			*cr = '\0';
		} else
			cr = NULL;
		rfc5322_push(ctx->parser, line);
		ctx->state = rfc5322_next(ctx->parser, &res);
		do {
			switch (ctx->state) {
			case RFC5322_HEADER_START:
				rfc5322_unfold_header(ctx->parser);
				break;
			case RFC5322_HEADER_END:
				lua_getfield(ctx->L, 2, "on_header");
				if (!lua_isfunction(ctx->L, -1)) {
					lua_settop(ctx->L, -2);
					break;
				}
				lua_pushstring(ctx->L,
				    str_tolower(res.hdr, hdr, sizeof(hdr)));
				decoded = NULL;
				if (need_decode(&res)) {
					decoded = decode_text(
					    skip_ws(res.value));
					if (decoded) {
						lua_pushstring(ctx->L, decoded);
						free(decoded);
					}
				}
				if (decoded == NULL)
					lua_pushstring(
					    ctx->L, skip_ws(res.value));
				lua_call(ctx->L, 2, 0);
				//lua_settop(ctx->L, -2);
				break;
			case RFC5322_END_OF_HEADERS:
				lua_getfield(ctx->L, 2, "on_end_of_headers");
				if (lua_isfunction(ctx->L, -1))
					lua_call(ctx->L, 0, 0);
				else
					lua_settop(ctx->L, -2);
				break;
			}
			ctx->state = rfc5322_next(ctx->parser, &res);
		} while (ctx->state != RFC5322_NONE &&
		    ctx->state != RFC5322_ERR);
		lua_getfield(ctx->L, 2, "on_write");
		if (lua_isfunction(ctx->L, -1)) {
			if (cr) {
				*cr = '\n';
				lua_pushlstring(ctx->L, line, cr - line + 1);
			} else {
				*lf = '\n';
				lua_pushlstring(ctx->L, line, lf - line + 1);
			}
			lua_call(ctx->L, 1, 0);
		} else
			lua_settop(ctx->L, -2);

		*lf = '\n';
		if (cr)
			*cr = '\r';
	}
	bytebuffer_compact(ctx->buffer);

	return (nmemb * size);
}

bool
need_decode(struct rfc5322_result *res)
{
	if (strcasecmp(res->hdr, "To") ||
	    strcasecmp(res->hdr, "Cc") ||
	    strcasecmp(res->hdr, "From") ||
	    strcasecmp(res->hdr, "Subject") ||
	    strcasecmp(res->hdr, "Comment"))
		return (true);
	return (false);
}

const char *
skip_ws(const char *s)
{
	while (*s == 0x20 || *s == 0x09 || *s == 0x0a || *s == 0x0d)
		s++;
	return (s);
}

char *
decode_text(const char *str)
{
	char	 decoded[128], *ret, *cp;
	int	 i, sz;
	size_t	 retsiz;

	ret = strdup(str);
	if (ret == NULL)
		return (NULL);
	retsiz = strlen(ret) + 1;
	for (i = 0; *str != '\0'; i++) {
		str = skip_ws(str);
		sz = rfc2047_decode(str, "UTF-8", decoded, sizeof(decoded));
		if (sz > 0) {
			str += sz;
			if (i == 0)
				strlcpy(ret, decoded, retsiz);
			else
				strlcat(ret, decoded, retsiz);
		} else {
			if (i == 0)
				cp = ret;
			else
				cp = ret + strlen(ret);

			while (*str != '\0' && !isspace(*str))
				*(cp++) = *(str++);
			if (*str != '\0')
				*(cp++) = ' ';
			*cp = '\0';
		}
	}

	return (ret);
}

const char *
str_tolower(const char *str, char *buf, size_t bufsiz)
{
	int	 i;

	for (i = 0; str[i] != '\0' && i + 1 < (int)bufsiz; i++)
		buf[i] = tolower(str[i]);
	buf[i] = '\0';

	return (buf);
}
