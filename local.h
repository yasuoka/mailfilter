/* from rfc2047.c */
int	 rfc2047_decode(const char *, const char *, char *, size_t);

/* from mailfilter.c */
int	 luaopen_mailfilter(lua_State *);
