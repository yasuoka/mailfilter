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
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <iconv.h>

static struct {
	const char	*mime;
	const char	*iconv;
	int		 mimelen;
} rfc2047_charsets[] = {
	{	"us-ascii",		"ASCII"			},
	{	"utf-8",		"UTF-8"			},
	{	"iso-8859-1",		"ISO-8859-1"		},
	{	"iso-2022-jp",		"ISO-2022-JP"		},
	{	"gb2312",		"EUC-CN"		},
	{	"ks_c_5601-1987",	"EUC-KR"		},
	{	"windows-1250",		"CP1250"		},
	{	"windows-1251",		"CP1251"		},
	{	"windows-1252",		"CP1252"		},
	{	"windows-1253",		"CP1253"		},
	{	"windows-1254",		"CP1254"		},
	{	"windows-1255",		"CP1255"		},
	{	"windows-1256",		"CP1256"		},
	{	"windows-1257",		"CP1257"		},
	{	"windows-1258",		"CP1258"		}
};

#define nitems(_x)	(sizeof((_x)) / sizeof((_x)[0]))

#define IS_XDIGIT(_c) (				\
	(('0' <= (_c) && (_c) <= '9')) ||	\
	(('a' <= (_c) && (_c) <= 'f')) ||	\
	(('A' <= (_c) && (_c) <= 'F')))
#define XDIGIT(_c) (						\
	(('0' <= (_c) && (_c) <= '9'))? (_c) - '0' :		\
	(('a' <= (_c) && (_c) <= 'f'))? (_c) - 'a' + 10 :	\
	(('A' <= (_c) && (_c) <= 'F'))? (_c) - 'A' + 10 : (-1))

int	 b64_pton(const char *, u_char *, size_t);
int	 rfc2047_decode(const char *, const char *, char *, size_t);

/*
 * Decode a text encoded in MIME message header extension (RFC 2047).
 */
int
rfc2047_decode(const char *str, const char *tocode, char *decode,
    size_t decode_size)
{
	int		 i, j, len, enc;
	const char	*p, *cs = NULL;
	iconv_t		 ic = (iconv_t)-1;
	char		*tmp = NULL, *in, *out = decode;
	size_t		 tmpsz = 0, insz, outsz = decode_size, retsz;

	/* must starts with =? and ends with ?= */
	p = str;
	len = strlen(p);
	if (len > 6 && p[0] == '=' && p[1] == '?') {
		for (i = 2; p[i] != '\0'; i++) {
			if (p[i] == '?' && p[i + 1] == '=' &&
			    (p[i + 2] == '\0' || p[i + 2] == ' ' ||
			    p[i + 2] == '\r' || p[i + 2] == '\n'))
				break;
		}
		if (p[i] == '\0')
			goto fail;	/* unknown encoding */
		p += 2;
		len = i;
	} else
		goto fail;	/* unknown encoding */

	for (i = 0; i < nitems(rfc2047_charsets); i++) {
		if (rfc2047_charsets[i].mimelen == 0)
			rfc2047_charsets[i].mimelen =
			    strlen(rfc2047_charsets[i].mime);
		if (strncasecmp(p, rfc2047_charsets[i].mime,
		    rfc2047_charsets[i].mimelen) == 0 &&
		    p[rfc2047_charsets[i].mimelen] == '?') {
    			cs = rfc2047_charsets[i].mime;
			break;
		}
	}
	if (cs == NULL)
		goto fail;	/* unknown charset */

	p += rfc2047_charsets[i].mimelen + 1;
	len -= rfc2047_charsets[i].mimelen + 1;

	if ((p[0] == 'B' || p[0] == 'Q' || p[0] == 'b' || p[0] == 'q') &&
	    p[1] == '?') {
		enc = toupper(p[0]);
		p += 2;
		len -= 4;
	} else
		goto fail;	/* unknown encoding */

	switch (enc) {
	case 'B':	/* "B" encoding, similar to base64 */
		tmpsz = 4 * ((len + 3) / 4) + 1;
		if ((tmp = calloc(1, tmpsz)) == NULL)
			goto fail;
		memcpy(tmp, p, len);
		/* revert the paddings */
		for (i = 0; i < len % 4; i++)
			tmp[len + i] = '=';
		tmp[len] = '\0';
		if ((retsz = b64_pton(tmp, tmp, tmpsz)) == -1)
			goto fail;
		tmp[retsz] = '\0';
		in = tmp;
		insz = tmpsz;
		break;
	case 'Q':	/* "Q" encoding, similar to quoted printable */
		tmp = strndup(p, len);
		tmpsz = len + 1;
		i = j = 0;
		while (i < len) {
			if (tmp[i] == '=') {
				if (IS_XDIGIT(tmp[i + 1]) &&
				    IS_XDIGIT(tmp[i + 2])) {
					tmp[j++] = (XDIGIT(tmp[i + 1])<<4) |
					    XDIGIT(tmp[i + 2]);
					i += 3;
				} else
					goto fail;
			} else if (tmp[i] == '_') {
				tmp[j++] = ' ';
				i++;
			} else
				tmp[j++] = tmp[i++];
		}
		tmp[j++] = '\0';
		in = tmp;
		insz = j;
		break;
	default:
		goto fail;
		break;
	}
	if ((ic = iconv_open(tocode, cs)) == (iconv_t)-1)
		goto fail;
	if (iconv(ic, &in, &insz, &out, &outsz) == (size_t)-1)
		goto fail;
	freezero(tmp, tmpsz);
	iconv_close(ic);

	return (p + len + 2 - str);
fail:
	freezero(tmp, tmpsz);
	if (ic != (iconv_t)-1)
		iconv_close(ic);
	return (-1);
}
