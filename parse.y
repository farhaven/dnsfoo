/* Derived from OpenBSD's /usr/src/usr.sbin/bgpd/parse.y */

%{
#include <err.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>

#include <sys/queue.h>

#include "config.h"

static struct file {
	FILE *stream;
	char *name;
	int lineno;
	int errors;
} *file;

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);


int yyparse(void);
int lookup(char *);
int yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));

typedef struct {
	union {
		char *string;
	} v;
	int lineno;
} YYSTYPE;

struct config *config;
struct source *current_source = NULL;
struct srcspec *current_srcspec = NULL;
%}

%token	SOURCE
%token	ERROR
%token	DHCPV4 RTADV

%token	<v.string>	STRING
%%

/* Grammar */
grammar	:
		| grammar '\n'
		| grammar source '\n'
		| grammar error '\n' { file->errors++; }
		;

source		: {
			current_source = calloc(1, sizeof(*current_source));
			if (current_source == NULL) {
				yyerror("Can't alloc space for source");
				YYERROR;
			}
			TAILQ_INIT(&current_source->specs);
			TAILQ_INSERT_TAIL(&config->sources, current_source, entry);
		} SOURCE STRING optnl '{' optnl srcspec_l optnl '}' {
			current_source->device = strdup($3);
#ifndef NDEBUG
			fprintf(stderr, "source: %s\n", $3);
#endif
		}
		;

srcspec_l	: srcspec
		| srcspec_l srcspec
		;

srcspec		: { new_srcspec(); } dhcpv4 '\n'
		| { new_srcspec(); } rtadv '\n'
		;

dhcpv4		: DHCPV4 STRING {
#ifndef NDEBUG
			fprintf(stderr, "dhcpv4 source: %s\n", $2);
#endif
			current_srcspec->type = SRC_DHCPV4;
			current_srcspec->source = strdup($2);
		}
		;

rtadv		: RTADV {
#ifndef NDEBUG
			fprintf(stderr, "rtadv\n");
#endif
			current_srcspec->type = SRC_RTADV;
			current_srcspec->source = NULL;
		}
		;

optnl		: optnl '\n'
		| /* empty */
		;
%%

void
new_srcspec(void) {
	current_srcspec = calloc(1, sizeof(*current_srcspec));
	if (current_srcspec == NULL) {
		yyerror("Can't alloc space for srcspec");
	}
#ifndef NDEBUG
	fprintf(stderr, "new srcspec: %p\n", (void*) current_srcspec);
#endif
	TAILQ_INSERT_TAIL(&current_source->specs, current_srcspec, entry);
}

struct keywords {
	const char* k_name;
	int k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		errx(1, "yyerror vasprintf");
	va_end(ap);
	warn("%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			return (EOF);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
lookup(char *s) {
	/* This has to be sorted */
	static const struct keywords keywords[] = {
		{"dhcpv4", DHCPV4},
		{"rtadv", RTADV},
		{"source", SOURCE},
	};

	const struct keywords *p;
	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	            sizeof(keywords[0]), kw_cmp);

	if (p)
		return p->k_val;

	return STRING;
}

struct config *
parse_config(char *filename) {
	struct file nfile;

	if ((nfile.name = strdup(filename)) == NULL) {
		warn("strdup");
		return 0;
	}

	if ((nfile.stream = fopen(nfile.name, "r")) == NULL) {
		free(nfile.name);
		warn("fopen");
		return 0;
	}

	nfile.lineno = 1;

	file = &nfile;

	config = calloc(1, sizeof(*config));
	TAILQ_INIT(&config->sources);

	yyparse();

	if (file->errors == 0)
		return config;
	return NULL;
}
