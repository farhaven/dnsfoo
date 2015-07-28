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

extern FILE *yyin;
int yyparse(void);
int yylex(void);
int yyerror(const char *);

typedef struct {
	union {
		char *string;
		struct srcspec *spec;
		struct srcspec_l *spec_l;
	} v;
	int lineno;
} YYSTYPE;

YYSTYPE yylval = { NULL, 1 };

struct config *config;
struct source *current_source = NULL;
struct srcspec *current_srcspec = NULL;
%}

%token	SOURCE
%token	TEST
%token	ERROR
%token	DHCPV4 RTADV
%token	STRING

%type	<v.string> STRING
%type	<v.spec> dhcpv4
%type	<v.spec> rtadv
%type	<v.spec> srcspec
%type	<v.spec_l> srcspec_l
%%

/* Grammar */
grammar	:
		| grammar '\n'
		| grammar source '\n'
		| grammar error '\n' { file->errors++; }
		;

source		: SOURCE STRING optnl '{' optnl srcspec_l optnl '}'
		{
			struct source *src = calloc(1, sizeof(*src));
			if (src == NULL) {
				yyerror("Can't alloc space for source");
				YYERROR;
			}
			src->specs = $6;
			src->device = strdup($2);
			TAILQ_INSERT_TAIL(&config->sources, src, entry);
			printf("source: %s\n", $2);
		}
		;

srcspec_l	: srcspec {
	  		$$ = new_srcspec_l();
			TAILQ_INSERT_TAIL(&$$->l, $1, entry);
		}
		| srcspec_l srcspec {
			TAILQ_INSERT_TAIL(&$1->l, $2, entry);
		}
		;

srcspec		: dhcpv4 '\n' { $$ = $1; }
		| rtadv '\n' { $$ = $1; }
		;

dhcpv4		: DHCPV4 STRING {
			fprintf(stderr, "dhcpv4 source: %s\n", $2);
			$$ = new_srcspec(SRC_DHCPV4, strdup($2));
		}
		;

rtadv		: RTADV {
			fprintf(stderr, "rtadv\n");
			$$ = new_srcspec(SRC_RTADV, NULL);
		}
		;

optnl		: optnl '\n'
		| /* empty */
		;
%%

struct srcspec *
new_srcspec(enum srctype type, char *src) {
	struct srcspec *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		err(1, "calloc");
	}
	s->type = type;
	s->source = src;
	return s;
}

struct srcspec_l *
new_srcspec_l() {
	struct srcspec_l *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		err(1, "calloc");
	}
	TAILQ_INIT(&s->l);
	return s;
}

int
yyerror(const char *msg) {
	file->errors++;
	fprintf(stderr, "%s:%d: %s\n", file->name, yylval.lineno, msg);
	return (0);
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

	if ((config = calloc(1, sizeof(*config))) == NULL) {
		err(1, "calloc");
	}
	TAILQ_INIT(&config->sources);

	yyin = file->stream;
	yyparse();

	if (file->errors == 0)
		return config;
	return NULL;
}
