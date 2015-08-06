%{
#include <err.h>
#include <stdio.h>

#include <sys/socket.h>
#include <net/if.h>
#include <sys/queue.h>

#include "config.h"

static struct file {
	FILE *stream;
	char *name;
	int errors;
} file;

extern FILE *yyin;
int yyparse(void);
int yylex(void);
int yyerror(const char *);

YYSTYPE yylval = { { NULL }, 1 };

struct config *config;
%}

%token	USER
%token	DEVICE
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
		| grammar user '\n'
		| grammar device '\n'
		| grammar error '\n' { file.errors++; }
		;

user		: USER STRING {
			if ((config->pw = getpwnam($2)) == NULL)
					errx(1, "Can't find user %s", $2);
		}
		;
device		: DEVICE STRING optnl '{' optnl srcspec_l optnl '}'
		{
			struct device *src;
			if (strlen($2) > IFNAMSIZ) {
				char *tmp;
				asprintf(&tmp, "Device name '%s' too long (maximum: %d, is: %ld)",
				         $2, IFNAMSIZ, strlen($2));
				yyerror(tmp);
				free(tmp);
				YYERROR;
			}
			src = calloc(1, sizeof(*src));
			if (src == NULL) {
				yyerror("Can't alloc space for device");
				YYERROR;
			}
			src->specs = $6;
			src->device = $2;
			TAILQ_INSERT_TAIL(&config->devices, src, entry);
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

dhcpv4		: DHCPV4 STRING { $$ = new_srcspec(SRC_DHCPV4, $2); } ;

rtadv		: RTADV { $$ = new_srcspec(SRC_RTADV, NULL); } ;

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
	file.errors++;
	fprintf(stderr, "%s:%d: %s\n", file.name, yylval.lineno, msg);
	return (0);
}

struct config *
parse_config(char *filename) {
	if ((file.name = strdup(filename)) == NULL) {
		warn("strdup");
		return NULL;
	}

	if ((file.stream = fopen(file.name, "r")) == NULL) {
		free(file.name);
		warn("fopen");
		return NULL;
	}

	if ((config = calloc(1, sizeof(*config))) == NULL) {
		err(1, "calloc");
	}
	TAILQ_INIT(&config->devices);

	yyin = file.stream;
	yyparse();
	fclose(file.stream);
	free(file.name);

	if ((config->pw == NULL) && ((config->pw = getpwnam("_dhcp")) == NULL)) {
		errx(1, "Can't find user _dhcp");
	}

	if (file.errors == 0)
		return config;
	return NULL;
}
