%{
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "y.tab.h"

typedef struct {
	union {
		char *string;
		struct {
			enum srctype type;
			char *source;
		} spec;
	} v;
	int lineno;
} YYSTYPE;
extern YYSTYPE yylval;
%}

%%
source		return SOURCE;
dhcpv4		return DHCPV4;
rtadv		return RTADV;
\{		return '{';
\}		return '}';
\"		; /* XXX */
[[:alnum:]/.-]+	yylval.v.string=strdup(yytext); return STRING;
\n		yylval.lineno++; return '\n';
[ \t]		;
%%
