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
test		printf("TEST "); return TEST;
source		printf("SOURCE "); return SOURCE;
dhcpv4		printf("DHCPV4 "); return DHCPV4;
rtadv		printf("RTADV "); return RTADV;
\{		printf("obrace "); return '{';
\}		printf("ebrace "); return '}';
\"		printf("quote ");
[[:alnum:]/.-]+	yylval.v.string=strdup(yytext); printf("STRING: %s ", yytext); return STRING;
\n		printf("NL "); yylval.lineno++; printf("\n"); return '\n';
[ \t]		printf("white ");
%%
