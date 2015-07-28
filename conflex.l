%{
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "y.tab.h"

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
