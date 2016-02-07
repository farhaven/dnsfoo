%{
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "y.tab.h"

extern YYSTYPE yylval;
%}

%%
server		return SERVER;
unbound		return UNBOUND;
rebound		return REBOUND;

user		return USER;
device		return DEVICE;

dhcpv4		return DHCPV4;
rtadv		return RTADV;
\{		return '{';
\}		return '}';
\"		; /* XXX */
[[:alnum:]/.-_]+	yylval.v.string=strdup(yytext); return STRING;
#.*\n		|
\n		yylval.lineno++; return '\n';
[ \t]		;
%%
