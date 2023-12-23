#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

/* 
 *
 */

token *scan_log(char *verifier_log)
{
	// evaluate content between from "; " to "\n"
	
	char *current_char = verifier_log;
	char *word_start = NULL;
	char *word_end = NULL;

	int log_len = strlen(verifier_log);


	while (current_char < verifier_log + log_len)
	{
		// scan after semicolon until  "number';'" pattern occurs
		// 
		switch (*current_char)
		{
			case ';':
				// now we can actually pick up the state.
				break;
			case '\n':
				// the state change from this instruction is complete
				break;
		}
	}
}

