#include <stdio.h>

int			main(void) {
	char	*null = NULL;

	printf("Attention aux segf\n");
	null[0] = 'a';
	return (0);
}

