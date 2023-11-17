#include "ft_strace.h"

void		print_int(int nb) {
	fprintf(stderr, "%d", nb);
}

void		print_uint(unsigned int nb) {
	fprintf(stderr, "%u", nb);
}

void		print_sizet(size_t size) {
	fprintf(stderr, "%lu", size);
}

void		print_hex(unsigned int nb) {
	fprintf(stderr, "0x%x", nb);
}

void		print_intptr(int *ptr) {
	fprintf(stderr, "%d", *ptr);
}

void		print_constintptr(const int *ptr) {
	fprintf(stderr, "%d", *ptr);
}

void		print_uintptr(unsigned int *ptr) { 
	fprintf(stderr, "%u", *ptr);
}

void		print_sizetptr(size_t *size) {
	fprintf(stderr, "%lu", *size);
}

void		print_long(long nb) {
	fprintf(stderr, "%ld", nb);
}

void		print_ulong(unsigned long nb) {
	fprintf(stderr, "%lu", nb);
}

void		print_constulong(const unsigned long nb) {
	fprintf(stderr, "%lu", nb);
}

void		print_u32(uint32_t nb) {
	fprintf(stderr, "%u", nb);
}

void		print_u32ptr(uint32_t *nb) {
	fprintf(stderr, "%u", *nb);
}

void		print_u64(uint64_t nb) { 
	fprintf(stderr, "%lu", nb);
}

void		print_u64ptr(uint64_t *nb) {
	fprintf(stderr, "%lu", *nb);
}

void		print_voidptr(void *ptr) {
	if (ptr)
		fprintf(stderr, "%llp", ptr);
	else
		fprintf(stderr, "NULL");
}

void		print_voidvoidptr(void **ptr) { 
	if (ptr)
		fprintf(stderr, "%llp", ptr);
	else
		fprintf(stderr, "NULL");
}

void		print_constvoidptr(const void *ptr) {
	if (ptr)
		fprintf(stderr, "%llp", ptr);
	else
		fprintf(stderr, "NULL");
}

void		print_constvoidvoidptr(const void **ptr) { 
	fprintf(stderr, "%llp", ptr);
}

void		print_charptr(char *str) {
	int		i;

	i = 0;
	write(STDERR_FILENO, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(STDERR_FILENO, "\n", 2);
		}
		else
			write(STDERR_FILENO, str + i, 1);
		if (i == 31)
		{
			write(STDERR_FILENO, "\"...", 4);
			return ;
		}
		i++;
	}
	write(STDERR_FILENO, "\"", 1);
}

void		print_ucharptr(unsigned char *str) {
	int		i;

	i = 0;
	write(STDERR_FILENO, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(STDERR_FILENO, "\n", 2);
		}
		else
			write(STDERR_FILENO, str + i, 1);
		if (i == 31)
		{
			write(STDERR_FILENO, "\"...", 4);
			return ;
		}
		i++;
	}
	write(STDERR_FILENO, "\"", 1);
}

void		print_constcharptr(const char *str) {
	int		i;

	i = 0;
	write(STDERR_FILENO, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(STDERR_FILENO, "\\n", 2);
		}
		else
			write(STDERR_FILENO, str + i, 1);
		if (i == 31)
		{
			write(STDERR_FILENO, "\"...", 4);
			return ;
		}
		i++;
	}
	write(STDERR_FILENO, "\"", 1);
}

void		print_charptrptr(const char **array) {
	int		i = 0;

	fprintf(stderr, "[");
	while (array[i]) {
		fprintf(stderr, "-%c-, ", array[i][0]);
		i++;
		break;
	}
	fprintf(stderr, "] -- %d printed", i);
}
