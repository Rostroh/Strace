#include "ft_strace.h"

void		print_int(int nb) {
	ft_printf("%d", nb);
}

void		print_uint(unsigned int nb) {
	ft_printf("%u", nb);
}

void		print_sizet(size_t size) {
	ft_printf("%lu", size);
}

void		print_intptr(int *ptr) {
	ft_printf("%d", *ptr);
}

void		print_constintptr(const int *ptr) {
	ft_printf("%d", *ptr);
}

void		print_uintptr(unsigned int *ptr) { 
	ft_printf("%u", *ptr);
}

void		print_sizetptr(size_t *size) {
	ft_printf("%lu", *size);
}

void		print_long(long nb) {
	ft_printf("%ld", nb);
}

void		print_ulong(unsigned long nb) {
	ft_printf("%lu", nb);
}

void		print_constulong(const unsigned long nb) {
	ft_printf("%lu", nb);
}

void		print_u32(uint32_t nb) {
	ft_printf("%u", nb);
}

void		print_u32ptr(uint32_t *nb) {
	ft_printf("%u", *nb);
}

void		print_u64(uint64_t nb) { 
	ft_printf("%lu", nb);
}

void		print_u64ptr(uint64_t *nb) {
	ft_printf("%lu", *nb);
}

void		print_voidptr(void *ptr) {
	if (ptr)
		ft_printf("%llp", ptr);
	else
		ft_printf("NULL");
}

void		print_voidvoidptr(void **ptr) { 
	if (ptr)
		ft_printf("%llp", ptr);
	else
		ft_printf("NULL");
}

void		print_constvoidptr(const void *ptr) {
	if (ptr)
		ft_printf("%llp", ptr);
	else
		ft_printf("NULL");
}

void		print_constvoidvoidptr(const void **ptr) { 
	ft_printf("%llp", ptr);
}

void		print_charptr(char *str) {
	int		i;

	i = 0;
	write(1, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(1, "\n", 2);
		}
		else
			write(1, str + i, 1);
		if (i == 31)
		{
			write(1, "\"...", 4);
			return ;
		}
		i++;
	}
	write(1, "\"", 1);
}

void		print_ucharptr(unsigned char *str) {
	int		i;

	i = 0;
	write(1, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(1, "\n", 2);
		}
		else
			write(1, str + i, 1);
		if (i == 31)
		{
			write(1, "\"...", 4);
			return ;
		}
		i++;
	}
	write(1, "\"", 1);
}

void		print_constcharptr(const char *str) {
	int		i;

	i = 0;
	write(1, "\"", 1);
	while (str[i] != '\0') {
		if (str[i] == '\n') {
			write(1, "\\n", 2);
		}
		else
			write(1, str + i, 1);
		if (i == 31)
		{
			write(1, "\"...", 4);
			return ;
		}
		i++;
	}
	write(1, "\"", 1);
}

void		print_charptrptr(const char **array) {
	int		i = 0;

	ft_printf("[");
	while (array[i]) {
		ft_printf("-%c-, ", array[i][0]);
		i++;
		break;
	}
	ft_printf("] -- %d printed", i);
}
