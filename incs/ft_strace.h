#ifndef FT_STRACE_H
# define FT_STRACE_H

# include "syscallx86.h"
//# include "syscall.h"

# include "../libft/include/libft.h"
# include <stdio.h>
# include <sys/ptrace.h>
# include <sys/wait.h>
# include <sys/user.h>
# include <sys/uio.h>
# include <errno.h>
# include <elf.h>

void		exit_error(char *name, char *msg);


//OUTPUT FUNCS
void		print_int(int nb);
void		print_uint(unsigned int nb);
void		print_sizet(size_t size);
void		print_intptr(int *ptr);
void		print_constintptr(const int *ptr);
void		print_uintptr(unsigned int *ptr);
void		print_sizetptr(size_t *size);
void		print_long(long nb);
void		print_ulong(unsigned long nb);
void		print_constulong(const unsigned long nb);
void		print_u32(uint32_t nb);
void		print_u32ptr(uint32_t *nb);
void		print_u64(uint64_t nb);
void		print_u64ptr(uint64_t *nb);
void		print_voidptr(void *ptr);
void		print_voidvoidptr(void **ptr);
void		print_constvoidptr(const void *ptr);
void		print_constvoidvoidptr(const void **ptr);
void		print_charptr(char *str);
void		print_ucharptr(unsigned char *str);
void		print_constcharptr(const char *str);
void		print_charptrptr(const char **array);

#endif
