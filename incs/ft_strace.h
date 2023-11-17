#ifndef FT_STRACE_H
# define FT_STRACE_H

#define _GNU_SOURCE
# include "syscallx86.h"
//# include "syscall.h"

# include "../libft/include/libft.h"
# include <stdio.h>
# include <stdlib.h>
# include <signal.h>
# include <sys/ptrace.h>
# include <sys/wait.h>
# include <sys/user.h>
# include <errno.h>
# include <elf.h>
# include <stdbool.h>
# include <fcntl.h>
//# include <sys/siginfo.h>
# include <sys/uio.h>

extern pid_t	p_tracee;

typedef struct	s_user_regs_struct_32
{
	uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint16_t ds, __ds;
    uint16_t es, __es;
    uint16_t fs, __fs;
    uint16_t gs, __gs;
    uint32_t orig_eax;
    uint32_t eip;
    uint16_t cs, __cs;
    uint32_t eflags;
    uint32_t esp;
    uint16_t ss, __ss;
}				t_user_regs32;

void		ft_strace(pid_t tracee);
void		exit_error(char *name, char *msg);
int			sig_handle(pid_t pid, int status);
void		*read_process_memory(pid_t pid, unsigned long addr, int size);
int			print_data(pid_t tracee, struct user_regs_struct regs, int read, int arch);
void		print_tamales(pid_t pid, unsigned long reg, int type);
void		print_buffer(pid_t pid, unsigned long addr, int size, bool byte);

//OUTPUT TYPE_FUNCS
void		print_int(int nb);
void		print_uint(unsigned int nb);
void		print_sizet(size_t size);
void		print_hex(unsigned int nb);
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


//OUTPUT SYSCALL_FUNCS
void		finish_read(pid_t pid, struct user_regs_struct regs);
void		print_read(struct user_regs_struct regs);
void		finish_pread64(pid_t pid, struct user_regs_struct regs);
void		print_pread64(struct user_regs_struct regs);
void		finish_getrandom(pid_t pid, struct user_regs_struct regs);
void		print_getrandom(void);
void		finish_wait4(struct user_regs_struct regs);
void		print_wait4(struct user_regs_struct regs);
void		print_write(pid_t pid, struct user_regs_struct regs);

//OUTPUT SYSCALL32_FUNCS
void		finish_read_32(pid_t pid, t_user_regs32 regs);
void		print_read_32(t_user_regs32 regs);
void		finish_pread64_32(pid_t pid, t_user_regs32 regs);
void		print_pread64_32(t_user_regs32 regs);
void		finish_getrandom_32(pid_t pid, t_user_regs32 regs);
void		print_getrandom_32(void);
void		finish_wait4_32(t_user_regs32 regs);
void		print_wait4_32(t_user_regs32 regs);
void		print_write_32(pid_t pid, t_user_regs32 regs);
#endif
