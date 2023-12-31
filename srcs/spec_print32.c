#include "ft_strace.h"

void		finish_read_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ecx, regs.edx, false);
	fprintf(stderr, ", %d", regs.edx);
}

void		print_read_32(t_user_regs32 regs)
{
	fprintf(stderr, "%d, ", regs.ebx);
}

void		finish_pread64_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ecx, regs.edx, false);
	fprintf(stderr, ", %d, %d", regs.edx, regs.esi);
}

void		print_pread64_32(t_user_regs32 regs)
{
	fprintf(stderr, "%d, ", regs.ebx);
}

void		finish_getrandom_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ebx, regs.ecx, true);
	fprintf(stderr, ", %d, %d", regs.ecx, regs.edx);
}

void		print_getrandom_32(void)
{
	;
}

void		finish_wait4_32(t_user_regs32 regs)
{
	uintptr_t	tmp = (uintptr_t)regs.ecx;
	print_voidptr((void*)tmp);
	fprintf(stderr, ", %d, ", regs.edx);
	tmp = (uintptr_t)regs.esi;
	print_voidptr((void*)tmp);
}

void		print_wait4_32(t_user_regs32 regs)
{
	fprintf(stderr, "%d, ", regs.ebx);
}

void		print_write_32(pid_t pid, t_user_regs32 regs)
{
	fprintf(stderr, "%d, ", regs.ebx);
	print_buffer(pid, regs.ecx, regs.edx, false);
	fprintf(stderr, ", %d", regs.edx);
}
