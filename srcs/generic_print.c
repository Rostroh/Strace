#include "ft_strace.h"

bool		print_spec(pid_t pid, struct user_regs_struct regs, int read)
{
	switch (regs.orig_rax) {
		case 0:
			if (read == 1)
			{
				finish_read(pid, regs);
				return false;
			}
			print_read(pid, regs);
			return true;
		case 17:
			if (read == 1)
			{
				finish_pread64(pid, regs);
				return false;
			}
			print_pread64(pid, regs);
			return true;
		case 318:
			if (read == 1)
			{
				finish_getrandom(pid, regs);
				return false;
			}
			print_getrandom(pid, regs);
			return true;
		case 1:
			if (read == 1)
				return false;
			print_write(pid, regs);
			return true;
		case 61:
			if (read == 1)
			{
				finish_wait4(pid, regs);
				return false;
			}
			print_wait4(pid, regs);
			return true;
		default:
			return false;
	}
	return false;
}

bool		print_spec32(pid_t pid, t_user_regs32 regs, int read)
{
	switch (regs.orig_eax) {
		case 3:
			if (read == 1)
			{
				finish_read_32(pid, regs);
				return false;
			}
			print_read_32(pid, regs);
			return true;
		case 180:
			if (read == 1)
			{
				finish_pread64_32(pid, regs);
				return false;
			}
			print_pread64_32(pid, regs);
			return true;
		case 355:
			if (read == 1)
			{
				finish_getrandom_32(pid, regs);
				return false;
			}
			print_getrandom_32(pid, regs);
			return true;
		case 4:
			if (read == 1)
				return false;
			print_write_32(pid, regs);
			return true;
		case 114:
			if (read == 1)
			{
				finish_wait4_32(pid, regs);
				return false;
			}
			print_wait4_32(pid, regs);
			return true;
		default:
			return false;
	}
	return false;
}

int			print64(pid_t tracee, struct user_regs_struct regs, int read) {
	if (read != 1)
		ft_printf("%s(", sysinfo_64[regs.orig_rax].sysname);
	if (print_spec(tracee, regs, read))
		return (1);//print_spec(tracee, regs);
	else if (read != 1)
	{
		if (sysinfo_64[regs.orig_rax].p1 != 0) {
			print_tamales(tracee, regs.rdi, sysinfo_64[regs.orig_rax].p1);
		}
		if (sysinfo_64[regs.orig_rax].p2 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.rsi, sysinfo_64[regs.orig_rax].p2);
		}
		if (sysinfo_64[regs.orig_rax].p3 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.rdx, sysinfo_64[regs.orig_rax].p3);
		}
		if (sysinfo_64[regs.orig_rax].p4 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.r10, sysinfo_64[regs.orig_rax].p4);
		}
		if (sysinfo_64[regs.orig_rax].p5 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.r8, sysinfo_64[regs.orig_rax].p5);
		}
		if (sysinfo_64[regs.orig_rax].p6 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.r9, sysinfo_64[regs.orig_rax].p6);
		}
	}
	return (0);
}

int			print32(pid_t tracee, t_user_regs32 regs, int read) {
	if (read != 1)
		ft_printf("%s(", sysinfo_32[regs.orig_eax].sysname);
	if (print_spec32(tracee, regs, read))
		return (1);//print_spec(tracee, regs);
	if (read != 1)
	{
		if (sysinfo_32[regs.orig_eax].p1 != 0) {
			print_tamales(tracee, regs.ebx, sysinfo_32[regs.orig_eax].p1);
		}
		if (sysinfo_32[regs.orig_eax].p2 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.ecx, sysinfo_32[regs.orig_eax].p2);
		}
		if (sysinfo_32[regs.orig_eax].p3 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.edx, sysinfo_32[regs.orig_eax].p3);
		}
		if (sysinfo_32[regs.orig_eax].p4 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.esi, sysinfo_32[regs.orig_eax].p4);
		}
		if (sysinfo_32[regs.orig_eax].p5 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.edi, sysinfo_32[regs.orig_eax].p5);
		}
		if (sysinfo_32[regs.orig_eax].p6 != 0) {
			ft_printf(", ");
			print_tamales(tracee, regs.ebp, sysinfo_32[regs.orig_eax].p6);
		}
	}
	return (0);
}

int			print_data(pid_t tracee, struct user_regs_struct regs, int read, int arch) {
	if (arch == 64)
		return (print64(tracee, regs, read));
	else
	{
		t_user_regs32		*tmp;

		tmp = (t_user_regs32*)&regs;
		return (print32(tracee, *tmp, read));
	}
	return (0);
	//else
	//	printf("Syscall num %d: %s\n", regs.orig_rax, sysinfo_86[regs.orig_rax].sysname);
	//printf("Syscall num: %d\n", regs.orig_rax);
}

