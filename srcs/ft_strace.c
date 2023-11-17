#include "ft_strace.h"

void		init_blocked(sigset_t *blocked) {
	sigaddset(blocked, SIGHUP);
	sigaddset(blocked, SIGINT);
	sigaddset(blocked, SIGQUIT);
	sigaddset(blocked, SIGPIPE);
	sigaddset(blocked, SIGTERM);
}

int			ptrace_continue(pid_t tracee, sigset_t empty, sigset_t blocked, int signal);

int			ptrace_wait(pid_t tracee, sigset_t empty, sigset_t blocked)
{
	int			status;

	sigprocmask(SIG_SETMASK, &empty, NULL);
	waitpid(tracee, &status, 0);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	if (WIFEXITED(status))
		return (1);
	if (WIFSTOPPED(status))
		if (sig_handle(tracee, status) != -1)
			ptrace_continue(tracee, empty, blocked, WSTOPSIG(status));
	return (0);
}

int			ptrace_continue(pid_t tracee, sigset_t empty, sigset_t blocked, int signal)
{
	if (signal == 0)
	{
		if (ptrace(PTRACE_SYSCALL, tracee, 0, 0) == -1)
			return (-1);
	}
	else
	{
		if (ptrace(PTRACE_SYSCALL, tracee, 0, signal) == -1)
			return (-1);
	}
	return (ptrace_wait(tracee, empty, blocked));
}

void		print_sysreturn(struct user_regs_struct regs, int arch)
{
	fprintf(stderr, ")\t\t = ");
	if (arch == 64)
	{
		if (sysinfo_64[regs.orig_rax].ret == 1)
			fprintf(stderr, "%llp\n", regs.rax);
		else
			fprintf(stderr, "%d\n", regs.rax);
		return ;
	}
	t_user_regs32	*r32;
	r32 = (t_user_regs32*)&regs;

	if (r32->orig_eax >= 386) {
		fprintf(stderr, "0\n");
		return ;
	}
	if (sysinfo_32[r32->orig_eax].ret == 1)
		fprintf(stderr, "%llp\n", r32->eax);
	else
		fprintf(stderr, "%d\n", r32->eax);
}

int			get_return(struct user_regs_struct regs, int arch)
{
	if (arch == 64)
		return (regs.rdi);
	t_user_regs32	*r32;

	r32 = (t_user_regs32 *)(&regs);
	return (r32->ebx);
}

void		ft_strace(pid_t tracee)
{
	sigset_t		empty;
	sigset_t		blocked;
	int				read;
	unsigned char	ret = 0;

	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;

	io.iov_len = sizeof(regs);
	sigemptyset(&empty);
	init_blocked(&blocked);
	if (ptrace(PTRACE_SEIZE, tracee, 0, 0) == -1)
		exit(0);
	ptrace_wait(tracee, empty, blocked);
	int				arch = 64;
	if (ptrace(PTRACE_INTERRUPT, tracee, 0, 0) == -1)
		exit(0);
	ptrace_continue(tracee, empty, blocked, 0);
	while (1) {
		if (ptrace_continue(tracee, empty, blocked, 0) != 0)
			break;
		ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
		if (io.iov_len == sizeof(t_user_regs32) && arch == 64)
		{
			fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n", tracee);
			arch = 32;
		}
		else if (io.iov_len == sizeof(regs) && arch == 32)
		{
			fprintf(stderr, "[ Process PID=%d runs in 64 bit mode. ]\n", tracee);
			arch = 64;
		}
		if (regs.orig_rax == 231 /*orig_rax == 252*/)
			ret = get_return(regs, arch);
		read = print_data(tracee, regs, 0, arch);
		if (ptrace_continue(tracee, empty, blocked, 0) != 0)
			break ;
		ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
		if (io.iov_len == sizeof(t_user_regs32))
			arch = 32;
		else
			arch = 64;
		if (read == 1)
			print_data(tracee, regs, read, arch);
		print_sysreturn(regs, arch);
	}
	wait(NULL);
	fprintf(stderr, ") =\t\t?\n");
	fprintf(stderr, "+++ exited with %u +++\n", ret);
}
