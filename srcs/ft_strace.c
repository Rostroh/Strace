#include "ft_strace.h"

void		init_blocked(sigset_t *blocked) {
	sigaddset(blocked, SIGHUP);
	sigaddset(blocked, SIGINT);
	sigaddset(blocked, SIGQUIT);
	sigaddset(blocked, SIGPIPE);
	sigaddset(blocked, SIGTERM);
}

int			ptrace_continue(pid_t tracee, sigset_t empty, sigset_t blocked);

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
			//ptrace(PTRACE_LISTEN, tracee, 0, 0);
			ptrace_continue(tracee, empty, blocked);
	return (0);
}

int			ptrace_continue(pid_t tracee, sigset_t empty, sigset_t blocked)
{
	if (ptrace(PTRACE_SYSCALL, tracee, 0, 0) == -1)
		return (-1);
	return (ptrace_wait(tracee, empty, blocked));
}

void		print_sysreturn(struct user_regs_struct regs)
{
	ft_printf(")\t\t = ");
	if (sysinfo_64[regs.orig_rax].ret == 1)
		ft_printf("%llp\n", regs.rax);
	else
		ft_printf("%d\n", regs.rax);

}

void		ft_strace(pid_t tracee)
{
	sigset_t	empty;
	sigset_t	blocked;
	int			sysret;
	int			status;
	int			read;
	unsigned char ret = 0;

	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	sigemptyset(&empty);
	init_blocked(&blocked);
	if (ptrace(PTRACE_SEIZE, tracee, 0, 0) == -1)
		exit(0);
	ptrace_wait(tracee, empty, blocked);
	if (ptrace(PTRACE_INTERRUPT, tracee, 0, 0) == -1)
		exit(0);//_error(argv[0], "ptrace error on PTRACE_INTERRUPT");
	ptrace_continue(tracee, empty, blocked);
	while (1) {
		if (ptrace_continue(tracee, empty, blocked) != 0)
			break;
		ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
		if (regs.orig_rax == 231)
			ret = regs.rdi;
		read = print_data(tracee, regs, 0);
		if (ptrace_continue(tracee, empty, blocked) != 0)
			break ;
		ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
		if (read == 1)
			print_data(tracee, regs, read);
		print_sysreturn(regs);
	}
	wait(NULL);
	ft_printf(") =\t\t?\n");
	ft_printf("+++ exited with %u +++\n", ret);
	//printf("A little cozy over here\n");
}
