#include "ft_strace.h"

void		print_sigcode_chld(siginfo_t info, int code)
{
	const char		sys_code[6][14] = {"CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "CLD_TRAPPED", "CLD_STOPPED", "CLD_CONTINUED"};

	ft_printf("--- SIGCHLD {si_signo=SIGCHLD, si_code=%s, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%d, si_stime=%d} ---\n", sys_code[code - 1], info.si_pid, info.si_uid, info.si_status, info.si_utime, info.si_stime);
}

void		print_sigcode_int(siginfo_t info, int code)
{
	const int		sys_val[8] = {-6, -5, -4, -3, -2, -1, 0, 0x80};
	const char		sys_code[8][11] = {"SI_TKILL", "SI_SIGIO", "SI_ASYNCIO", "SI_MESGQ", "SI_TIMER", "SI_QUEUE", "SI_USER", "SI_KERNEL"};

	ft_putstr("--- SIGINT {si_signo=SIGINT, si_code=");
	for (int i = 0; i < 8; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_pid=%d, si_uid=%d} ---\n", info.si_pid, info.si_uid);
}

void		print_sigcode_segv(siginfo_t info, int code)
{
	const int		sys_val[2] = {1, 2};
	const char		sys_code[2][12] = {"SEGV_MAPERR", "SEGV_ACCERR"};

	ft_putstr("--- SIGSEGV {si_signo=SIGSEGV, si_code=");
	for (int i = 0; i < 2; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	if (info.si_addr)
		ft_printf(", si_addr=%p} ---\n", info.si_addr);
	else
		ft_printf(", si_addr=NULL\n");
	ft_printf("+++ killed by SIGSEGV (core dumped) +++\n");
	ft_printf("[1]\t%d segmentation fault (core dumped)\n", getpid());
	exit(0);
}

void		print_sigcode_fpe(siginfo_t info, int code)
{
	const int		sys_val[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	const char		sys_code[8][12] = {"FPE_INTDIV", "FPE_INTOVF", "FPE_FLTDIV", "FPE_FLTOVF", "FPE_FLTUND", "FPE_FLTRES", "FPE_FLTINV", "FPE_FLTSUB"};

	ft_putstr("--- SIGFPE {si_signo=SIGFPE, si_code=");
	for (int i = 0; i < 2; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_addr=%p} ---\n", info.si_addr);
	ft_printf("+++ killed by SIGFPE (core dumped) +++\n");
	ft_printf("[1]\t%d Floating point exception (core dumped)\n", getpid());
	exit(0);
}

void		print_sigcode_bus(siginfo_t info, int code)
{
	const int		sys_val[3] = {1, 2, 3};
	const char		sys_code[3][11] = {"BUS_ADRALN", "BUS_ADRERR", "BUS_OBJERR"};

	ft_putstr("--- SIGBUS {si_signo=SIGBUS, si_code=");
	for (int i = 0; i < 2; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_addr=%p} ---\n", info.si_addr);
	ft_printf("+++ killed by SIGBUS (core dumped) +++\n");
	ft_printf("[1]\t%d bus error (core dumped)\n", getpid());
	exit(0);
}

void		print_sigcode_ill(siginfo_t info, int code)
{
	const int		sys_val[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	const char		sys_code[8][11] = {"ILL_ILLOPC", "ILL_ILLOPN", "ILL_ILLADR", "ILL_ILLTRP", "ILL_PRVOPC", "ILL_PRVREG", "ILL_COPROC", "ILL_BADSTK"};

	ft_putstr("--- SIGILL {si_signo=SIGILL, si_code=");
	for (int i = 0; i < 2; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_addr=%p} ---\n", info.si_addr);
	ft_printf("+++ killed by SIGILL (core dumped) +++\n");
	ft_printf("[1]\t%d illegal instruction (core dumped)\n", getpid());
	exit(0);
}

void		print_sigcode_poll(siginfo_t info, int code)
{
	const int		sys_val[6] = {1, 2, 3, 4, 5, 6};
	const char		sys_code[6][9] = {"POLL_IN", "POLL_OUT", "POLL_MSG", "POLL_ERR", "POLL_PRI", "POLL_HUP"};

	ft_putstr("--- SIGPOLL {si_signo=SIGPOLL, si_code=");
	for (int i = 0; i < 6; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_band=%ld, si_fd=%d} ---\n", info.si_band, info.si_fd);
}

void		print_sigcode_winch(siginfo_t info, int code)
{
	const int		sys_val[8] = {-6, -5, -4, -3, -2, -1, 0, 0x80};
	const char		sys_code[8][11] = {"SI_TKILL", "SI_SIGIO", "SI_ASYNCIO", "SI_MESGQ", "SI_TIMER", "SI_QUEUE", "SI_USER", "SI_KERNEL"};

	ft_putstr("--- SIGWINCH {si_signo=SIGWINCH, si_code=");
	for (int i = 0; i < 8; i++)
	{
		if (sys_val[i] == code)
		{
			ft_putstr(sys_code[i]);
			break ;
		}
	}
	ft_printf(", si_pid=%d, si_uid=%d} ---\n", info.si_pid, info.si_uid);
}

int			sig_handle(pid_t pid, int status)
{
	int signalNumber = WSTOPSIG(status);

	if (signalNumber == SIGTRAP || signalNumber == SIGSTOP)
		return (-1);
	siginfo_t	info;
	if (ptrace(PTRACE_GETSIGINFO, pid, 0, &info) == -1) {
		perror("ptrace getsiginfo");
		exit(EXIT_FAILURE);
	}
	#define SIG_NB 8
	const int		sig_id[SIG_NB] = {SIGSEGV, SIGINT, SIGILL, SIGBUS, SIGFPE, SIGCHLD, SIGPOLL, SIGWINCH};
	const void		(*print_sigcode[SIG_NB])(siginfo_t info, int code) = {&print_sigcode_segv, &print_sigcode_int, &print_sigcode_ill, &print_sigcode_bus, &print_sigcode_fpe, &print_sigcode_chld, &print_sigcode_poll, &print_sigcode_winch};

	for (int i = 0; i < SIG_NB; i++)
	{
		if (sig_id[i] == info.si_signo)
		{
			print_sigcode[i](info, info.si_code);
			break ;
		}
	}
	return (0);
}
