#include "ft_strace.h"

void		exit_error(char *name, char *msg) {
	printf("Error: %s %s\n", name, msg);
	exit(0);
}

void		print_reg(struct user_regs_struct regs) {
/*	printf("r15 = 0x%lx\n", regs.r15);
	printf("r14 = 0x%lx\n", regs.r14);
	printf("r13 = 0x%lx\n", regs.r13);
	printf("r12 = 0x%lx\n", regs.r12);
	printf("rbp = 0x%lx\n", regs.rbp);
	printf("rbx = 0x%lx\n", regs.rbx);*/
	printf("r8 = 0x%lx\n", regs.r8);
	printf("r9 = 0x%lx\n", regs.r9);
	printf("r10 = 0x%lx\n", regs.r10);
	printf("r11 = 0x%lx\n", regs.r11);
	printf("rax = 0x%lx\n", regs.rax);
	printf("rcx = 0x%lx\n", regs.rcx);
	printf("rdx = 0x%lx\n", regs.rdx);
	printf("rsi = 0x%lx\n", regs.rsi);
	printf("rdi = 0x%lx\n", regs.rdi);
	printf("orig_rax = 0x%lx\n", regs.orig_rax);
/*	printf("rip = 0x%lx\n", regs.rip);
	printf("cs = 0x%lx\n", regs.cs);
	printf("eflags = 0x%lx\n", regs.eflags);
	printf("rsp = 0x%lx\n", regs.rsp);
	printf("ss = 0x%lx\n", regs.ss);
	printf("fs_base = 0x%lx\n", regs.fs_base);
	printf("gs_base = 0x%lx\n", regs.gs_base);
	printf("es = 0x%lx\n", regs.es);
	printf("fs = 0x%lx\n", regs.fs);
	printf("gs = 0x%lx\n", regs.gs);*/
}

void	*read_process_memory(pid_t pid, unsigned long addr, int size) {
    struct iovec local[1];
    struct iovec remote[1];
	if (!addr)
		return (NULL);
	
	void *ret_addr;

	ret_addr = (void *)malloc(sizeof(char) * size);
    local[0].iov_base = ret_addr;
    local[0].iov_len = size;

    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = size;

    ssize_t bytesRead = process_vm_readv(pid, local, 1, remote, 1, 0);

    if (bytesRead < 0) {
        perror("process_vm_readv");
        exit(EXIT_FAILURE);
    }

	char	*buf = ret_addr;
	buf[bytesRead] = '\0';

    return (ret_addr);
}

void		print_tamales(pid_t pid, unsigned long reg, int type) {
	void	*ptr;
	switch (type) {
		case INT://1
		case PID_T:
			print_int((int)reg);
			break;
		case UINT://2
			print_uint((unsigned int)reg);
			break;
		case SIZE_T://3
			print_sizet((size_t)reg);
			break;
		case LONG://8
			print_long((long)reg);
			break;
		case UNSIGNED_LONG://9
			print_ulong((unsigned long)reg);
			break;
		case U32://12
			print_u32((uint32_t)reg);
			break;
		case U64://14
			print_u64((uint64_t)reg);
			break;
		case CHAR_PTR://20
			if (ptr = read_process_memory(pid, reg, 256))
				print_charptr((char*)ptr);
			else
				ft_printf("NULL");
			break;
		case UNSIGNED_CHAR_PTR://21
			if (ptr = read_process_memory(pid, reg, 256))
				print_ucharptr((unsigned char*)ptr);
			else
				ft_printf("NULL");
			break;
		case CONST_CHAR_PTR://22
			if (ptr = read_process_memory(pid, reg, 256))
				print_constcharptr((const char*)ptr);
			else
				ft_printf("NULL");
			break;
		default:
			print_voidptr((void*)reg);
	}
}


pid_t		s_tracee;
int			s_nbargs;
char		**s_args;

#define NB_SPEC 3

bool		print_spec(pid_t pid, struct user_regs_struct regs, int read)
{
	static int	sysspec[] = {0, 17, 318};

	for (int i = 0; i < NB_SPEC; i++)
		if (sysspec[i] == regs.orig_rax)
			switch (i) {
			case 0:
				if (read == 1)
				{
					finish_read(pid, regs);
					return false;
				}
				print_read(pid, regs);
				return true;
			case 1:
				if (read == 1)
				{
					finish_read(pid, regs);
					return false;
				}
				print_pread64(pid, regs);
				return true;
			case 2:
				print_getrandom(pid, regs);
				return true;
			}
	return false;
}

int			print64(pid_t tracee, struct user_regs_struct regs, int read) {
	if (read != 1)
		ft_printf("%s(", sysinfo_64[regs.orig_rax].sysname);
	if (print_spec(tracee, regs, read))
		return (1);//print_spec(tracee, regs);
	else
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
/*	ft_printf(")\t\t = ");
	if (sysinfo_64[regs.orig_rax].ret == 1)
		ft_printf("%llp\n", regs.rax);
	else
		ft_printf("%d\n", regs.rax);*/
}

int			print_data(pid_t tracee, struct user_regs_struct regs, int read) {
	if (SYS64 == 1)
		return (print64(tracee, regs, read));
	//else
	//	printf("Syscall num %d: %s\n", regs.orig_rax, sysinfo_86[regs.orig_rax].sysname);
	//printf("Syscall num: %d\n", regs.orig_rax);
}

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

void		sig_handler(int sig) {
	const int		sig_id[5] = {SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM};

	ft_printf("Process %u detached\n <detached ...>\n", s_tracee);
	switch (sig) {
		case 2:
		case 13:
			wait(NULL);
			exit(0);
		case 1:
			ft_printf("[1]\t%d %s", getpid(), "hangup");
		case 3:
			ft_printf("[1]\t%d %s", getpid(), "quit (core dumped)");
		case 15:
			ft_printf("[1]\t%d %s", getpid(), "terminated");
	}
	for (int i = 0; i < s_nbargs; i++)
		ft_printf("%s ", s_args[i]);
	ft_printf("\n");
	waitpid(s_tracee, NULL, 0);
	exit(0);
}

void		init_signal()
{
	signal(SIGHUP, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGPIPE, &sig_handler);
	signal(SIGTERM, &sig_handler);
	signal(SIGQUIT, &sig_handler);
}

int			main(int argc, char **argv, char **env) {
	pid_t		tracee;

	if (argc == 1)
		exit_error(argv[0], "needs argument");
	if ((tracee = fork()) == -1)
		exit_error(argv[0], "fork failed");
	s_tracee = tracee;
	s_nbargs = argc;
	s_args = argv;
	init_signal();
	if (tracee == 0) { 
		raise(SIGSTOP);
		execve(argv[1], argv + 1, env);
	}
	else
		ft_strace(tracee);
	return (0);
}
