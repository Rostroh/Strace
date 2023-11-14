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
		//case UNKNOWN:
		//	break;
		case INT://1
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

#define NB_SPEC 3

bool		is_regs(int sysid)
{
	static int	sysspec[] = {0, 17, 318};

	for (int i = 0; i < NB_SPEC; i++)
		if (sysspec[i] == sysid)
			return (true);
	return (false);
}

bool		print_spec(pid_t pid, struct user_regs_struct regs)
{
	static int	sysspec[] = {0, 17, 318};

	for (int i = 0; i < NB_SPEC; i++)
		if (sysspec[i] == regs.orig_rax)
			switch (i) {
			case 0:
				print_read(pid, regs);
				return true;
			case 1:
				print_pread64(pid, regs);
				return true;
			case 2:
				print_getrandom(pid, regs);
				return true;
			}
	return false;
}

void		print64(pid_t tracee, struct user_regs_struct regs, int sysret) {
	ft_printf("%s(", sysinfo_64[regs.orig_rax].sysname);
	if (print_spec(tracee, regs))
		;//print_spec(tracee, regs);
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
	ft_printf(")\t\t = ");
	if (sysinfo_64[regs.orig_rax].ret == 1)
		ft_printf("%p\n", sysret);//regs.rax);
	else
		ft_printf("%d\n", sysret);//regs.rax);
}

void		print_data(pid_t tracee, struct user_regs_struct regs, int sysret) {
	if (SYS64 == 1)
		print64(tracee, regs, sysret);
	//else
	//	printf("Syscall num %d: %s\n", regs.orig_rax, sysinfo_86[regs.orig_rax].sysname);
	//printf("Syscall num: %d\n", regs.orig_rax);
}

void		init_blocked(sigset_t *blocked) {
	sigaddset(blocked, SIGHUP);
	sigaddset(blocked, SIGINT);
	sigaddset(blocked, SIGQUIT);
	sigaddset(blocked, SIGPIPE);
	sigaddset(blocked, SIGTERM);
}

void		print_sigcode_chld(int code)
{
	const char		sys_code[6][14] = {"CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "CLD_TRAPPED", "CLD_STOPPED", "CLD_CONTINUED"};

	ft_putstr(sys_code[code - 1]);
}

int			sig_handle(pid_t pid, int status)
{
	int signalNumber = WSTOPSIG(status);

	if (!(signalNumber == SIGHUP || signalNumber == SIGINT || signalNumber == SIGQUIT || signalNumber == SIGPIPE || signalNumber == SIGTERM || signalNumber == SIGCHLD))
		return (-1);
	siginfo_t	info;
	if (ptrace(PTRACE_GETSIGINFO, pid, 0, &info) == -1) {
		perror("ptrace getsiginfo");
		exit(EXIT_FAILURE);
	}
	#define SIG_NB 6
	const char		signame[SIG_NB][8] = {"SIGHUP", "SIGINT", "SIGQUIT", "SIGPIPE", "SIGTERM", "SIGCHLD"};
	const int		sig_id[SIG_NB] = {1, 2, 3, 13, 15, 17};
	const void		(*print_sigcode[SIG_NB])(int code) = {NULL, NULL, NULL, NULL, NULL, &print_sigcode_chld};
	int		idx;
	for (idx = 0; idx < SIG_NB; idx++)
		if (sig_id[idx] == info.si_signo)
			break;
	int		idx2;
	for (idx2 = 0; idx2 < SIG_NB; idx2++)
		if (sig_id[idx2] == signalNumber)
			break;
	ft_printf("--- %s {si_signo=%s, si_code=", signame[idx2], signame[idx]);
	print_sigcode[idx](info.si_code);
	ft_printf(", si_pid=%d, si_uid=%d, si_status=%d, si_utime=%d, si_stime=%d} ---\n", info.si_pid, info.si_uid, info.si_status, info.si_utime, info.si_stime);
/*	printf("hup %d int %d quit %d pipe %d term %d chld %d\n", SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM, SIGCHLD);
	printf("Process stopped due to signal: %d\n", signalNumber);
	printf("Signal code: %d\n", info.si_code);
	printf("Signal errno: %d\n", info.si_errno);
	printf("Signal signo: %d\n", info.si_signo);*/
	//ptrace(PTRACE_SYSCALL, tracee, 0, 0)
	//ptrace(PTRACE_CONT, pid, 0, 0);
	return (0);
}

void		siguwu(void) {
	printf("Caught a sigint\n");
	exit(0);
}

int			main(int argc, char **argv, char **env) {
	pid_t		tracee;
	int			status;
	int			ret = 0;
	int			i = 0;
	sigset_t	empty;
	sigset_t	blocked;
	int			sysret;

	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	int	j = 0;
	while (env[j])
		j++;
	if (argc == 1)
		exit_error(argv[0], "needs argument");
	signal(SIGINT, siguwu);
	if ((tracee = fork()) == -1)
		exit_error(argv[0], "fork failed");
	if (tracee == 0) { 
		raise(SIGSTOP);
		execve(argv[1], argv + 1, env);
	}
	else {
		if (ptrace(PTRACE_SEIZE, tracee, 0, 0) == -1)
			exit_error(argv[0], "ptrace error on PTRACE_SEIZE");
		sigemptyset(&empty);
		init_blocked(&blocked);
		sigprocmask(SIG_SETMASK, &empty, NULL);
		waitpid(tracee, NULL, 0);
		sigprocmask(SIG_BLOCK, &blocked, NULL);
		ptrace(PTRACE_SYSCALL, tracee, 0, 0);
		sigprocmask(SIG_SETMASK, &empty, NULL);
		waitpid(tracee, NULL, 0);
		sigprocmask(SIG_BLOCK, &blocked, NULL);
		if (ptrace(PTRACE_INTERRUPT, tracee, 0, 0) == -1)
			exit_error(argv[0], "ptrace error on PTRACE_INTERRUPT");
		while (1) {
			if ((ret = ptrace(PTRACE_SYSCALL, tracee, 0, 0)) == -1)
			{
				printf("Probleme with %s\n", strerror(errno));
				exit_error(argv[0], "ptrace error on PTRACE_SYSCALL");
			}
			sigprocmask(SIG_SETMASK, &empty, NULL);
			waitpid(tracee, &status, 0);
			sigprocmask(SIG_BLOCK, &blocked, NULL);
			if (WIFEXITED(status)) {
				printf("Child exited 0\n");
				break ;
			}
			ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
			//print_reg(regs);
			sysret = regs.rax;
			printf("-- uwu ---\n");
			if (regs.orig_rax == 59)
			{
				ft_printf("execve(\"%s\", [", argv[1]);
				for (int j = 1; j < argc; j++)
				{
					ft_printf("\"%s\"", *(argv + j));
					if (j + 1 < argc)
						ft_printf(", ");
				}
				ft_printf("], %p /* %d vars */) = %d\n", env, j, regs.rax);
			}
			else
				print_data(tracee, regs, regs.rax);
			if ((ret = ptrace(PTRACE_SYSCALL, tracee, 0, 0)) == -1)
			{
				printf("Probleme with %s\n", strerror(errno));
				exit_error(argv[0], "ptrace error on PTRACE_SYSCALL");
			}
			sigprocmask(SIG_SETMASK, &empty, NULL);
			waitpid(tracee, &status, 0);
			sigprocmask(SIG_BLOCK, &blocked, NULL);
			if (WIFEXITED(status)) {
				printf("Child exited 1\n");
				break ;
			}
			ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
			printf("-- owo ---\n");
			print_data(tracee, regs, sysret);
			if (WIFSTOPPED(status))
			{
				if (sig_handle(tracee, status) != -1)
				{
					if ((ret = ptrace(PTRACE_SYSCALL, tracee, 0, 0)) == -1)
					{
						printf("Probleme with %s\n", strerror(errno));
						exit_error(argv[0], "ptrace error on PTRACE_SYSCALL");
					}
					sigprocmask(SIG_SETMASK, &empty, NULL);
					waitpid(tracee, &status, 0);
					sigprocmask(SIG_BLOCK, &blocked, NULL);
					if (WIFEXITED(status)) {
						printf("Child exited 2\n");
						break ;
					}
				}
			}
			i++;
		}
		wait(NULL);
		printf("A little cozy over here\n");
	}
	return (0);
}
