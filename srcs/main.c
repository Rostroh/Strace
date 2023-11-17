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
		printf("\n%s\n", strerror(errno));
        //perror("process_vm_readv");
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
		case UNSIGNED_INT:
		case UINT://2
			print_uint((unsigned int)reg);
			break;
		case SIZE_T://3
			print_sizet((size_t)reg);
			break;
		case HEX:
			print_hex((unsigned int)reg);
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
			if ((ptr = read_process_memory(pid, reg, 256)))
				print_charptr((char*)ptr);
			else
				ft_printf("NULL");
			break;
		case UNSIGNED_CHAR_PTR://21
			if ((ptr = read_process_memory(pid, reg, 256)))
				print_ucharptr((unsigned char*)ptr);
			else
				ft_printf("NULL");
			break;
		case CONST_CHAR_PTR://22
			if ((ptr = read_process_memory(pid, reg, 256)))
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

void		sig_handler(int sig) {
	//const int		sig_id[5] = {SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM};

	ft_printf("Process %u detached\n <detached ...>\n", s_tracee);
	switch (sig) {
		case 2:
		case 13:
			kill(s_tracee, sig);
			exit(0);
		case 1:
			ft_printf("[1]\t%d %s", getpid(), "hangup");
			break;
		case 3:
			ft_printf("[1]\t%d %s", getpid(), "quit (core dumped)");
			break;
		case 15:
			ft_printf("[1]\t%d %s", getpid(), "terminated");
			break;
	}
	for (int i = 0; i < s_nbargs; i++)
		ft_printf("%s ", s_args[i]);
	ft_printf("\n");
	kill(s_tracee, sig);
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
