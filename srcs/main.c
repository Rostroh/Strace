#include "ft_strace.h"

void		exit_error(char *name, char *msg) {
	printf("Error: %s %s\n", name, msg);
	exit(0);
}

void		print_reg(struct user_regs_struct regs) {
  printf("r15 = 0x%lx\n", regs.r15);
  printf("r14 = 0x%lx\n", regs.r14);
  printf("r13 = 0x%lx\n", regs.r13);
  printf("r12 = 0x%lx\n", regs.r12);
  printf("rbp = 0x%lx\n", regs.rbp);
  printf("rbx = 0x%lx\n", regs.rbx);
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
  printf("rip = 0x%lx\n", regs.rip);
  printf("cs = 0x%lx\n", regs.cs);
  printf("eflags = 0x%lx\n", regs.eflags);
  printf("rsp = 0x%lx\n", regs.rsp);
  printf("ss = 0x%lx\n", regs.ss);
  printf("fs_base = 0x%lx\n", regs.fs_base);
  printf("gs_base = 0x%lx\n", regs.gs_base);
  printf("es = 0x%lx\n", regs.es);
  printf("fs = 0x%lx\n", regs.fs);
  printf("gs = 0x%lx\n", regs.gs);
}

void	*read_process_memory(pid_t pid, unsigned long addr, int size) {
    struct iovec local[1];
    struct iovec remote[1];
	if (!addr)
		return (NULL);
	//(void)size;
    char buffer[256];  // Adjust the buffer size as needed
	
	void *ret_addr;

	ret_addr = (void *)malloc(sizeof(char) * size);
    // Set up the local buffer
    local[0].iov_base = ret_addr;//buffer;
    local[0].iov_len = size;//sizeof(buffer);

    // Set up the remote buffer
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = size;//sizeof(buffer);

    // Read the string from the target process's memory using process_vm_readv
    ssize_t bytesRead = process_vm_readv(pid, local, 1, remote, 1, 0);

    if (bytesRead < 0) {
        perror("process_vm_readv");
        exit(EXIT_FAILURE);
    }

    // Null-terminate the string
    //buffer[bytesRead] = '\0';
	char	*buf = ret_addr;
	//printf("byte_read = %d\n", bytesRead);
	buf[bytesRead] = '\0';

    // Print the string
    //printf("String from target process: -%s-\n", (char *)ret_addr);

    return (ret_addr);
}

void		print_tamales(pid_t pid, unsigned long reg, int type) {
	void	*ptr;
	switch (type) {
		case UNKNOWN:
			break;
		case INT://1
			print_int((int)reg);
			break;
		case UINT://2
			print_uint((unsigned int)reg);
			break;
		case SIZE_T://3
			print_sizet((size_t)reg);
			break;
/*		case INT_PTR://4
			print_intptr((int *)reg);
			break;
		case CONST_INT_PTR://5
			print_constintptr((const int *)reg);
			break;
		case UNSIGNED_INT_PTR://6
			print_uintptr((unsigned int *)reg);
			break;
		case SIZE_T_PTR://7
			print_sizetptr((size_t *)reg);
			break;*/
		case LONG://8
			print_long((long)reg);
			break;
		case UNSIGNED_LONG://9
			print_ulong((unsigned long)reg);
			break;
/*		case UNSIGNED_LONG_PTR://10
			printf("AMIMIR\n");
			break;
		case CONST_UNSIGNED_LONG_PTR://11
			print_constulong((const unsigned long)reg);
			break;*/
		case U32://12
			print_u32((uint32_t)reg);
			break;
/*		case U32_PTR://13
			print_u32ptr((uint32_t *)reg);
			break;*/
		case U64://14
			print_u64((uint64_t)reg);
			break;
/*		case U64_PTR://15
			print_u64ptr((uint64_t *)reg);
			break;
		case VOID_PTR://16
			print_voidptr((void *)reg);
			break;
		case VOID_PTR_PTR://17
			print_voidvoidptr((void **)reg);
			break;
		case CONST_VOID_PTR://18
			print_constvoidptr((const void *)reg);
			break;
		case CONST_VOID_PTR_PTR://19
			print_constvoidvoidptr((const void **)reg);
			break;*/
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
	/*	case CONST_CHAR_PTR_PTR://23
			char *str = (char*)read_process_memory(pid_t pid, reg, 256);
			print_charptrptr((const char **)reg);
			break;*/
		default:
			ft_printf("%p", reg);
	}
}

void		print64(pid_t tracee, struct user_regs_struct regs) {
	ft_printf("%s(", sysinfo_64[regs.orig_rax].sysname);
/*	if (ft_strcmp("getrandom", sysinfo_64[regs.orig_rax].sysname) != 0) {
		printf("not a write\n");
		return ;
	}*/
	if (sysinfo_64[regs.orig_rax].p1 != 0) {
	//	printf("p1 = %lx\n", regs.rdi);
		print_tamales(tracee, regs.rdi, sysinfo_64[regs.orig_rax].p1);
	}
	if (sysinfo_64[regs.orig_rax].p2 != 0) {
		ft_printf(", ");
//		printf("p2 = %lx\n", regs.rsi);
		print_tamales(tracee, regs.rsi, sysinfo_64[regs.orig_rax].p2);
	}
	if (sysinfo_64[regs.orig_rax].p3 != 0) {
		ft_printf(", ");
//		printf("p3 = %lx\n", regs.rdx);
		print_tamales(tracee, regs.rdx, sysinfo_64[regs.orig_rax].p3);
	}
	if (sysinfo_64[regs.orig_rax].p4 != 0) {
		ft_printf(", ");
//		printf("p4 = %lx\n", regs.r10);
		print_tamales(tracee, regs.r10, sysinfo_64[regs.orig_rax].p4);
	}
	if (sysinfo_64[regs.orig_rax].p5 != 0) {
		ft_printf(", ");
//		printf("p5 = %lx\n", regs.r9);
		print_tamales(tracee, regs.r9, sysinfo_64[regs.orig_rax].p5);
	}
	if (sysinfo_64[regs.orig_rax].p6 != 0) {
		ft_printf(", ");
//		printf("p6 = %lx\n", regs.r8);
		print_tamales(tracee, regs.r8, sysinfo_64[regs.orig_rax].p6);
	}
	ft_printf(")\t\t = ");
	if (sysinfo_64[regs.orig_rax].ret == 1)
		ft_printf("%p\n", regs.rax);
	else
		ft_printf("%d\n", regs.rax);
/*	if (sysinfo_64[reg.orig_rax].p2 != 0)
	if (sysinfo_64[reg.orig_rax].p3 != 0)
	if (sysinfo_64[reg.orig_rax].p4 != 0)
	if (sysinfo_64[reg.orig_rax].p5 != 0)
	if (sysinfo_64[reg.orig_rax].p6 != 0)*/
}

void		print_data(pid_t tracee, struct user_regs_struct regs) {
	if (SYS64 == 1)
		print64(tracee, regs);
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

int			main(int argc, char **argv, char **env) {
	pid_t		tracee;
	int			status;
	int			ret = 0;
	struct user_regs_struct	reg;
	int			i = 0;
	sigset_t	empty;
	sigset_t	blocked;

	if (argc == 1)
		exit_error(argv[0], "needs argument");
	if ((tracee = fork()) == -1)
		exit_error(argv[0], "fork failed");
	if (tracee == 0) { 
		printf("Hello from child -- Running straces with \n%s\n", argv[1]);
		for (int i = 1; i < argc; i++)
			printf("args = %s\n", *(argv + i));
		raise(SIGSTOP);
		execve(argv[1], argv + 1, env);
		printf("end execve\n");
	}
	else {
		printf("Hello from parent %s\n");
		ft_bzero(&reg, sizeof(struct user_regs_struct));
		if (ptrace(PTRACE_SEIZE, tracee, 0, 0) == -1)
			exit_error(argv[0], "ptrace error on PTRACE_SEIZE");
		sigemptyset(&empty);
		init_blocked(&blocked);
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
				printf("Child exited\n");
				break ;
			}
			//if (i < 5) {
				struct iovec io;
				struct user_regs_struct regs;
				io.iov_base = &regs;
				io.iov_len = sizeof(regs);
				ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &io);
				print_data(tracee, regs);
			if (WIFEXITED(status)) {
				printf("Child exited\n");
				break ;
			}
//				print_reg(regs);
			//}
			i++;
			if ((ret = ptrace(PTRACE_SYSCALL, tracee, 0, 0)) == -1)
			{
				printf("Probleme with %s\n", strerror(errno));
				exit_error(argv[0], "ptrace error on PTRACE_SYSCALL");
			}
			sigprocmask(SIG_SETMASK, &empty, NULL);
			waitpid(tracee, &status, 0);
			sigprocmask(SIG_BLOCK, &blocked, NULL);
			if (WIFEXITED(status)) {
				printf("Child exited\n");
				break ;
			}
			/*printf("second reg read :\n");
			ptrace(PTRACE_GETREGSET, tracee, NT_PRSTATUS, &reg);
			print_reg(reg);*/
		}
		wait(NULL);
		printf("A little cozy over here\n");
	}
	return (0);
}
