#include "ft_strace.h"

void		print_buffer(pid_t pid, unsigned long addr, int size, bool byte)
{
	char		*ptr;

	fprintf(stderr, "\"");
	if ((ptr = (char*)read_process_memory(pid, addr, size)))
	{
		for (int i = 0; i < size; i++)
		{
			if (byte)
				fprintf(stderr, "\\x%x", ptr[i]);
			else
			{
				if (ft_isprint(ptr[i]))
					fprintf(stderr, "%c", ptr[i]);
				else if (ptr[i] == '\n')
					fprintf(stderr, "\\n");
				else
					fprintf(stderr, "\\%d", ptr[i]);
				if (i == 28)
				{
					fprintf(stderr, "\"...");
					return ;
				}
			}
		}
	}
	ft_printf("\"");
}

void		finish_read(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rsi, regs.rdx, false);
	fprintf(stderr, ", %d", regs.rdx);
}

void		print_read(struct user_regs_struct regs)
{
	fprintf(stderr, "%d, ", regs.rdi);
}

void		finish_pread64(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rsi, regs.rdx, false);
	fprintf(stderr, ", %d, %d", regs.rdx, regs.r10);
}

void		print_pread64(struct user_regs_struct regs)
{
	fprintf(stderr, "%d, ", regs.rdi);
}

void		finish_getrandom(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rdi, regs.rsi, true);
	fprintf(stderr, ", %d, %d", regs.rsi, regs.rdx);
}

void		print_getrandom(void)
{
	;
}

void		finish_wait4(struct user_regs_struct regs)
{
	print_voidptr((void*)regs.rsi);
	fprintf(stderr, ", %d, ", regs.rdx);
	print_voidptr((void*)regs.r10);
}

void		print_wait4(struct user_regs_struct regs)
{
	fprintf(stderr, "%d, ", regs.rdi);
}

void		print_write(pid_t pid, struct user_regs_struct regs)
{
	fprintf(stderr, "%d, ", regs.rdi);
	print_buffer(pid, regs.rsi, regs.rdx, false);
	fprintf(stderr, ", %d", regs.rdx);
}
