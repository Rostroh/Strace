#include "ft_strace.h"

void		print_buffer(pid_t pid, unsigned long addr, int size, bool byte)
{
	unsigned char 	*ptr;

	ft_printf("\"");
	if (ptr = (char*)read_process_memory(pid, addr, size))
	{
		for (int i = 0; i < size; i++)
		{
			if (byte)
				ft_printf("\\x%x", ptr[i]);
			else
			{
				if (ft_isprint(ptr[i]))
					ft_printf("%c", ptr[i]);
				else if (ptr[i] == '\n')
					ft_printf("\\n");
				else
					ft_printf("\\%d", ptr[i]);
				if (i == 28)
				{
					ft_printf("\"...");
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
	ft_printf(", %d", regs.rdx);
}

void		print_read(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
//	print_buffer(pid, regs.rsi, regs.rdx, false);
//	ft_printf(", %d", regs.rdx);
}

void		finish_pread64(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rsi, regs.rdx, false);
	ft_printf(", %d, %d", regs.rdx, regs.r10);
}

void		print_pread64(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
//	print_buffer(pid, regs.rsi, regs.rdx, false);
//	ft_printf(", %d, %d", regs.rdx, regs.r10);
}

void		finish_getrandom(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rdi, regs.rsi, true);
	ft_printf(", %d, %d", regs.rsi, regs.rdx);
}

void		print_getrandom(pid_t pid, struct user_regs_struct regs)
{
	;
}

void		finish_wait4(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("owo ???");
	print_voidptr((void*)regs.rsi);
	ft_printf(", %d, ", regs.rdx);
	print_voidptr((void*)regs.r10);
}

void		print_wait4(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
}

void		print_write(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
	print_buffer(pid, regs.rsi, regs.rdx, false);
	ft_printf(", %d", regs.rdx);
}
