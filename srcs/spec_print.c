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

void		print_read(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
	print_buffer(pid, regs.rsi, regs.rdx, false);
	ft_printf(", %d", regs.rdx);
}

void		print_pread64(pid_t pid, struct user_regs_struct regs)
{
	ft_printf("%d, ", regs.rdi);
	print_buffer(pid, regs.rsi, regs.rdx, false);
	ft_printf(", %d, %d", regs.rdx, regs.r10);
}

void		print_getrandom(pid_t pid, struct user_regs_struct regs)
{
	print_buffer(pid, regs.rdi, regs.rsi, true);
	ft_printf(", %d, %d", regs.rsi, regs.rdx);
}
