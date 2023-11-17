#include "ft_strace.h"
/*
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
}*/

void		finish_read_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ecx, regs.edx, false);
	ft_printf(", %d", regs.edx);
}

void		print_read_32(pid_t pid, t_user_regs32 regs)
{
	ft_printf("%d, ", regs.ebx);
}

void		finish_pread64_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ecx, regs.edx, false);
	ft_printf(", %d, %d", regs.edx, regs.esi);
}

void		print_pread64_32(pid_t pid, t_user_regs32 regs)
{
	ft_printf("%d, ", regs.ebx);
}

void		finish_getrandom_32(pid_t pid, t_user_regs32 regs)
{
	print_buffer(pid, regs.ebx, regs.ecx, true);
	ft_printf(", %d, %d", regs.ecx, regs.edx);
}

void		print_getrandom_32(pid_t pid, t_user_regs32 regs)
{
	;
}

void		finish_wait4_32(pid_t pid, t_user_regs32 regs)
{
	print_voidptr((void*)regs.ecx);
	ft_printf(", %d, ", regs.edx);
	print_voidptr((void*)regs.esi);
}

void		print_wait4_32(pid_t pid, t_user_regs32 regs)
{
	ft_printf("%d, ", regs.ebx);
}

void		print_write_32(pid_t pid, t_user_regs32 regs)
{
	ft_printf("%d, ", regs.ebx);
	print_buffer(pid, regs.ecx, regs.edx, false);
	ft_printf(", %d", regs.edx);
}
