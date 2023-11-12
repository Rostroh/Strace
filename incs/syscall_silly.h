#ifndef SILLY_H
# define SILLY_H

# include "ft_strace.h"

typedef struct	t_syscall_info {
	char		*sysname;
	int			p1;
	int			p2;
	int			p3;
	int			p4;
	int			p5;
	int			p6;
}				s_syscall_info;

static s_syscall_info test[] = {
	{"uwu_name", 0, 0, 0, 0, 0, 0},
	{"name2", 1, 1, 1, 0, 0, 0}
};
#endif
