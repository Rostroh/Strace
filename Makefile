NAME = ./ft_strace

SRC = main.c print_func.c spec_print.c

OBJ = $(SRC:.c=.o)

SRC_DIR = ./srcs
OBJ_DIR = ./objs
INC_DIR = ./incs

INC = ft_strace.h #syscallx64.h syscallx86.h

OBJS = $(OBJ:%=$(OBJ_DIR)/%)

HEAD = $(INC_DIR)/$(INC)

LIBFT = libft.a
LIB_DIR = ./libft
LFT = $(LIB_DIR)/$(LIBFT)
LIB = -L $(LIB_DIR) -l$(LIBFT:lib%.a=%)

FLG = -Wno-format #-Wall -Werror -Wextra

CC = gcc

all:
	@make -C $(LIB_DIR)
	@make $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	gcc $(FLG) -I $(INC_DIR) -o $@ -c -fPIC $<

$(OBJS): $(HEAD)


$(NAME): $(OBJS)
	clang $(OBJS) -o $@ $(LIB)

clean:
	@rm -rf $(OBJ_DIR)
	@make $@ -C $(LIB_DIR)

fclean: clean
	@rm -rf $(NAME)
	@make $@ -C $(LIB_DIR)

re: fclean all

