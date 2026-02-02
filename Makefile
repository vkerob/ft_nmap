NAME        := ft_nmap

SRC_DIR     := src
OBJ_DIR     := obj
INCLUDE_DIR := includes

SRCS        := $(wildcard $(SRC_DIR)/*.c)
OBJS        := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CPPFLAGS    := -I $(INCLUDE_DIR)

# Release (gcc)
CC          := gcc
CFLAGS      := -Wall -Wextra -Werror --std=c11

# Clang
CLANG       := clang

# ASan + UBSan (mémoire + UB)
ASANFLAGS   := -Wall -Wextra -Werror -std=c11 -g \
               -fsanitize=address,undefined \
               -fno-omit-frame-pointer

# TSan (threads / data races)
TSANFLAGS   := -Wall -Wextra -Werror -std=c11 -g \
               -fsanitize=thread \
               -fno-omit-frame-pointer

LDFLAGS     := -lpcap -lpthread 

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJS) -o $(NAME) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Build with clang + ASan/UBSan
asan: fclean
	$(MAKE) CC=$(CLANG) CFLAGS="$(ASANFLAGS)" all

# Build with clang + TSan
tsan: fclean
	$(MAKE) CC=$(CLANG) CFLAGS="$(TSANFLAGS)" all

clean:
	rm -f $(OBJS)

fclean: clean
	rm -rf $(OBJ_DIR)
	rm -f $(NAME)

re: fclean all

.PHONY: all asan tsan clean fclean re
