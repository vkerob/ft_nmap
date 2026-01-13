/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: dguillau <dguillau@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/09/26 15:08:15 by dguillau          #+#    #+#             */
/*   Updated: 2025/02/27 10:45:34 by dguillau         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
#define LIBFT_H

#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/*                                                                            */
/* ************************************************************************** */
/*                                PROTOTYPES                                  */
/* ************************************************************************** */
/*                                                                            */

size_t	ft_strlen(const char* s);

void*		ft_memset(void* s, int c, size_t n);

int			ft_atoi(const char* ptr);

int			ft_isdigit(const char c);

int			ft_isspace(const int c);

#endif
