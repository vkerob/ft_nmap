/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:05:57 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "limits.h"

int	ft_atoi(const char *ptr) {
	long	nbr = 0;
	int		sign = 1;

	while (ft_isspace(*ptr))
			ptr++;
	switch (*ptr) {
			case '-':
					sign *= -1;
					ptr++;
			default:
					break;
	}
	while (ft_isdigit(*ptr)) {
			nbr = nbr * 10 + (*ptr - '0');
			if (sign * nbr > INT_MAX)
					return -1;
			if (sign * nbr < INT_MIN)
					return 0;
			ptr++;
	}
	return sign * nbr;
}