/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:07:55 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 15:18:15 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memset(void *s, const int c, const size_t n) {
	char	*p = NULL;

	p = (char *) s;
	if (n > ft_strlen(p))
			return s;
	for (size_t i = 0; i < n; i++)
			p[i] = c;
	return s;
}
