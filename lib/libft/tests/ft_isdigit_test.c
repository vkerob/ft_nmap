/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isdigit_test.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:04:42 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "greatest.h"
#include "libft.h"

SUITE(isdigit_suite);

TEST test_ft_isdigit(const char c, const int expected) {
    const int result = ft_isdigit(c);
    ASSERT_EQ_FMT(expected, result, "%d");
    PASS();
}

SUITE(isdigit_suite) {
    RUN_TESTp(test_ft_isdigit, '0', 1);
    RUN_TESTp(test_ft_isdigit, '1', 1);
    RUN_TESTp(test_ft_isdigit, '2', 1);
    RUN_TESTp(test_ft_isdigit, '3', 1);
    RUN_TESTp(test_ft_isdigit, '4', 1);
    RUN_TESTp(test_ft_isdigit, '5', 1);
    RUN_TESTp(test_ft_isdigit, '6', 1);
    RUN_TESTp(test_ft_isdigit, '7', 1);
    RUN_TESTp(test_ft_isdigit, '8', 1);
    RUN_TESTp(test_ft_isdigit, '9', 1);
    RUN_TESTp(test_ft_isdigit, 'a', 0);
    RUN_TESTp(test_ft_isdigit, 'z', 0);
    RUN_TESTp(test_ft_isdigit, 'A', 0);
    RUN_TESTp(test_ft_isdigit, 'Z', 0);
    RUN_TESTp(test_ft_isdigit, '@', 0);
    RUN_TESTp(test_ft_isdigit, '[', 0);
    RUN_TESTp(test_ft_isdigit, '`', 0);
    RUN_TESTp(test_ft_isdigit, '{', 0);
}
