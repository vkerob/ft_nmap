/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isspace_test.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:04:45 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "greatest.h"
#include "libft.h"

SUITE(isspace_suite);

TEST test_ft_isspace(const int input, const int expected) {
    const int result = ft_isspace(input);
    ASSERT_EQ(result, expected);
    PASS();
}

SUITE(isspace_suite) {
    RUN_TESTp(test_ft_isspace, ' ', 1);
    RUN_TESTp(test_ft_isspace, '\t', 1);
    RUN_TESTp(test_ft_isspace, '\n', 1);
    RUN_TESTp(test_ft_isspace, '\v', 1);
    RUN_TESTp(test_ft_isspace, '\f', 1);
    RUN_TESTp(test_ft_isspace, '\r', 1);
    RUN_TESTp(test_ft_isspace, 'a', 0);
    RUN_TESTp(test_ft_isspace, '1', 0);
    RUN_TESTp(test_ft_isspace, '!', 0);
    RUN_TESTp(test_ft_isspace, 0, 0);
}
