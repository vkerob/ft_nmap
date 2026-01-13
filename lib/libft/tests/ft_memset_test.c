/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset_test.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:05:00 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "greatest.h"
#include "libft.h"

SUITE(memset_suite);

TEST test_ft_memset(void *s, const int c, const size_t n, void const *expected) {
    void const *result = ft_memset(s, c, n);
    ASSERT_MEM_EQ(expected, result, n);
    PASS();
}

SUITE(memset_suite) {
    char buffer1[10] = "abcdefghi";
    char buffer2[10] = "abcdefghi";
    char buffer3[10] = "abcdefghi";
    char buffer4[10] = "abcdefghi";
    const char expected1[10] = "xxxxefghi";
    const char expected2[10] = "aaaaefghi";
    const char expected3[10] = "abcdefghi";
    const char expected4[10] = "abcdefghi";

    RUN_TESTp(test_ft_memset, buffer1, 'x', 4, expected1);
    RUN_TESTp(test_ft_memset, buffer2, 'a', 4, expected2);
    RUN_TESTp(test_ft_memset, buffer3, 'b', 0, expected3);
    RUN_TESTp(test_ft_memset, buffer4, 'c', 10, expected4);
}
