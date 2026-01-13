/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi_test.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:04:13 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "greatest.h"
#include "libft.h"

#include <limits.h>

SUITE(atoi_suite);

TEST test_ft_atoi(const char *str, const int expected) {
    const int result = ft_atoi(str);
    ASSERT_EQ_FMT(expected, result, "%d");
    PASS();
}

SUITE(atoi_suite) {
    RUN_TESTp(test_ft_atoi, "0", 0);
    RUN_TESTp(test_ft_atoi, "123", 123);
    RUN_TESTp(test_ft_atoi, "-123", -123);
    RUN_TESTp(test_ft_atoi, "42", 42);
    RUN_TESTp(test_ft_atoi, "000123", 123);
    RUN_TESTp(test_ft_atoi, "  456", 456);
    RUN_TESTp(test_ft_atoi, "789abc", 789);
    RUN_TESTp(test_ft_atoi, "   987654321", 987654321);
    RUN_TESTp(test_ft_atoi, "2147483647", INT_MAX); // INT_MAX case
    RUN_TESTp(test_ft_atoi, "-2147483648", INT_MIN); // INT_MIN case
    RUN_TESTp(test_ft_atoi, "2147483648", -1); // Overflow case
    RUN_TESTp(test_ft_atoi, "-2147483649", 0); // Underflow case
}
