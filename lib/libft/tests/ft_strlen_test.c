/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlen_test.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: damien <damien@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/12/06 16:05:21 by damien            #+#    #+#             */
/*   Updated: 2024/12/27 16:43:00 by damien           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "greatest.h"
#include "libft.h"

SUITE(strlen_suite);

TEST test_ft_strlen(const char *input, const size_t expected) {
    const size_t result = ft_strlen(input);
    ASSERT_EQ(result, expected);
    PASS();
}

SUITE(strlen_suite) {
    RUN_TESTp(test_ft_strlen, "", 0);
    RUN_TESTp(test_ft_strlen, "a", 1);
    RUN_TESTp(test_ft_strlen, "hello", 5);
    RUN_TESTp(test_ft_strlen, "42", 2);
    RUN_TESTp(test_ft_strlen, "This is a longer string.", 24);
    RUN_TESTp(test_ft_strlen, "Another\0string", 7);
    RUN_TESTp(test_ft_strlen, "1234567890", 10);
    RUN_TESTp(test_ft_strlen, "A string with spaces", 20);
    RUN_TESTp(test_ft_strlen, "Special chars !@#$%^&*()", 24);
}
