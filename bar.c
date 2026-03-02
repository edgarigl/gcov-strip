#include <stdio.h>

static inline void local_inline_bar(void)
{
    puts(__func__);
}

static void local_bar(void)
{
    puts(__func__);
}

void bar(void)
{
    local_bar();
    local_inline_bar();
    puts(__func__);
}
