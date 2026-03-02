#include <stdio.h>

static void local_bar(void)
{
    puts(__func__);
}

void bar(void)
{
    local_bar();
    puts(__func__);
}
