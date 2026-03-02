#include <stdio.h>

static void local_foo(void)
{
    puts(__func__);
}

void foo(void)
{
    local_foo();
    puts(__func__);
}
