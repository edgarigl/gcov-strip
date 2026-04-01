#include <stdio.h>
#include "c.h"

static void local_foo(void)
{
    puts(__func__);
}

void foo(void)
{
    local_foo();
    func_c(1);
    puts(__func__);
}
