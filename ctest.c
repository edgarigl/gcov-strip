#include <stdio.h>

extern void foo(void);
extern void bar(void);

static void local_bar(void)
{
    puts("local_bar");
}

int main(void)
{
    if (1)
        foo();
    else {
        local_bar();
        bar();
    }

    return 0;
}
