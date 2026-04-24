#include <stdio.h>

extern void foo(void);

int main(void)
{
    foo();
    puts("main");
    return 0;
}
