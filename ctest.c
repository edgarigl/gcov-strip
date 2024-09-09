#include <stdio.h>
#include <stdint.h>

volatile int x;

void func(int a, int b, int c)
{
    if (a > 10 && (b || c)) {
        printf("SET\n");
        x = 10;
    }
}

int main(int argc, char *argv[]) {
    func(11, 20, 0);
    printf("done\n");
	return 0;
}
