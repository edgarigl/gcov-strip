#include <stdio.h>
#include <stdint.h>

volatile int x;

void func(int a, int b, int c)
{
    if (a > 10 && (b || c)) {
        x = 10;
    }
}

int main(int argc, char *argv[]) {
    func(10, 20, 0);
	return 0;
}
