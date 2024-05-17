#include <stdio.h>

#define NOT_USED(var) (void) var

int main(int argc, char* argv[]) {
    NOT_USED(argc);
    NOT_USED(argv);
    printf("Hello world!\n");
    return 0;
}
