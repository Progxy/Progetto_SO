#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s N\n", argv[0]);
        return -1;
    }

    unsigned int N = atoi(argv[1]);
    printf("Printing %u numbers...\n", N);

    unsigned int child_count = 0;
    pid_t* pids = (pid_t*) calloc(10, sizeof(pid_t));

    while (child_count < 10) {
        pid_t pid = fork();
        if (pid == 0) {
            printf("I am child: %u\n", child_count);
            return 0;
        } else if (pid == -1) {
            printf("Error: failed creating the child!\n");
            return -1;
        } else {
            pids[child_count++] = pid;
        }
    }

    printf("I am the master, and those are the pids i own: \n");
    for (unsigned int i = 0; i < child_count; ++i) {
        printf("Child %u: %u\n", i, pids[i]);
    }
    return 0;
}
