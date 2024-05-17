#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define NOT_USED(var) (void) var

int child_main(unsigned int* shm_ptr) {
    NOT_USED(shm_ptr);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s N\n", argv[0]);
        return -1;
    }

    unsigned int N = atoi(argv[1]);
    printf("Printing %u numbers...\n", N);

    const unsigned int max_children = 10;
    pid_t* pids = (pid_t*) calloc(max_children, sizeof(pid_t));

    shm_unlink("next_number_shm");
    int fd = shm_open("next_number_shm", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("error creating the shared memory!\n");
        return -1;
    }

    unsigned int* shm_ptr = mmap(NULL, sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm_ptr == MAP_FAILED) {
        printf("Failed mapping the shared memory!\n");
        return -1;
    }

    close(fd);

    for (unsigned int child_count = 0; child_count < max_children; ++child_count) {
        pid_t pid = fork();
        if (pid == 0) {
            printf("I am child: %u\n", child_count);
            return child_main(shm_ptr);
        } else if (pid == -1) {
            printf("Error: failed creating the child!\n");
            return -1;
        } else {
            pids[child_count] = pid;
        }
    }

    printf("I am the master, and those are the pids i own: \n");
    for (unsigned int i = 0; i < max_children; ++i) {
        printf("Child %u: %u\n", i, pids[i]);
    }

    shm_unlink("next_number_shm");

    return 0;
}
