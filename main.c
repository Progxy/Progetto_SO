#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define NOT_USED(var) (void) var
#define CAST_PTR(ptr, type) ((type*) ptr)
#define MAX_CHILDREN 10
#define READER 0
#define WRITER 1
#define FALSE 0
#define TRUE 1

typedef unsigned char bool;

static void mem_copy(void* dest, void* src, size_t size, size_t n) {
    for (size_t i = 0; i < (size * n); ++i) CAST_PTR(dest, unsigned char)[i] = CAST_PTR(src, unsigned char)[i];
    return;
}

static int child_main(unsigned int child_id, unsigned int* shm_ptr, int pipefds[2]) {
    bool status = TRUE;
    while (status) {
        int res;
        if ((res = read(pipefds[READER], &status, sizeof(status))) == -1) {
            perror("Error reading");
            return -1;
        }
        if (status) printf("child_id '%u': %u\n", child_id, (*CAST_PTR(shm_ptr, unsigned int))++);
        bool iVal = 1;
        if ((res = write(pipefds[WRITER], &iVal, sizeof(iVal))) == -1) {
            perror("Failed writing");
            return -1;
        }
        sleep(2); // Wait the thread manager to consume from the pipe before the thread itself
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s N\n", argv[0]);
        return -1;
    }

    shm_unlink("my_shm"); // Ensure that the shared memory doesn't exist

    int fd = shm_open("my_shm", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("Error creating the shared memory");
        return -1;
    }

    // extend shared memory object as by default it's initialized with size 0
	int res = ftruncate(fd, sizeof(unsigned int));
	if (res == -1) {
		perror("Error truncating the shared memory");
		return -1;
	}

    void* shm_ptr = mmap(NULL, sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0L);
    if (shm_ptr == MAP_FAILED) {
        perror("Failed mapping the shared memory");
        return -1;
    }

    close(fd);

    pid_t* pids = (pid_t*) calloc(MAX_CHILDREN, sizeof(pid_t));
    int pipefds[MAX_CHILDREN][2];

    for (unsigned int child_count = 0; child_count < MAX_CHILDREN; ++child_count) {
        if (pipe(pipefds[child_count])) {
            perror("Failed creating the pipe");
            return -1;
        }
        pid_t pid = fork();
        if (pid == 0) {
            return child_main(child_count, shm_ptr, pipefds[child_count]);
        } else if (pid == -1) {
            perror("Failed creating the child");
            return -1;
        } else {
            pids[child_count] = pid;
        }
    }

    unsigned int N = atoi(argv[1]);
    printf("Printing %u numbers...\n", N);
    unsigned int empty = 0;
    mem_copy(shm_ptr, &empty, sizeof(unsigned int), 1);

    for (unsigned int i = 0; i < N; ++i) {
        unsigned int child = rand() % MAX_CHILDREN;
        printf("Child '%u' will print\n", child);
        bool res;
        int iRet;
        bool iVal = 1;

        if ((iRet = write(pipefds[child][WRITER], &iVal, sizeof(iVal))) == -1) {
            perror("Error writing");
            return -1;
        }

        sleep(1); // Wait the thread selected to consume from the pipe
        
        if ((iRet = read(pipefds[child][READER], &res, sizeof(res))) == -1) {
            perror("Error reading");
            return -1;
        }
    }

    int unlink_res = shm_unlink("my_shm");
    if (unlink_res == -1) perror("Failed unlinking the shared memory");

    return 0;
}
