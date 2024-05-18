#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
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

pid_t pids[MAX_CHILDREN] = {0};

static void mem_copy(void* dest, void* src, size_t size, size_t n) {
    for (size_t i = 0; i < (size * n); ++i) CAST_PTR(dest, unsigned char)[i] = CAST_PTR(src, unsigned char)[i];
    return;
}

static void mem_set(void* dest, unsigned char src, size_t size) {
    for (size_t i = 0; i < size; ++i) CAST_PTR(dest, unsigned char)[i] = src;
    return;
}

void signal_handler(int signal) {
    if (signal == SIGTERM) {
        for (unsigned int i = 0; i < MAX_CHILDREN; ++i) {
            kill(pids[i], SIGUSR1);
            int status;
            waitpid(pids[i], &status, 0);
        }
    }
    exit(0);
    return;
}

static int child_main(unsigned int* shm_ptr, int pipefds[2], int vis_pid_fd, unsigned int N) {\
    // Ignore SIGINT
    struct sigaction sa;
    mem_set(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);

    bool status = TRUE;
    pid_t pid = getpid();
    while (status) {
        int res;
        if ((res = read(pipefds[READER], &status, sizeof(status))) == -1) {
            perror("Failed reading");
            return -1;
        }

        if (status) printf("child_id '%d': %u\n", pid, (*CAST_PTR(shm_ptr, unsigned int))++);
        
        // Store the name of the buffer
        char buffer[50];
        int len = snprintf(buffer, 50, "%d\n", pid);
        if ((res = write(vis_pid_fd, buffer, len)) == -1) {
            perror("Failed writing");
            return -1;
        }

        bool iVal = 1;
        if ((res = write(pipefds[WRITER], &iVal, sizeof(iVal))) == -1) {
            perror("Failed writing");
            return -1;
        }

        if (*CAST_PTR(shm_ptr, unsigned int) == (N + 1)) {
            return 0;
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

    // Ignore SIGINT and set signal handler for SIGTERM
    struct sigaction sa;
    mem_set(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    
    unsigned int N = atoi(argv[1]);
    printf("Printing %u numbers...\n", N);

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

    int vis_pid_fd = open("./out/vis_pid.txt", O_CREAT | O_RDWR);
    if (vis_pid_fd == -1) {
        perror("Unable to open './vis_pid.txt'");
        return -1;
    }    
    
    int coord_pid_fd = open("./out/coord_pid.txt", O_CREAT | O_RDWR);
    if (coord_pid_fd == -1) {
        perror("Unable to open './coord_pid.txt'");
        return -1;
    }

    int pipefds[MAX_CHILDREN][2];

    for (unsigned int child_count = 0; child_count < MAX_CHILDREN; ++child_count) {
        if (pipe(pipefds[child_count])) {
            perror("Failed creating the pipe");
            return -1;
        }
        pid_t pid = fork();
        if (pid == 0) {
            return child_main(shm_ptr, pipefds[child_count], vis_pid_fd, N);
        } else if (pid == -1) {
            perror("Failed creating the child");
            return -1;
        } else {
            pids[child_count] = pid;
        }
    }

    unsigned int empty = 1;
    mem_copy(shm_ptr, &empty, sizeof(unsigned int), 1);

    for (unsigned int i = 0; i < N; ++i) {
        unsigned int child = rand() % MAX_CHILDREN;
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

        // Store the number of the child
        char buffer[50];
        int len = snprintf(buffer, 50, "%u\n", pids[child]);
        if ((iRet = write(coord_pid_fd, buffer, len)) == -1) {
            perror("Error writing");
            return -1;
        }
    }

    // Join all the visualizers
    for (unsigned int i = 0; i < MAX_CHILDREN; ++i) {
        kill(pids[i], SIGUSR1);
        int status;
        waitpid(pids[i], &status, 0);
        close(pipefds[i][READER]);
        close(pipefds[i][WRITER]);
    }

    close(vis_pid_fd);
    close(coord_pid_fd);

    int unlink_res = shm_unlink("my_shm");
    if (unlink_res == -1) perror("Failed unlinking the shared memory");

    return 0;
}
