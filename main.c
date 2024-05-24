#define _POSIX_C_SOURCE 199508L
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#define CAST_PTR(ptr, type) ((type*) ptr)
#define MAX_CHILDREN 10
#define FALSE 0
#define TRUE 1

typedef unsigned char bool;
typedef enum Status { READY = 1, FINISH } Status;
typedef enum PipeType { READER, WRITER } PipeType;

pid_t pids[MAX_CHILDREN] = {0};

void signal_handler(int signal);

/* ------------------------------------------------------------------------------------------------ */

static void mem_copy(void* dest, void* src, size_t size, size_t n) {
    for (size_t i = 0; i < (size * n); ++i) CAST_PTR(dest, unsigned char)[i] = CAST_PTR(src, unsigned char)[i];
    return;
}

static void mem_set(void* dest, unsigned char src, size_t size) {
    for (size_t i = 0; i < size; ++i) CAST_PTR(dest, unsigned char)[i] = src;
    return;
}

static int itoa(int num, char* str, char suffix) {
    if (num == 0) return (str[0] = '0', str[1] = suffix, 2);
    int temp = 1;
    unsigned int num_size = 0;

    for (num_size = 0; num >= temp; ++num_size) temp *= 10;

    str[num_size] = suffix;
    for (int i = num_size - 1; i >= 0; --i, num /= 10) str[i] = (num % 10) + 48;
    
    return (num_size + 1);
}

static void terminate_program(int pipefds[MAX_CHILDREN][2], int vis_pid_fd, int coord_pid_fd) {
    // Terminate all the visualizers
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

    return;
}

static int child_main(unsigned int* shm_ptr, int pipefds[2], int vis_pid_fd, unsigned int N) {
    // Set SIGUSR1 signal handler to catch the coordinator signal to terminate the program
    struct sigaction sa;
    mem_set(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);

    pid_t pid = getpid();
    bool status = READY;

    while (status) {
        bool iVal = FINISH;
        int res;
        
        // Wait to read the READY signal
        if ((res = read(pipefds[READER], &status, sizeof(status))) == -1) {
            perror("Failed reading");
            return -1;
        }

        if (status == READY) {
            printf("child_id '%d': %u\n", pid, (*CAST_PTR(shm_ptr, unsigned int))++);        
            // Store the pid of the visualizer
            char buffer[16] = {0};
            int len = itoa(pid, buffer, '\n');
            if ((res = write(vis_pid_fd, buffer, len)) == -1) {
                perror("Failed writing");
                return -1;
            }
        }
        
        // Set the pipe to FINISH, to prevent the next cycle to print multiple times while waiting to resume the program
        if ((res = write(pipefds[WRITER], &iVal, sizeof(iVal))) == -1) {
            perror("Failed writing");
            return -1;
        }

        // Check if the limit has been reached
        if (*CAST_PTR(shm_ptr, unsigned int) == (N + 1)) return 0;
        
        sleep(2); // Wait the coordinator to consume from the pipe before the visualizer itself
    }

    return 0;
}

void signal_handler(int signal) {
    if (signal == SIGTERM) {
        // Kill all the visualizers
        for (unsigned int i = 0; i < MAX_CHILDREN; ++i) {
            kill(pids[i], SIGUSR1);
            int status;
            waitpid(pids[i], &status, 0);
        }
    } else if (signal == SIGUSR2) {
        // Wait the signal to resume the execution
        sigset_t sigset;
        int sig_code;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGUSR2);
        sigprocmask(SIG_BLOCK, &sigset, NULL);
        sigwait(&sigset, &sig_code);
        return;
    }
    exit(0);
    return;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s N\n", argv[0]);
        return -1;
    }

    pid_t my_pid = getpid();
    printf("Coordinator pid: %d\n", my_pid);

    // Ignore SIGINT and set signal handler for SIGTERM and SIGUSR2
    struct sigaction sa;
    mem_set(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR2, &sa, NULL);
    
    unsigned int N = atoi(argv[1]);
    printf("Printing %u numbers...\n", N);

    shm_unlink("my_shm"); // Ensure that the shared memory doesn't exist (also ignore the result)

    // Create the shared memory
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

    // Map the shared memory into memory
    void* shm_ptr = mmap(NULL, sizeof(unsigned int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0L);
    if (shm_ptr == MAP_FAILED) {
        perror("Failed mapping the shared memory");
        return -1;
    }

    close(fd);

    // Open the files to store the pids
    int vis_pid_fd = open("./vis_pid.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if (vis_pid_fd == -1) {
        perror("Unable to open './vis_pid.txt'");
        return -1;
    }    
    
    int coord_pid_fd = open("./coord_pid.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if (coord_pid_fd == -1) {
        perror("Unable to open './coord_pid.txt'");
        return -1;
    }

    int pipefds[MAX_CHILDREN][2];

    // Create the visualizers
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

    unsigned int init_value = 1;
    mem_copy(shm_ptr, &init_value, sizeof(unsigned int), 1);

    for (unsigned int i = 0; i < N; ++i) {
        unsigned int child = rand() % MAX_CHILDREN;
        bool iVal = READY;
        bool res;
        int iRet;

        // Set the selected visualizer to ready state
        if ((iRet = write(pipefds[child][WRITER], &iVal, sizeof(iVal))) == -1) {
            perror("Error writing");
            terminate_program(pipefds, vis_pid_fd, coord_pid_fd);
            return -1;
        }

        sleep(1); // Wait the selected visualizer to consume from the pipe

        if ((iRet = read(pipefds[child][READER], &res, sizeof(res))) == -1) {
            perror("Error reading");
            terminate_program(pipefds, vis_pid_fd, coord_pid_fd);
            return -1;
        }

        if (res != FINISH) {
            printf("error while printing child %u: %u\n", pids[child], res);
            terminate_program(pipefds, vis_pid_fd, coord_pid_fd);
            return -1;
        }

        // Store the pid of the visualizer
        char buffer[16] = {0};
        int len = itoa(pids[child], buffer, '\n');
        if ((iRet = write(coord_pid_fd, buffer, len)) == -1) {
            perror("Error writing");
            terminate_program(pipefds, vis_pid_fd, coord_pid_fd);
            return -1;
        }
    }

    terminate_program(pipefds, vis_pid_fd, coord_pid_fd);

    return 0;
}
