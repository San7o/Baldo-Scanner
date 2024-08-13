#include "daemon/sandbox.hpp"
#include "daemon/daemon.hpp"
#include "common/logger.hpp"

#include <iostream>
#include <thread>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>  /* For setgroups */
#include <sys/mman.h>
#include <signal.h>
#include <sched.h>
#include <err.h>
#include <fstream>
#include <seccomp.h>

using namespace AV;

Sandbox::app_data Sandbox::parse_data(char* data)
{
    Sandbox::app_data data_struct;
    std::string name = strtok(data, ",");
    if (name == "") return data_struct;
    data_struct.program_name = name; 
    char* arg = strtok(NULL, ",");
    while (arg != NULL)
    {
        data_struct.arguments.push_back(arg);
        arg = strtok(NULL, ",");
    }
    return data_struct;
}

void Sandbox::run_threaded_sandbox(char* sandbox_data)
{
    Sandbox::app_data data = parse_data(sandbox_data);

    pthread_t thread;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
    {
        perror("pthread_attr_init");
    }

    /* No need to allocate data on the heap, as the thread will be joined */
    if (pthread_create(&thread, &attr, thread_run_sandbox, (void*) &data) != 0)
    {
        perror("pthread_create");
        exit(1);
    }

    Daemon::threads_mutex.lock();
    Daemon::threads.push_back(thread);
    Daemon::threads_mutex.unlock();

    if (pthread_join(thread, NULL) != 0)
    {
        perror("pthread_join");
        exit(1);
    }
}

void *Sandbox::thread_run_sandbox(void* sandbox_data)
{
    /* Disable handlers */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) != 0)
    {
        perror("pthread_sigmask");
        exit(1);
    }

    /* Allocate stack for the new thread */
    char *stack;         /* Start of stack buffer */
    char *stackTop;      /* End of stack buffer */
    stack = (char*) mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED)
    {
       err(EXIT_FAILURE, "mmap");
    }
    stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

    /* fork and exec the application in a sandbox */
    pid_t pid = clone(sandboxed_process, /* Child function */
                      stackTop,          /* End of stack */
                      SIGCHLD |          /* Signal to send to parent on child termination */
                      CLONE_NEWPID |     /* Create new PID namespace */
                      CLONE_NEWNET |     /* Create new network namespace */
                      CLONE_NEWNS,      /* Create new mount namespace */
                   // CLONE_NEWUSER,     /* Create new user namespace (does not work) */
                      sandbox_data);     /* Argument to child function */
    if (pid == -1)
    {
        perror("fork");
        exit(1);
    }

    Logger::Log(Enums::LogLevel::INFO, "Sandboxed application pid: " + std::to_string(pid));
    if (waitpid(pid, NULL, 0) == -1)
    {
        perror("waitpid");
        exit(1);
    }
    Logger::Log(Enums::LogLevel::INFO, "Sandboxed application finished");

    return NULL;
}

/**
 * @brief Run the application in a sandbox
 *
 * @param arg The data from the sandbox
 *
 * The cloned process drops all It's privilages
 * and filters allowd system calls through
 * seccomp.
 */
int Sandbox::sandboxed_process(void* arg)
{
    Sandbox::app_data data = *(Sandbox::app_data*) arg;

    /* Change user and group from sudo */
    uid_t uid = 1000;
    gid_t gid = 100;
    if (setgid(gid) == -1)
    {
        perror("setgid");
        exit(1);
    }
    gid_t groups[] = {gid};
    if (setgroups(1, groups) < 0) {
        std::cerr << "Failed to set supplementary groups!" << std::endl;
        exit(1);
    }
    if (setuid(uid) == -1)
    {
        perror("setuid");
        exit(1);
    }

    if (unshare(CLONE_NEWUSER) == -1)
    {
        perror("unshare");
        exit(1);
    }

    /* Filter system calls */
    int ret;
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
    {
        perror("seccomp_init");
        exit(1);
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0) < 0)
    {
        perror("seccomp_rule_add");
        exit(1);
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0) < 0)
    {
        perror("seccomp_rule_add");
        exit(1);
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0) < 0)
    {
        perror("seccomp_rule_add");
        exit(1);
    }

    ret = seccomp_load(ctx);
    if (ret < 0)
    {
        perror("seccomp_load");
        exit(1);
    }

    /* Set env variables */
    std::vector<char*> args;
    args.push_back((char*) data.program_name.c_str());
    for (auto arg : data.arguments)
    {
        args.push_back((char*) arg.c_str());
    }
    args.push_back(NULL);
    char* env[] = {
        (char*) "HOME=/home/lanto/",
        NULL
    };

    if (execvpe(data.program_name.c_str(), args.data(), env) == -1)
    {
        perror("execvp");
        exit(1);
    }

    /* This should never be reached */
    return 0;
}

void Sandbox::print_data(struct Sandbox::app_data data)
{
    Logger::Log(Enums::LogLevel::INFO, "Program name: " + data.program_name);
    Logger::Log(Enums::LogLevel::INFO, "Arguments: ");
    for (auto arg : data.arguments)
    {
        Logger::Log(Enums::LogLevel::INFO, arg);
    }
}
