#!/usr/sbin/dtrace -s
#pragma D option quiet

/**
 * Tracer de chamadas ao sistema openat() que conta o numero.
 * de tentativas e de sucessos.
 * int openat(int fildes, const char *path, int oflag, mode_t mode);
 **/

dtrace:::BEGIN {
    printf("#Tentativas e #sucessos.\n");
    printf("____________________________________________");
    printf("_____________________________________________\n");
}

/*Catch openat system call entry*/
syscall::openat*:entry
/(arg2 & O_CREAT) == 0/ {
    /*Entry that tries to open an existing file*/
    @try_open[execname, pid]        = count();
    @try_open_global[execname, pid] = count();
}
 
/*Catch openat system call entry*/
syscall::openat*:entry
/(arg2 & O_CREAT) == O_CREAT/ {
    /*Entry that tries to create a file*/
    @try_create[execname, pid]        = count();
    @try_create_global[execname, pid] = count();
}

/*Catch openat system call return*/
syscall::openat*:return
/arg1 >= 0/ {
    /*Count successes*/
    @success[execname, pid]        = count();
    @success_global[execname, pid] = count();
}

tick-$1s {
    /*Print*/
    printf("____________________________________________");
    printf("_____________________________________________\n");
    printf("| %20s | %8s | %5s | %7s | %10s |\n", 
           "Executable", "PID", "Open", "Create", "Successes");
    printf("____________________________________________");
    printf("_____________________________________________\n");
    printa("| %20s | %8d | %@5d | %@7d | %@10d |\n", 
              @try_open, @try_create, @success);
    printf("| TIME: %Y\n", walltimestamp);
    printf("____________________________________________");
    printf("_____________________________________________\n");

    /*Discard last measurements*/
    trunc(@try_create);
    trunc(@try_open);
    trunc(@success);
}

/*print results*/
dtrace:::END {
    /*Print*/
    printf("____________________________________________");
    printf("_____________________________________________\n");
    printf("| %20s | %8s | %5s | %7s | %10s |\n", 
           "Executable", "PID", "Open", "Create", "Successes");
    printf("____________________________________________");
    printf("_____________________________________________\n");
    printa("| %20s | %8d | %@5d | %@7d | %@10d |\n", 
           @try_open_global, @try_create_global, @success_global);
    printf("____________________________________________");
    printf("_____________________________________________\n");

    /*Clear Counters*/
    clear(@try_open);
    clear(@try_create);
    clear(@success);
    clear(@try_open_global);
    clear(@try_create_global);
    clear(@success_global);
}


