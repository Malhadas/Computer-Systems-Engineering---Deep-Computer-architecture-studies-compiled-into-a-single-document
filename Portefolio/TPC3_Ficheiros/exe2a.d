#!/usr/sbin/dtrace -s
#pragma D option quiet

/**
 * Tracer de chamadas ao sistema openat() que conta o numero.
 * de tentativas e de sucessos.
 * int openat(int fildes, const char *path, int oflag, mode_t mode);
 **/

dtrace:::BEGIN {
    printf("#Tentativas e #sucessos.\n");
    printf("_________________________________________________________________________________________\n");
}

/*Catch openat system call entry*/
syscall::openat*:entry
/(arg2 & O_CREAT) == 0/ {
    /*Entry that tries to open an existing file*/
    @try_open[pid]   = count();
    printf("%s on PID: %d, open try.\n", execname, pid);
}
 
/*Catch openat system call entry*/
syscall::openat*:entry
/(arg2 & O_CREAT) == O_CREAT/ {
    /*Entry that tries to create a file*/
    @try_create[pid]   = count();
    printf("%s on PID: %d, create try.\n", execname, pid);
}

/*Catch openat system call return*/
syscall::openat*:return
/arg1 >= 0/ {
    /*Count successes*/
    @success[pid] = count();
    printf("%s on PID: %d, success.\n", execname, pid);
}

/*print results*/
dtrace:::END {
    /*Print*/
    printf("_________________________________________________________________________________________\n");
    printf("| %8s | %5s | %5s | %10s |\n", "PID", "Open", "Create", "Successes");
    printf("_________________________________________________________________________________________\n");
    printa("| %8d | %@5d | %@5d | %@10d |\n", @try_open, @try_create, @success);
    printf("________________________________________________________________________________________\n");

    /*Clear Counters*/
    clear(@try_open);
    clear(@try_create);
    clear(@success);
}

