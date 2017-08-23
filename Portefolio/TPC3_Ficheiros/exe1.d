#!/usr/sbin/dtrace -s
#pragma D option quiet

/**
 * Tracer de chamadas ao sistema openat().
 * int openat(int fildes, const char *path, int oflag, mode_t mode);
 **/

dtrace:::BEGIN {
    printf("Tracer de chamadas ao sistema openat().\n");
    printf("_________________________________________________________________________________________\n");
    printf("| %s, %s, %s, %s, %s, %s, %s\n", "Executable", "Path", "Flags", "PID", "UID", "GID", "Return");
    printf("_________________________________________________________________________________________\n");
}

/*Catch openat system call entry*/
syscall::openat*:entry {
    /*Print executable name and absolute path*/ 
    printf("| %s, %s", execname, copyinstr(arg1)); 

    printf("%s", arg2 & O_RDONLY ? ", O_RDONLY" : (arg2 & O_WRONLY ? ", O_WRONLY" : ", O_RDWR") );
    printf("%s%s", arg2 & O_APPEND ? "|O_APPEND" : "", arg2 & O_CREAT  ? "|O_CREAT"  : "");
}

/*Catch apenat systema call return*/
syscall::openat*:return {
    /*Print pid, uid, gid and return value*/
    printf(", %d, %d, %d, %d\n", pid, uid, gid, arg1);
    printf("________________________________________________________________________________________\n");
}


