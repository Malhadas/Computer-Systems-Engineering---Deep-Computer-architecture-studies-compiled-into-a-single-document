#!/usr/sbin/dtrace -s
#pragma D option quiet

/**
 * Tracer de chamadas ao sistema openat().
 * int openat(int fildes, const char *path, int oflag, mode_t mode);
 **/

dtrace:::BEGIN {
    printf("Tracer de chamadas ao sistema openat().\n");
    printf("_________________________________________");
    printf("________________________________________________\n");
    printf("| %s, %s, %s, %s, %s, %s, %s\n", 
           "Executable", "Path", "Flags", "PID", "UID", "GID", "Return");
    printf("_________________________________________");
    printf("________________________________________________\n");
}

/*Catch openat system call entry*/
syscall::openat*:entry {

    self->print_ret = (strstr(copyinstr(arg1), "/etc") != NULL) ? 1 : 0;
    self->path = copyinstr(arg1);
    self->flag = arg2;
}

/*Catch openat system call return*/
syscall::openat*:return
/self->print_ret == 1/ {

    /*Print executable name and absolute path*/ 
    printf("| %s, %s", execname, self->path); 

    printf("%s", self->flag & O_RDONLY ? ", O_RDONLY" : (self->flag & O_WRONLY ? ", O_WRONLY" : ", O_RDWR") );
    printf("%s%s", self->flag & O_APPEND ? "|O_APPEND" : "", self->flag & O_CREAT  ? "|O_CREAT"  : "");

    /*Print pid, uid, gid and return value*/
    printf(", %d, %d, %d, %d\n", pid, uid, gid, arg1);
    printf("_________________________________________");
    printf("________________________________________________\n");
}


