#!/usr/sbin/dtrace -s
#pragma D option quiet


dtrace:::BEGIN {
    printf("#Chamadas de sistema.\n");
    printf("__________________________________________");
    printf("_______________________________________________\n");
    self->started = 0;
}

/*Catch system call entry*/
syscall:::entry
/execname == $$1/ {
    @times_called[probefunc] = count();
    self->started = timestamp;
}

/*Catch system call return*/
syscall:::return
/*Ignore also syscalls where entry was not traced*/
/execname == $$1 && self->started!=0/ {
    @syscall_time_elapsed[probefunc] = sum((timestamp - self->started));
    self->started = 0;
}

/*print results*/
dtrace:::END {
    /*Print*/
    printf("Program: %s\n", $$1);
    printf("_________________________________________________________________________________________\n");
    printf("| %15s | %15s | %s\n", "Sys Call", "times Called", "Time spent");
    printf("_________________________________________________________________________________________\n");
    printa("| %15s | %@15d | %@d ns\n", @times_called, @syscall_time_elapsed);
    printf("_________________________________________________________________________________________\n");

    /*Clear Counters*/
    clear(@times_called);
    clear(@syscall_time_elapsed);
}


