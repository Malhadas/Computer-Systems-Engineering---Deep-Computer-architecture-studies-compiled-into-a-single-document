#!/usr/sbin/dtrace -s
#pragma D option quiet


dtrace:::BEGIN {
    printf("Identificacao de Hot Spots.\n");
    printf("_________________________________________________________________________________________\n");
}

pid$target:$1::entry
/self->start[probefunc] == 0/{

    self->start[probefunc] = timestamp;
    self->vstart[probefunc] = vtimestamp;

    @function_count[ufunc(uregs[R_PC])] = count();
}

pid$target:$1::return
/self->start[probefunc]/{

    this->wall_elapsed = timestamp - self->start[probefunc];
    self->start[probefunc] = 0;
    this->cpu_elapsed = vtimestamp - self->vstart[probefunc];
    self->vstart[probefunc] = 0;

    @function_walltime[ufunc(uregs[R_PC])] = sum(this->wall_elapsed);
    @function_cputime[ufunc(uregs[R_PC])] = sum(this->cpu_elapsed);
}           

dtrace:::END{       
    normalize(@function_walltime, 1000000);
    normalize(@function_cputime, 1000000);

    printf("| %30s | %10s    | %10s    | %s\n", "Function", "Wall Time", "CPU Time","Times Called");
    printa("| %30A | %@10d ms | %@10d ms | %@d\n", @function_walltime, @function_cputime, @function_count);
}



