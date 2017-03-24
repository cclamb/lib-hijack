#include <stdio.h>

void do_other_stuff(void) {
    printf("do lots of other stuff.\n");
}

void print(void) {
    do_other_stuff();
    printf("do some stuff.\n");
}