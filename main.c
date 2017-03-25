#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syslimits.h>

#include "libPrinter.h"

typedef enum {
    OK, FAIL
} error_t;

static const char* LIBNAME  = "./libPrinter.dylib";
static const char* FUNAME   = "print";
static const char* FNAME    = "./libExtract.dylib";

static int _load_and_run(const char* name) {
    void* handle = dlopen(name, RTLD_LAZY);

    if (handle == NULL) {
        printf("Error opening library: %s\n", dlerror());
        return FAIL;
    }

    void (*printer)(void) = NULL;
    *(void **) (&printer) = dlsym(handle, FUNAME);

    if (printer == NULL) {
        printf("Error opening function: %s\n", dlerror());        
        return FAIL;
    }

    (*printer)();
    if (dlclose(handle)) {
        printf("Error closing library: %s\n", dlerror());
        return FAIL;
    }

    remove(name);

    return OK;
}

static int _load_file(void) {
    return _load_and_run(LIBNAME);
}

static int _load_write(void) {
    int new_lib = open(FNAME, O_CREAT | O_WRONLY);
    write(new_lib, libPrinter_dylib, sizeof(libPrinter_dylib));
    close(new_lib);
    return _load_and_run(FNAME);
}

int main(void) {
    return _load_write();
}