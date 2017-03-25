#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "libPrinter.h"

typedef enum {
    OK, FAIL
} error_t;

static const char* LIBNAME  = "./libPrinter.dylib";
static const char* FUNAME   = "print";

static int load_file(void) {
    void* handle = dlopen(LIBNAME, RTLD_LAZY);

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
    
    return OK;
}

static int load_mem(void) {
    static const char* FNAME    = "/tmp/libExtract.dylib";

    FILE* new_lib = fopen(FNAME, "w");
    for(unsigned int i = 0; i < sizeof(libPrinter_dylib); i++) {
        fprintf(new_lib, "%c", libPrinter_dylib[i]);
    }
    fclose(new_lib);

    void* handle = dlopen(FNAME, RTLD_LAZY);

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

    remove(FNAME);

    return OK;
}

int main(void) {
    return load_mem();
}