#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/syslimits.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "libPrinter.h"
#include "libPrinterPT.h"
#include "packer.h"



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

static void _handle_error(const char* msg) {
  perror(msg);
  exit(FAIL);
}

static void _handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(FAIL);
}

static int _decrypt(
    unsigned char *ciphertext, 
    int ciphertext_len, 
    const unsigned char *key,
    const unsigned char *iv, 
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) { 
        _handleErrors(); 
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        _handleErrors();
    }
    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        _handleErrors();
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        _handleErrors();
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static int _unpack_library(
    unsigned char* ciphertext, 
    unsigned int ct_length,
    unsigned char* buffer) {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);

    printf("%u\n", ct_length);
    _decrypt(ciphertext, ct_length, KEY, IV, buffer);

    /* Clean up */
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return OK;
}

static int _load_packed(void) {
    unsigned char lib_shellcode[10000];

    _unpack_library(libPrinter_enc, sizeof(libPrinter_enc), lib_shellcode);

    int new_lib = open(FNAME, O_CREAT | O_RDWR);
    if (new_lib == -1) {
      _handle_error("Error opening library file");
    }

    if (write(new_lib, lib_shellcode, sizeof(lib_shellcode)) == -1) {
      _handle_error("Error writing library file");
    }

    if (close(new_lib) == -1) {
      _handle_error("Error closing library file");
    }

    if (chmod(FNAME, S_IRWXU) == -1) {
      _handle_error("Error changing library perms");
    }

    return _load_and_run(FNAME);
}

int main(void) {
    return _load_packed();
}
