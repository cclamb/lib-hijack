#!/bin/bash

# Setting the key and IV for the encryption step.
key="1234567890123456789012345678901234567890123456789012345678901234"
iv="12345678901234567890123456789012"

# Encrypting the library.
openssl enc -aes-256-cbc -p -nosalt -in libPrinter.dylib -out libPrinter.enc -K $key -iv $iv

# Extracting the packable representation.
xxd -i libPrinter.enc libPrinter.h