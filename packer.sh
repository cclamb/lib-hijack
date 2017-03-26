#!/bin/bash

# Setting the key and IV for the encryption step.
key="123456789a123456789a123456789a12"
iv="123456789a123456"

# Encrypting the library.
openssl enc -aes-256-cbc -p -nosalt -in libPrinter.dylib -out libPrinter.enc -K $key -iv $iv

# Extracting the packable representation.
xxd -i libPrinter.enc libPrinter.h