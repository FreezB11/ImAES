## ImAES
### a simple aes(advanced encrytion system) implementation in c++

This is a simple implementation of aes from scratch in c++, the code is inspired and taken from the book [Implementing-SSL-TLS-Using-Cryptography](https://www.amazon.com/Implementing-SSL-TLS-Using-Cryptography-ebook/dp/B004IK9TVO)

The reference is taken from [fips-197](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf)

ImAES also has a implementation for the 
#### aes_ctr_encrypt(), 
#### aes_ccm_encrypt(), 
#### aes_gcm_encrypt()


```c++
    #include "ImAES.h"

    uc *key;
    int key_len;

    // use the hex_decode to convert the key into hex values.
    // you can use it for the iv and input.

    key_len = hex_decode("<your key of 128|256 bit>", &key);

    //  use case
    //  here the 16 represents the 128 bit key type,
    //  ImAES supports 256 bit key also
    uc * cpyher = ImAES::encrypt<16>(input, input_len, iv, key)
    // the above will give a unsinged char* (uc*)
    show_hex(cypher,input_len + MAC_LENGTH);
```

