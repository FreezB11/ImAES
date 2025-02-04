#include <iostream>
#include <string.h>

#include "ImAES.h"

int main(int argc, char *argv[]){

    uc *key, *input, *iv;
    int key_len, input_len, iv_len;

    key_len = hex_decode( argv[ 2 ], &key );
    iv_len = hex_decode( argv[ 3 ], &iv );
    input_len = hex_decode( argv[ 4 ], &input );
     

    if(!strcmp(argv[1], "-e")){
        // std::cout << ImAES::encrypt<16>(input, input_len, iv, key) << std::endl;; 
        show_hex(ImAES::encrypt<16>(input, input_len, iv, key),input_len + MAC_LENGTH);
    }else if(!strcmp(argv[1], "-d")){
        show_hex(ImAES::decrypt<16>(input, input_len, iv, key), input_len - MAC_LENGTH);
    }

    return 0;
}