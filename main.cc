#include <iostream>
#include <string.h>

#include "ImAES.h"

int main(int argc, char *argv[]){

    uc *key, *input, *iv;
    int key_len, input_len, iv_len;

    key_len = hex_decode( "thisisasecret00", &key );
    iv_len = hex_decode( "thisistheiv", &iv );
    input_len = hex_decode( argv[2], &input );
     

    if(!strcmp(argv[1], "-e")){
        show_hex(ImAES::encrypt<16>(input, input_len, iv, key),input_len + MAC_LENGTH);
    }else if(!strcmp(argv[1], "-d")){
        show_hex(ImAES::decrypt<16>(input, input_len, iv, key), input_len - MAC_LENGTH);
    }

    return 0;
}