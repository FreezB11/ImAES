#include <iostream>
#include <string.h>

#include "ImAES.h"

int main(int argc, char *argv[]){
    

    if(!strcmp(argv[1], "-e")){
        std::cout << "oka\n";
    }else if(!strcmp(argv[1], "-d")){
        std::cout << "umm yea\n";
    }

    return 0;
}