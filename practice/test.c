#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 16

int main(int argc, char* argv[]){
    FILE *fp;
    char buf[BUF_SIZE];

    if (argc != 2){
        printf("usage: ./test [input]\n");
        exit(1);
    }

    fp = fopen(argv[1], "r");

    if (fp == NULL){
        printf("file error\n");
        exit(1);
    }

    int result = fread(buf, 1, BUF_SIZE, fp);

    printf("data: ");

    for (int i = 0; i <= result; i++){
        printf("%c", buf[i]);
    }

    char *bug = NULL;

    if(buf[0] == 'A')
        if(buf[1] == 'B')
            if(buf[2] == 'C')
                if(buf[3] == 'D')
                    *bug = '\0';

    fclose(fp);

    return 0;
}
