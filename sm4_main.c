#include <getopt.h>
#include "sm4_utility.h"
char *const short_options = "rpkch:";
char *l_opt_arg = NULL; 
struct option long_options[] = {  
     { "run_mode",            1,   NULL,    'r'     },
     { "plain_file_path",     1,   NULL,    'p'     },
     { "key_file_path",       1,   NULL,    'k'     },      
     { "ctext_file_path",     1,   NULL,    'c'     },
     { "help",                0,   NULL,    'h'     },  
     {      0,                0,      0,     0      },  
};
void usage() {
    printf("sm4 encrypt:./sm4_utility --run_mode encypt_file_with_key --plain_file_path ./1.txt --key_file_path ./2.txt --ctext_file_path ./3.txt\n");
    printf("sm4 decrypt:./sm4_utility --run_mode decypt_file_with_key --ctext_file_path ./3.txt --key_file_path ./2.txt --plain_file_path ./4.txt\n");
}
int main(int argc, char **argv) {
    int c = 0;
    char run_mode[64] = { 0 };
    char plain_file_path[128] = { 0 };
    char ctext_file_path[128] = { 0 };
    char key_file_path[128] = { 0 };
    if (argc < 3) {     // 至少有run_mode参数
        usage();
        return -1;
    }
    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {  
        switch (c) {
        case 'r':
            l_opt_arg = optarg;
            snprintf(run_mode, sizeof(run_mode), "%s", l_opt_arg);
            break;  
        case 'p':
            l_opt_arg = optarg;
            snprintf(plain_file_path, sizeof(plain_file_path), "%s", l_opt_arg);
            break;
        case 'c':
            l_opt_arg = optarg;  
            snprintf(ctext_file_path, sizeof(ctext_file_path), "%s", l_opt_arg);
            break;
        case 'k':
            l_opt_arg = optarg;  
            snprintf(key_file_path, sizeof(key_file_path), "%s", l_opt_arg);
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            return -1;
            break;
        }
    }
    if (0 == strcmp(run_mode, "encypt_file_with_key")) {
        printf("encypt_file_with_key result:%d\n", sm4_encrypt_ecb(plain_file_path, key_file_path, ctext_file_path));
    }
    else if (0 == strcmp(run_mode, "decypt_file_with_key")) {
        printf("decypt_file_with_key result:%d\n", sm4_decrypt_ecb(ctext_file_path, key_file_path, plain_file_path));
    }

    return 0;
}
