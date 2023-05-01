#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <gcrypt.h>

#define BUF_SIZE 1024
#define ITERATIONS 4096

// Declare the HMAC, key and salt length.
#define HMAC_SIZE 32
#define KEY_SIZE 32
#define SALT_SIZE 16
#define IV_SIZE 16

char *iv = "Kf5gM1tRj7Lp8q9H";
char *progname;


void print_usage() {
    printf("Usage: purenc <input file> [-d <output IP-addr:port>] [-l]\n");
}

void print_error(char* message) {
    printf("Error: %s\n", message);
}


void read_salt_iv(unsigned char* salt, unsigned char* iv, const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        print_error("Failed to open input file");
        exit(1);
    }
    if (fread(salt, 1, BUF_SIZE, fp) != BUF_SIZE) {
        print_error("Failed to read salt from input file");
        exit(1);
    }
    if (fread(iv, 1, IV_SIZE, fp) != IV_SIZE) {
        print_error("Failed to read iv from input file");
        exit(1);
    }
    fclose(fp);
}

int main(){
    
}
