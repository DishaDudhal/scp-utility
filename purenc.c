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
//#include <gcrypt.h>

#define BUF_SIZE 1024
#define ITERATIONS 4096

// Declare the HMAC, key and salt length.
#define HMAC_SIZE 32
#define KEY_SIZE 32
#define SALT_SIZE 16

char *progname;

void print_usage() {
    printf("Usage: purenc <input file> [-d <output IP-addr:port>] [-l]\n");
}

void print_error(char* message) {
    printf("Error: %s\n", message);
}

int main(int argc, char *argv[]) {
    progname = argv[0];
        if (argc < 2 || argc > 4) {
        print_usage();
        return 1;
    }

    bool is_local = false;
    bool is_network = false;
    char* input_file = argv[1];
    char* output_file = NULL;
    char* output_addr = NULL;
    char* output_port = NULL;

    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            is_local = true;
        } else if (strcmp(argv[i], "-d") == 0 && i+1 < argc) {
            is_network = true;
            char* output = argv[++i];
            char* colon = strchr(output, ':');
            if (colon == NULL) {
                print_error("Invalid output address format");
                return 1;
            }
            *colon = '\0';
            output_addr = output;
            output_port = colon + 1;
        } else {
            print_usage();
            return 1;
        }
    }

    // Check if the input file exists
    FILE* file = fopen(input_file, "r");
    if (file == NULL) {
        print_error("Input file not found");
        return 1;
    }
    fclose(file);

    // Check if the output file already exists
    if (!is_network) {
        output_file = malloc(strlen(input_file) + 5);
        strcpy(output_file, input_file);
        strcat(output_file, ".pur");
        if (access(output_file, F_OK) == 0) {
            print_error("Output file already exists");
            free(output_file);
            return 1;
        }
    }

    // Prompt user for password
    char* password = malloc(BUF_SIZE);
    printf("Enter password: ");
    fgets(password, BUF_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';
}