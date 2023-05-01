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
#define DEFAULT_PORT 8888

// Declare the HMAC, key and salt length.
#define HMAC_SIZE 32
#define KEY_SIZE 32
#define SALT_SIZE 16
#define IV_SIZE 16

char *iv = "Kf5gM1tRj7Lp8q9H";
char *progname;


void print_usage() {
    printf("Usage: purdec [-p listening-port>] [-l <input file>]\n");
}

void print_error(char* message) {
    printf("Error: %s\n", message);
}

// Function to compute HMAC of a message using a key
void compute_hmac(unsigned char* message, size_t message_len, unsigned char* key, unsigned char* hmac) {
    gcry_md_hd_t md;
    gcry_md_open(&md, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(md, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
    gcry_md_write(md, message, message_len);
    memcpy(hmac, gcry_md_read(md, GCRY_MD_SHA256), gcry_md_get_algo_dlen(GCRY_MD_SHA256));
    gcry_md_close(md);
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

int main(int argc, char* argv[]) {
    // Check command line arguments
    bool is_local = false;
    char* input_filename;
    int port = -1;
    // Parse command line arguments
    if (argc < 3 || argc > 4) {
        print_usage();
        return 1;
    }

    int c;
    while ((c = getopt(argc, argv, "l:p:")) != -1) {
        switch (c) {
            case 'l':
                is_local = true;
                input_filename = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    print_error("Invalid port number\n");
                    return 1;
                }
                break;
            default:
                print_usage();
                //port = atoi(DEFAULT_PORT);
                return 1;
        }
    }
    //printf("Port no is: %d", port);

    // Create the socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Socket creation failed");
    }

    // Bind the socket to the specified port
    struct sockaddr_in serv_addr, cli_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Binding failed");
    }

    // Listen for incoming connections
     // Listen for incoming connections
    if (listen(sockfd, 5) < 0) {
        print_error("listen() failed");
        return 1;
    }
    printf("Listening on port %d...\n", port);
    printf("Waiting for incoming connections...\n");

    while (1) {
        // Accept incoming connection
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
        if (newsockfd < 0) {
            print_error("Accepting connection failed");
        }
        printf("Accepted connection from %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

        // Receive the file contents
        unsigned char buffer[BUF_SIZE];
        memset(buffer, 0, BUF_SIZE);
        ssize_t n = read(newsockfd, buffer, BUF_SIZE);
        if (n < 0) {
            print_error("Reading from socket failed");
        }

        // Parse the salt and IV from the first two lines
        unsigned char* salt = malloc(16);
        memcpy(salt, buffer, 16);
        unsigned char* iv = malloc(16);
        memcpy(iv, buffer + 16, 16);
        size_t salt_len = 16;
        size_t iv_len = 16;
        salt_len = strlen((const char*)salt);
        iv_len = strlen((const char*)iv);
        printf("Salt is = %s and the IV is = %s\n", salt, iv);

        //
        FILE* in_fp = NULL;
        if(salt_len == 16 && iv_len == 16){
            in_fp = fmemopen(buffer + 32, n - 32, "r");
        }else {
            in_fp = fopen(input_filename, "rb");
            if (!in_fp) {
                print_error("Failed to open input file");
            }
        }

        // Prompt user for password
        char password[BUF_SIZE];
        printf("Enter password: ");
        fgets(password, BUF_SIZE, stdin);
        password[strcspn(password, "\n")] = 0;

        // Generate key from password, salt, and IV
        gcry_cipher_hd_t cipher;
        unsigned char* key = malloc(gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
        size_t key_len = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
        gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
        gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA256, salt, salt_len, 10000, key_len, key);

        // Read the rest of the file contents
        // Initialize the decryption cipher
        gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
        gcry_cipher_setkey(cipher, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
        gcry_cipher_setiv(cipher, iv, 16);

        // Determine the size of the file
        fseek(in_fp, 0, SEEK_END);
        long int total_size = ftell(in_fp);

        // Get the salt and iv from the file 
        fseek(in_fp, 16 + salt_len + iv_len, SEEK_SET);
        unsigned char* file_contents = malloc(total_size - 16 - salt_len - iv_len - 32);
        fread(file_contents, total_size -16 - salt_len - iv_len - 32, 1, in_fp);
        gcry_cipher_decrypt(cipher, file_contents, total_size -16 - salt_len - iv_len - 32, NULL, 0);

        fclose(in_fp);
        // memcpy(file_contents, buffer, n);

        // while (n > 0) {
        //     n = read(newsockfd, buffer, BUF_SIZE);
        //     if (n < 0) {
        //         print_error("Reading from socket failed");
        //     }
        //     total_size += n;
        //     file_contents = realloc(file_contents, total_size);
        //     memcpy(file_contents + total_size - n, buffer, n);
        // }

        // Verify HMAC tag
        fseek(in_fp, -32, SEEK_END);
        unsigned char* hmac = malloc(32);
        fread(hmac, 32, 1, in_fp);

        unsigned char* tag = malloc(HMAC_SIZE);
        gcry_md_hd_t digest;
        gcry_md_open(&digest, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
        gcry_md_setkey(digest, key, key_len);
        gcry_md_write(digest, file_contents, total_size - 16 - salt_len - iv_len - 32);
        //gcry_md_write(digest, file_contents, total_size - HMAC_SIZE);
        memcpy(tag, gcry_md_read(digest, GCRY_MD_SHA256), HMAC_SIZE);

        if (memcmp(hmac, tag, HMAC_SIZE) != 0) {
            print_error("HMAC tag verification failed. File has been tampered with.");
        } else {
            printf("HMAC tag verification successful.\n");
        }
        // Decrypt the file contents
        // gcry_cipher_setkey(cipher, key, key_len);
        // gcry_cipher_setiv(cipher, iv, iv_len);
        // gcry_cipher_decrypt(cipher, file_contents + salt_len + iv_len + 16, total_size - salt_len - iv_len - 16 - HMAC_SIZE, NULL, 0);


        unsigned char* output_filename = malloc(strlen(input_filename) + 5);
        strcpy(output_filename, input_filename);
        strcat(output_filename, ".pur");
        FILE* out_fp = fopen(output_filename, "wb");
        if (!out_fp) {
            print_error("Failed to open output file");
        }
        fwrite(file_contents, total_size - 16 - salt_len - iv_len - 32, 1, out_fp);
        fclose(out_fp);

        printf("Decryption successful. File saved as %s.\n", output_filename);
        // Write the decrypted contents to the output file
        // FILE* out_fp = fopen(filename, "wb");
        // if (!out_fp) {
        //     print_error("Failed to open output file");
        // }
        // fwrite(file_contents + salt_len + iv_len + 16, total_size - salt_len - iv_len - 16 - HMAC_SIZE, 1, out_fp);
        // fclose(out_fp);

        // printf("Decryption successful. File saved as %s.\n", filename);
        // }
        free(file_contents);
        close(newsockfd);
    }
    close(sockfd);
    return 0;
}
