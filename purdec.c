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

//GLOBAL VARIABLES
char *iv = "Kf5gM1tRj7Lp8q9H";
char *salt = "w7eU4b4x3qX9sL8N";
char *progname;
size_t salt_len = SALT_SIZE;
size_t iv_len = IV_SIZE;


void print_usage() {
    printf("Usage: purdec [-p listening-port>] [-l <input file>]\n");
}

void print_error(char* message) {
    printf("Error: %s\n", message);
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
                is_local = false;
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

    if(is_local){
        char password[BUF_SIZE];
            printf("Enter password: ");
            fgets(password, BUF_SIZE, stdin);
            password[strcspn(password, "\n")] = 0;

            // Receive the file contents

            FILE* rp = fopen(input_filename, "rb");
            if (!rp) {
                perror("Error opening file");
                return;
            }

            FILE* fp = fopen("temporary", "wb");
            if (!fp) {
                perror("Error opening file");
                return;
            }

            char in_buffer[BUF_SIZE];
            ssize_t bytes_read;
            while ((bytes_read = fread(in_buffer, 1, BUF_SIZE, rp)) > 0) {
                fwrite(in_buffer, sizeof(char), bytes_read, fp);
            }
            fclose(fp);
            fclose(rp);

            // Generate key and salt from password using PBKDF2
            gcry_error_t err;
            gcry_cipher_hd_t cipher;
            //printf("Cipher initialized done");
            unsigned char* key = malloc(gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
            err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
                GCRY_MD_SHA256, salt, salt_len, 10000, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256), key);
            // Initialize encryption/decryption
            err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
            err = gcry_cipher_setkey(cipher, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
            err = gcry_cipher_setiv(cipher, iv, IV_SIZE);
                //printf("Cipher encryption done");

            // Extract the HMAC
            fp = fopen("temporary", "rb");
            if (!fp) {
                print_error("Failed to open file for verification");
            }

            // Get file size
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            rewind(fp);
            printf("\nSize of file is %ld", size);

            // Read the file contents and HMAC
            unsigned char* file_contents = malloc(size - HMAC_SIZE);
            unsigned char* hmac = malloc(HMAC_SIZE);
            fread(file_contents, size - HMAC_SIZE, 1, fp);
            fread(hmac, HMAC_SIZE, 1, fp);
            //printf("Allocated hmac %s", hmac);

            /// Compute HMAC of the file contents
            gcry_md_hd_t md;
            gcry_md_open(&md, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
            gcry_md_setkey(md, key, KEY_SIZE);
            gcry_md_write(md, file_contents, size - HMAC_SIZE);
            unsigned char* computed_hmac = gcry_md_read(md, GCRY_MD_SHA256);
            //printf("Computed hmac %s", computed_hmac);

            bool hmac_valid = (memcmp(hmac, computed_hmac, HMAC_SIZE) == 0);
            if(hmac_valid){
                printf("\nHMAC Verification successfull");

                unsigned char* decrypted_data = malloc(size - HMAC_SIZE);
                gcry_cipher_decrypt(cipher, decrypted_data, size - HMAC_SIZE, file_contents, size - HMAC_SIZE);
                printf("\nData Decryption done");

                unsigned char* output_filename = malloc(strlen(input_filename));
                strcpy(output_filename, input_filename);
                
                char newstr[BUF_SIZE]; // make sure to allocate enough space for the new string
                // copy all but last 4 characters to the new string
                strncpy(newstr, input_filename, strlen(input_filename) - 4);
                newstr[strlen(input_filename) - 4] = '\0';

                printf("Output filename is :%s", newstr);

                FILE* out_fp = fopen(output_filename, "wb");
                if (!out_fp) {
                    print_error("Failed to open output file");
                }
                fwrite(decrypted_data, size - HMAC_SIZE, 1, out_fp);
                //fwrite(file_contents, total_size - 16 - salt_len - iv_len - 32, 1, out_fp);
                fclose(out_fp);

                printf("\nDecryption successful. File saved as %s\n", output_filename);
                free(decrypted_data);
                return 0;
            }else{
                print_error("Your file has been tampered!!!");
                return 1;
            }
            
        
    } else {
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

            //Get the incoming filename;
            char input_filename[BUF_SIZE] = {0};
            ssize_t n = recv(newsockfd, input_filename, BUF_SIZE, 0);
            if (n < 0) {
                print_error("Failed to receive filename");
                exit(EXIT_FAILURE);
            }
            printf("Received filename: %s\n", input_filename);

            //Change the filename to store encrypted data locally and add a .pur extension.
            char* temp = malloc(strlen(input_filename) + 5);
            strcpy(temp, input_filename);
            strcat(temp, ".pur");
            //printf("%s",temp);

  
            char password[BUF_SIZE];
            printf("Enter password: ");
            fgets(password, BUF_SIZE, stdin);
            password[strcspn(password, "\n")] = 0;

            // Receive the file contents
            FILE* fp = fopen("temporary", "wb");
            if (!fp) {
                perror("Error opening file");
                continue;
            }

            char in_buffer[BUF_SIZE];
            ssize_t bytes_read;
            while ((bytes_read = read(newsockfd, in_buffer, BUF_SIZE)) > 0) {
                fwrite(in_buffer, sizeof(char), bytes_read, fp);
            }
            fclose(fp);

            //Read the data from the file and store it in a buffer callled encrypted buffer
            fp = fopen("temporary", "rb"); // Open file in binary mode
                if (!fp) {
                    perror("Failed to open file");
                    return 1;
                }

                // Initialize buffer
                unsigned char* recv_buffer = NULL;
                size_t encrypted_buffer_len = 0;

                while (!feof(fp)) {
                    // Read data from file in chunks of BUF_SIZE
                    unsigned char buf[BUF_SIZE];
                    size_t bytes_read = fread(buf, 1, BUF_SIZE, fp);
                    if (bytes_read == 0) {
                        break; // End of file
                    }

                    // Resize buffer to fit new data
                    recv_buffer = realloc(recv_buffer, encrypted_buffer_len + bytes_read);
                    if (!recv_buffer) {
                        perror("Failed to allocate memory for encrypted_buffer");
                        return 1;
                    }

                    // Copy new data to end of buffer
                    memcpy(recv_buffer + encrypted_buffer_len, buf, bytes_read);

                    // Update buffer length
                    encrypted_buffer_len += bytes_read;
                }

                // Close file
                fclose(fp);

                // Print buffer length
                printf("\nLength of encrypted_buffer: %zu\n", encrypted_buffer_len);

            // Generate key and salt from password using PBKDF2
                gcry_error_t err;
                gcry_cipher_hd_t cipher;
                //printf("Cipher initialized done");
                unsigned char* key = malloc(gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
                err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
                    GCRY_MD_SHA256, salt, salt_len, 10000, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256), key);
                // Initialize encryption/decryption
                err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
                err = gcry_cipher_setkey(cipher, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
                err = gcry_cipher_setiv(cipher, iv, IV_SIZE);
                //printf("Cipher encryption done");

            // Extract the HMAC
            fp = fopen("temporary", "rb");
            if (!fp) {
                print_error("Failed to open file for verification");
            }

            // Get file size
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            rewind(fp);
            printf("\nSize of file is %ld", size);

            // Read the file contents and HMAC
            unsigned char* file_contents = malloc(size - HMAC_SIZE);
            unsigned char* hmac = malloc(HMAC_SIZE);
            fread(file_contents, size - HMAC_SIZE, 1, fp);
            fread(hmac, HMAC_SIZE, 1, fp);
            //printf("Allocated hmac %s", hmac);

            /// Compute HMAC of the file contents
            gcry_md_hd_t md;
            gcry_md_open(&md, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
            gcry_md_setkey(md, key, KEY_SIZE);
            gcry_md_write(md, file_contents, size - HMAC_SIZE);
            unsigned char* computed_hmac = gcry_md_read(md, GCRY_MD_SHA256);

            bool hmac_valid = (memcmp(hmac, computed_hmac, HMAC_SIZE) == 0);
            if(hmac_valid){
                printf("\nHMAC Verification successfull %s = %s", hmac, computed_hmac);

                unsigned char* decrypted_data = malloc(size - HMAC_SIZE);
                gcry_cipher_decrypt(cipher, decrypted_data, size - HMAC_SIZE, file_contents, size - HMAC_SIZE);
                printf("\nData Decryption done");

                unsigned char* output_filename = malloc(strlen(input_filename));
                strcpy(output_filename, input_filename);
                //unsigned char* output_filename = malloc(strlen(input_filename) - 4);
                //output_filename[strlen(input_filename) - 4] = "\0";
                FILE* out_fp = fopen(output_filename, "wb");
                if (!out_fp) {
                    print_error("Failed to open output file");
                }
                fwrite(decrypted_data, size - HMAC_SIZE, 1, out_fp);
                //fwrite(file_contents, total_size - 16 - salt_len - iv_len - 32, 1, out_fp);
                fclose(out_fp);

                printf("\nDecryption successful. File saved as %s\n", output_filename);
                free(decrypted_data);
                close(newsockfd);
                return 0;
            }else{
                print_error("Your file has been tampered!!!");
                free(newsockfd);
                free(password);
                return 1;
            }
            
        }
        close(sockfd);
        return 0;
    }
}
