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
char *salt = "w7eU4b4x3qX9sL8N";
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

    // Generate key and salt from password using PBKDF2
    gcry_error_t err;
    gcry_cipher_hd_t cipher;
    unsigned char* key = malloc(gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
    size_t salt_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
    printf("The salt is %s\nThe salt length is %d ", salt, salt_len);
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
        GCRY_MD_SHA256, salt, salt_len, 10000, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256), key);
    if (err) {
        print_error("Key derivation failed");
        free(password);
        free(key);
        free(salt);
        return 1;
    }

    //Initialize HMAC
    gcry_md_hd_t hmac;
    err = gcry_md_open(&hmac, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if (err) {
    print_error("HMAC initialization failed");
    free(password);
    free(key);
    free(salt);
    return 1;
    }
    //Set the key
    err = gcry_md_setkey(hmac, key, KEY_SIZE);
    if (err) {
    print_error("HMAC key setting failed");
    gcry_md_close(hmac);
    free(password);
    free(key);
    free(salt);
    return 1;
    }

    // Initialize encryption/decryption
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if (err) {
        print_error("Cipher initialization failed");
        gcry_md_close(hmac);
        free(password);
        free(key);
        free(salt);
        return 1;
    }
    err = gcry_cipher_setkey(cipher, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
    if (err) {
        print_error("Cipher key setting failed");
        gcry_md_close(hmac);
        gcry_cipher_close(cipher);
        free(password);
        free(key);
        free(salt);
        return 1;
    }
    err = gcry_cipher_setiv(cipher, iv, IV_SIZE);
    if (err) {
        print_error("Cipher IV setting failed");
        gcry_md_close(hmac);
        gcry_cipher_close(cipher);
        free(password);
        free(key);
        free(salt);
        return 1;
    }

    //Encrypt the input file
    // Create output file
    output_file = malloc(strlen(input_file) + 5);
    strcpy(output_file, input_file);
    strcat(output_file, ".pur");
    printf("%s",output_file);

    //Check if the output file already exists
    FILE* out_file = fopen(output_file, "wb");
    if (out_file == NULL) {
        print_error("Could not create output file");
        gcry_md_close(hmac);
        gcry_cipher_close(cipher);
        free(password);
        free(key);
        free(salt);
        return 1;
    }

    // Encrypt the input file and write the output to the output file
    FILE* in_file = fopen(input_file, "rb");
    // Allocate memory for the encrypted data buffer
    unsigned char *encrypted_data = malloc(BUF_SIZE);
    size_t encrypted_data_len = 0;

    // Read and encrypt data from the input file
    unsigned char *in_buffer = malloc(BUF_SIZE);
    size_t bytes_read = 0;
    while ((bytes_read = fread(in_buffer, 1, BUF_SIZE, in_file)) > 0) {
        // Allocate memory for the encrypted block
        unsigned char *encrypted_block = malloc(bytes_read);
        size_t encrypted_block_len = bytes_read;
        // Encrypt the block
        gcry_cipher_encrypt(cipher, encrypted_block, encrypted_block_len, in_buffer, bytes_read);
        printf("Read %zu bytes and wrote %zu bytes", bytes_read, encrypted_block_len);
        // Append the encrypted block to the encrypted data buffer
        encrypted_data = realloc(encrypted_data, encrypted_data_len + encrypted_block_len);
        memcpy(encrypted_data + encrypted_data_len, encrypted_block, encrypted_block_len);
        encrypted_data_len += encrypted_block_len;

        // Free the encrypted block memory
        free(encrypted_block);
    }

    // Write the encrypted data to the output file
    fwrite(encrypted_data, 1, encrypted_data_len, out_file);

    // Add HMAC tag to the end of the output file
    gcry_md_write(hmac, encrypted_data, encrypted_data_len);
    unsigned char* tag = gcry_md_read(hmac, GCRY_MD_SHA256);
    //printf("\nThe hmac generated is %s", tag);
    size_t bytes_written = fwrite(tag, 1, HMAC_SIZE, out_file);
    if (bytes_written < HMAC_SIZE) {
        print_error("Output file write error");
        free(password);
        free(key);
        free(salt);
        fclose(in_file);
        fclose(out_file);
        gcry_cipher_close(cipher);
        gcry_md_close(hmac);
        return 1;
    }

    // Close the input and output files
    fclose(in_file);
    fclose(out_file);

    printf("\nEncryption complete.\n");

    // Connect to destination over the network
    if (is_network) {
        // Resolve IP address
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(atoi(output_port));
        if (inet_pton(AF_INET, output_addr, &server_addr.sin_addr) <= 0) {
            print_error("Invalid IP address");
            return 1;
        }

        // Connect to server
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            print_error("Socket creation failed");
            return 1;
        }

        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            print_error("Connection failed");
            close(sockfd);
            return 1;
        }

        // Send the filename to the server
        int n = send(sockfd, input_file, strlen(input_file), 0);
        if (n < 0) {
            print_error("Sending input file name failed");
        }

        // Send encrypted file
        FILE* input = fopen(output_file, "rb");
        if (input == NULL) {
            print_error("Output file not found");
            close(sockfd);
            return 1;
        }

        unsigned char buffer[BUF_SIZE];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, BUF_SIZE, input)) > 0) {
            ssize_t bytes_sent = send(sockfd, buffer, bytes_read, 0);
            if (bytes_sent != bytes_read) {
                print_error("File send failed");
                fclose(input);
                close(sockfd);
                return 1;
            }
            printf("Successfully sent %d bytes", bytes_sent);
        }

        fclose(input);
        close(sockfd);
    }
}