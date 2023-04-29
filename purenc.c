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
    unsigned char* salt = malloc(BUF_SIZE);
    size_t salt_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
        GCRY_MD_SHA256, salt, BUF_SIZE, 10000, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256), key);
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

    // Write salt and IV to the output file
    fwrite(salt, SALT_SIZE, 1, out_file);
    fwrite(iv, strlen(iv), 1, out_file);

    // Encrypt the input file and write it to the output file
    file = fopen(input_file, "rb");
    unsigned char buf[BUF_SIZE];
    size_t nread;
    //gcry_cipher_setiv(cipher, iv, strlen(iv));
    while ((nread = fread(buf, 1, BUF_SIZE, file)) > 0) {
        gcry_cipher_encrypt(cipher, buf, nread, buf, BUF_SIZE);
        gcry_md_write(hmac, buf, nread);
        fwrite(buf, 1, nread, out_file);
    }
    fclose(file);
    fclose(out_file);

    // Finalize HMAC
    unsigned char* hmac_result = gcry_md_read(hmac, GCRY_MD_SHA256);
    out_file = fopen(output_file, "wb");
    fwrite(hmac_result, HMAC_SIZE, 1, out_file);
    fclose(out_file);

    printf("Encryption complete.\n");
}