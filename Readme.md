<!-- gcc -o purenc purenc-new.c `pkg-config --cflags --libs libgcrypt`
gcc -o purdec purdec.c `pkg-config --cflags --libs libgcrypt` -->

Name : Disha Dudhal
List of files: 
1. purenc-new.c
2. purdec.c
3. move.txt

The task is to implement SCP (Secure Copy) from scratch using the libgcrypt library in C language. The implementation has three stages. In the first stage, the file encryption program will be developed. In the second stage, the file decryption program will be developed. In the third and final stage, the file transfer using the host IP will be implemented.

The programs are written in C language and will use the libgcrypt library. The make utility will be used to create the program.

The file encryption program "purenc" will take an input file as input and transmit it to the IP address/port specified on the command line using the -d option. Alternatively, if -d option is not used, the encrypted contents of the input file will be dumped to an output file of the same name, but with the added extension ".pur". For example, if the input file is "hello.txt", the output file should be "hello.txt.pur". The file decryption program "purdec" will run as a network daemon, awaiting incoming network connections on the command-line specified network port. It can also be run in local mode (-l option) in which it bypasses the network functionality and simply decrypts a file specified as input. In either mode, the output should be the original name of the file, minus the ".pur" extension.

On each invocation, both programs (purenc and purdec) will prompt the user for a password to encrypt or decrypt the file under. The key used to encrypt the file will be computed from the password by hashing it using the PBKDF2 function. An HMAC will also be attached to the file and verified with purdec. Encryption will be done using AES256.

Both purenc and purdec will display an error and abort the operation if the output file already exists.

I have created 2 files each of which handle a local mode and a network mode.
In the local mode , purenc simply encrypts the file which purdec simply decrypts the file.

* Please run the following commands to update libgcrypt version to 1.10.2 on a Ubuntu 18 machine. 
sudo apt-get update
sudo apt-get install libgcrypt20

* To the programs in local mode, run
make
./purenc testfile.txt -l
./purdec -l testfile.txt.pur

* To run the progorams in network mode, run 
make
./purdec -p 8888
./purenc testfile.txt -d 127.0.0.1:8888

Decisions Made:
1. Hardcode salt and IV -> My code was segfaulting numerous times if i was sending these values over the network.
2. keeping the decrypted filename same as the argument passed -> Same segfault issue.
3. For handling PBKDF2 we have to pass the hash algorithm SHA256 in addition to the salt, salt length, password and password length, as well as the size of the key to be generated.
            