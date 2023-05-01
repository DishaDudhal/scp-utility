gcc -o purenc purenc-new.c `pkg-config --cflags --libs libgcrypt`
gcc -o purdec purdec.c `pkg-config --cflags --libs libgcrypt`