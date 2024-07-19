#include <cstdio>
#include <unistd.h>

int data = 123;

int foo() {
    return data;
}

int main(int argc, char** argv) {
    FILE *file = fopen("data.txt", "w");
    fprintf(file, "%d\n", getpid());
    fprintf(file, "%p\n", (void*)foo);
    fprintf(file, "%p\n", &data);
    fclose(file);

    while (true) {
        printf("%d\n", foo());
        sleep(1);
    }
}
