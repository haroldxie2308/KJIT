#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BUFFER_SIZE 200
#define REPEAT_COUNT (1 << 20)
#define OUTPUT_FILE "/tmp/note"

int read_input(char *buffer, int size) {
    printf("Enter some text (max %d characters): ", size);
    if (fgets(buffer, size, stdin) == NULL) {
        perror("Error reading input");
        return -1;
    }
    return 0;
}

int write_output(const char *buffer) {
    for (int i = 0; i < REPEAT_COUNT; i++) {
        FILE *file = fopen(OUTPUT_FILE, "w");
        if (file == NULL) {
            perror("Error opening file");
            return EXIT_FAILURE;
        }
        if (fputs(buffer, file) == EOF) {
            fclose(file);
            perror("Error writing to file");
            return -1;
        }
        fclose(file);
    }

    printf("Buffer written to %s.\n", OUTPUT_FILE);
    return 0;
}

int main() {
    char buffer[BUFFER_SIZE];
    read_input(buffer, BUFFER_SIZE);

    clock_t tic = clock();
    
    if (write_output(buffer) != 0) {
        return EXIT_FAILURE;
    }

    clock_t toc = clock();
    printf("Buffer written to %s %d times within %f\n",
                OUTPUT_FILE, REPEAT_COUNT, (double)(toc - tic) / CLOCKS_PER_SEC);
    return EXIT_SUCCESS;
}