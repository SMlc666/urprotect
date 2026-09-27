#define _GNU_SOURCE

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (getenv("URPROTECT_PROCESS_PROBE") == NULL) {
        return 0;
    }

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        return 10;
    }

    const char *argument_zero = strrchr(argv[0], '/');
    argument_zero = argument_zero == NULL ? argv[0] : argument_zero + 1;
    printf("argc=%d\n", argc);
    printf("argv0=%s\n", argument_zero);
    for (int index = 1; index < argc; ++index) {
        printf("argv%d=%s\n", index, argv[index]);
    }
    printf("environment=%s\n", getenv("URPROTECT_PROCESS_ENV"));
    printf("cwd=%s\n", cwd);

    char descriptor_content[128];
    ssize_t descriptor_size = read(3, descriptor_content, sizeof(descriptor_content) - 1);
    if (descriptor_size <= 0) {
        return 11;
    }
    descriptor_content[descriptor_size] = '\0';
    printf("descriptor3=%s", descriptor_content);

    FILE *declared_file = fopen("declared-artifact.txt", "wb");
    if (declared_file == NULL) {
        return 12;
    }
    int declared_write_failed = fputs("created-by-dynamic-et-exec\n", declared_file) < 0;
    if (fclose(declared_file) != 0 || declared_write_failed) {
        return 12;
    }

    if (getenv("URPROTECT_PROCESS_SIGNAL") != NULL) {
        (void)fflush(stdout);
        (void)raise(SIGTERM);
        return 13;
    }

    return 0;
}
