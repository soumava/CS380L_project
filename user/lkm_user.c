#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#define BAIL_ON_ERROR(x, failure_val)   if (x == failure_val) {printf("ret=%d, errno=%s\n", x, strerror(errno)); return;}
#define BAIL_ON_NULL(x) if (x == NULL) {return;}
#define INSMOD "insmod "
#define FILTER " filter=\""

void main(int argc, char** argv) {
    int fd, size, ret, i;
    struct stat file_stat = {0};
    char buffer[512], *final_str = NULL, *file_contents = NULL;
    char* rules_filename, *module_filename;

    if (argc != 3) {
        printf("Usage: %s <module_file> <rules_filename>\n", argv[0]);
        return;
    }

    module_filename = argv[1];
    rules_filename = argv[2];

    ret = open(rules_filename, O_RDONLY, 0);
    BAIL_ON_ERROR(ret, -1);

    fd = ret;
    ret = fstat(fd, &file_stat);
    BAIL_ON_ERROR(ret, -1);
    
    strncpy(buffer, INSMOD, sizeof(INSMOD) - 1);
    size = sizeof(INSMOD) - 1;
    strncpy(buffer + size, module_filename, strlen(module_filename));
    size += strlen(module_filename);
    strncpy(buffer + size, FILTER, sizeof(FILTER) - 1);
    size += sizeof(FILTER) - 1;

    size += file_stat.st_size;
    final_str = (char *)malloc(sizeof(char) * (size + 2));
    BAIL_ON_NULL(final_str);

    size -= file_stat.st_size;
    strncpy(final_str, buffer, size);
    printf("Prepared prefix string: %s\n", final_str);

    file_contents = (char *)malloc(sizeof(char) * file_stat.st_size);
    ret = read(fd, file_contents, file_stat.st_size);
    BAIL_ON_ERROR(ret, -1);

    printf("Copied file contents: %s", file_contents);

    for (i = 0; i < file_stat.st_size; i++) {
        if (file_contents[i] != ' ' && file_contents[i] != '\n' && file_contents[i] != '\r') {
            final_str[size + i] = file_contents[i];
        }
        else if (file_contents[i] == '\n') {
            if (i != file_stat.st_size - 1) {
                final_str[size + i] = '|';
            }
            else {
                final_str[size + i] = '\"';
            }
        }
    }
    final_str[size + file_stat.st_size] = '\0';
    
    printf("Constructed invocation string: %s\n", final_str);
    close(fd);

    // ret = open(module_image, O_RDONLY, 0);
    // BAIL_ON_ERROR(ret, -1);

    // modulefd = ret;
    // ret = fstat(modulefd, &file_stat);
    // BAIL_ON_ERROR(ret, -1);

    // addr = mmap(NULL, file_stat.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, modulefd, 0);
    // BAIL_ON_ERROR(addr, (void *)-1);

    ret = system(final_str);
    BAIL_ON_ERROR(ret, -1);
}
