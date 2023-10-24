#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>

#include "kpdbg.h"

int main(int argc, char const *argv[])
{
    int ret;
    struct kpdbg_arg arg = {};

    int fd = open(KPDBG_DEV_PATH, O_RDONLY);

    if(fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (argc == 2) {
        if (!strcmp(argv[1], "unreg"))
            ret = ioctl(fd, CMD_UNREGISTER_ALL);
            if (ret)
                perror("ioctl");
        else
            puts("error command");
    }
    else if (argc == 3) {
        arg.sym_or_addr = (uint64_t)(unsigned long)argv[2];
        arg.size_or_idx = strlen(argv[2]) + 1;
        if (!strcmp(argv[1], "sym")) {
            ret = ioctl(fd, CMD_REGISTER_KPROBE_WITH_SYMBOL, &arg);
            if (ret)
                perror("ioctl");
        }
        else if (!strcmp(argv[1], "addr")) {
            ret = ioctl(fd, CMD_REGISTER_KPROBE_WITH_ADDRESS, &arg);
            if (ret)
                perror("ioctl");
        }
        else
            puts("error command");
    }

    close(fd);

    return 0;
}