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
    int ret = EXIT_SUCCESS;

    int fd = open(KPDBG_DEV_PATH, O_RDONLY);

    if(fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return ret;
}