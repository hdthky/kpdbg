#ifndef KPDBG_H
#define KPDBG_H

#ifndef KPDBG_DEV_PATH
#define KPDBG_DEV_PATH "/dev/kpdbg"
#endif

enum ioctl_cmd {
    CMD_REGISTER_KPROBE_WITH_SYMBOL = 3,
    CMD_REGISTER_KPROBE_WITH_ADDRESS,

    CMD_MAX
};

struct kpdbg_arg {
    uint64_t sym_or_addr;
    uint64_t size_or_idx;
    uint64_t message;
    uint64_t msgsz;
};

#endif