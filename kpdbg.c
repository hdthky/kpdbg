#define DEBUG

#include <linux/init.h>       /* module_init, module_exit */
#include <linux/module.h>     /* version info, MODULE_LICENSE, MODULE_AUTHOR, printk() */
#include <linux/fs.h> 	      /* file stuff */
#include <linux/kernel.h>     /* printk() */
#include <linux/errno.h>      /* error codes */
#include <linux/module.h>     /* THIS_MODULE */
#include <linux/cdev.h>       /* char device stuff */
#include <linux/uaccess.h>    /* copy_to_user() */
#include <linux/compat.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>

#include "kpdbg.h"

MODULE_DESCRIPTION("Exploit Playground");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hdthky");

#define MAX_NUM_KP 64
struct kprobe *kps[MAX_NUM_KP];
char *msgs[MAX_NUM_KP];

void free_kps(void) {
    int i;
    for(i = 0; i < MAX_NUM_KP; i++) {
        if (kps[i]) {
            unregister_kprobe(kps[i]);
            if(kps[i]->symbol_name)
                kfree(kps[i]->symbol_name);
            kfree(kps[i]);
            kps[i] = NULL;
            if (msgs[i]) {
                kfree(msgs[i]);
                msgs[i] = NULL;
            }
        }
    }
}

int get_slot(void) {
    int i;
    for(i = 0; i < MAX_NUM_KP; i++) {
        if (!kps[i])
            return i;
    }
    return -ENOENT;
}

int find_slot(void *needle) {
    int i;
    for(i = 0; i < MAX_NUM_KP; i++) {
        if (kps[i] == needle)
            return i;
    }
    return -ENOENT;
}

int kpdbg_pre_handler(struct kprobe* kp, struct pt_regs* regs) {
    int idx;

    idx = find_slot(kp);
    if (idx < 0) 
        return 0;
    
    if (msgs[idx])
        pr_info("%s\n", msgs[idx]);
    else
        pr_info("execute %px\n", kp->addr);

    return 0;
}

int kpdbg_parse_symbol(struct kprobe *kp, struct kpdbg_arg* arg) {
    void *symbol;

    symbol = kmalloc(arg->size_or_idx, GFP_KERNEL);
    if (!symbol)
        return -ENOMEM;
    
    if (copy_from_user(symbol, (void *)(unsigned long)arg->sym_or_addr, arg->size_or_idx))
        return -EFAULT;
    
    kp->symbol_name = symbol;

    return 0;
}

int kpdbg_parse_address(struct kprobe *kp, struct kpdbg_arg* arg) {
    unsigned long addr;
    char *addr_str;
    int ret;

    addr_str = kmalloc(arg->size_or_idx, GFP_KERNEL);
    if (!addr_str)
        return -ENOMEM;
    
    if (copy_from_user(addr_str, (void *)(unsigned long)arg->sym_or_addr, arg->size_or_idx))
        return -EFAULT;
    
    ret = kstrtoul(addr_str, 0, &addr);
    if (ret)
        return ret;

    kp->addr = (kprobe_opcode_t *)addr;
    kfree(addr_str);

    return 0;
}

/*===============================================================================================*/
static long kpdbg_ioctl(struct file *filp, unsigned int cmd, unsigned long user_buffer) { // 不知为何，cmd为2时，不会进入本函数
    struct kprobe *kp;
    struct kpdbg_arg arg;
    void *message = NULL;
    uint64_t idx;
    int ret;

    pr_debug("[kpdbg] ioctl: cmd is %u\n", cmd);

    if (copy_from_user(&arg, (void *)user_buffer, sizeof(arg)))
        return -ENOMEM;

    switch (cmd) {
    case CMD_REGISTER_KPROBE_WITH_SYMBOL:
        kp = kzalloc(sizeof(*kp), GFP_KERNEL);
        if (!kp)
            return -ENOMEM;
        kp->pre_handler = kpdbg_pre_handler;

        ret = kpdbg_parse_symbol(kp, &arg);
        if (ret)
            return ret;
        
        if (arg.msgsz) {
            message = kmalloc(arg.msgsz, GFP_KERNEL);
            if (!message)
                return -ENOMEM;
            
            if (copy_from_user(message, (void *)(unsigned long)arg.message, arg.msgsz))
                return -EFAULT;
        }
        
        idx = get_slot();
        if (idx < 0) 
            return -ENOENT;

        ret = put_user(idx, &((struct kpdbg_arg *)user_buffer)->size_or_idx);
        if (ret)
            return ret;
        
        ret = register_kprobe(kp);
        if (ret)
            return ret;

        kps[idx] = kp;
        msgs[idx] = message;

        break;
    case CMD_REGISTER_KPROBE_WITH_ADDRESS:
        kp = kzalloc(sizeof(*kp), GFP_KERNEL);
        if (!kp)
            return -ENOMEM;
        kp->pre_handler = kpdbg_pre_handler;

        ret = kpdbg_parse_address(kp, &arg);
        if (ret)
            return ret;
        
        if (arg.msgsz) {
            message = kmalloc(arg.msgsz, GFP_KERNEL);
            if (!message)
                return -ENOMEM;
            
            if (copy_from_user(message, (void *)(unsigned long)arg.message, arg.msgsz))
                return -EFAULT;
        }

        idx = get_slot();
        if (idx < 0) 
            return -ENOENT;

        ret = put_user(idx, &((struct kpdbg_arg *)user_buffer)->size_or_idx);
        if (ret)
            return ret;

        ret = register_kprobe(kp);
        if (ret)
            return ret;

        kps[idx] = kp;
        msgs[idx] = message;

        break;
    case CMD_UNREGISTER_ALL:
        free_kps();

        break;
    default:
        break;
    }
    
    return 0;
}

/*===============================================================================================*/
static struct file_operations simple_driver_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = kpdbg_ioctl,
};

static int device_file_major_number = 237;
static const char device_name[] = "kpdbg";

/*===============================================================================================*/
static int kpdbg_init(void) {
    int ret;

    ret = register_chrdev(device_file_major_number, device_name, &simple_driver_fops);
    if (ret < 0) {
        device_file_major_number = ret;
        pr_info("[kpdbg] init: register_chrdev failed with error code %i\n", ret);
        return ret;
    }

    pr_info("[kpdbg] init: register kpdbg chrdev\n");

    pr_info("[kpdbg] init: all done\n");

    return 0;
}

/*===============================================================================================*/
static void kpdbg_exit(void) {
    free_kps();

    if (device_file_major_number >= 0) {
        pr_info("[kpdbg] exit: unregister chrdev\n" );
        unregister_chrdev(device_file_major_number, device_name);
    }
}

/*===============================================================================================*/
module_init(kpdbg_init);
module_exit(kpdbg_exit);
