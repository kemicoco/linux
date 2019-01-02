#include <linux/mman.h>
#include <linux/sysctl.h>

#define KVM_MADV_FREE    0
#define KVM_MADV_DONTNEED    1

int sysctl_kvm_madv_free = KVM_MADV_FREE;
int kvm_ret_mem_advice = MADV_FREE;
EXPORT_SYMBOL_GPL(kvm_ret_mem_advice);

static DEFINE_MUTEX(kvm_ret_memory_advice_lock);

int kvm_madv_free_sysctl_handler(struct ctl_table *table, int write,
        void __user *buffer, size_t *length, loff_t *ppos)
{
    int ret;

    mutex_lock(&kvm_ret_memory_advice_lock);
    ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
    if (ret || !write)
        goto out;

    if (sysctl_kvm_madv_free == KVM_MADV_FREE)
        kvm_ret_mem_advice = MADV_FREE;
    else if (sysctl_kvm_madv_free == KVM_MADV_DONTNEED)
        kvm_ret_mem_advice = MADV_DONTNEED;

out:
    mutex_unlock(&kvm_ret_memory_advice_lock);
    return ret;
}
