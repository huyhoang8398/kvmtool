#ifndef KVM__KVM_MULTIBOOT_H
#define KVM__KVM_MULTIBOOT_H

#include "kvm/kvm.h"

bool load_multiboot(struct kvm *kvm, int fd_kernel, int fd_initrd,
		    const char *kernel_cmdline);

#endif
