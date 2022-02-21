#ifndef KVM_BOOTSTATE_H
#define KVM_BOOTSTATE_H

#include <linux/types.h>

struct kvm;

void kvm__bootstate_set_selectors(struct kvm *kvm, u16 boot_selector);
void kvm__bootstate_set_msr(struct kvm *kvm, u32 index, u64 data);
void kvm__bootstate_init(struct kvm *kvm);

#endif
