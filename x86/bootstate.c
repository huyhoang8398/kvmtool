#include "kvm/kvm-cpu.h"
#include "kvm/kvm.h"
#include "kvm/cpufeature.h"
#include "kvm/bootstate.h"
#include "asm/cpudef.h"

static struct kvm_msrs *kvm_msrs__new(size_t nmsrs)
{
	struct kvm_msrs *vcpu = calloc(1, sizeof(*vcpu) + (sizeof(struct kvm_msr_entry) * nmsrs));

	if (!vcpu)
		die("out of memory");

	return vcpu;
}

static void kvm_bootstate__setup_sregs(struct kvm_sregs *sregs)
{
	sregs->cs = (struct kvm_segment){
	    .base = 0xffff0000ul,
	    .limit = 0xffff,
	    .selector = 0xf000,
	    .type = 0xb,
	    .present = 1,
	    .dpl = 0,
	    .db = 0,
	    .s = 1,
	    .l = 0,
	    .g = 0,
	    .avl = 0,
	};
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = (struct kvm_segment){
	    .base = 0,
	    .limit = 0xffff,
	    .selector = 0,
	    .type = 0x3,
	    .present = 1,
	    .dpl = 0,
	    .db = 0,
	    .s = 1,
	    .l = 0,
	    .g = 0,
	    .avl = 0,
	};
	sregs->cr0 = 0x60000010ul;
	// sregs->cr2 = sregs->cr3 = sregs->cr4 = sregs->cr8 = 0;
	sregs->gdt = sregs->idt = (struct kvm_dtable){
	    .base = 0,
	    .limit = 0xffff,
	};
	sregs->ldt = (struct kvm_segment){
	    .base = 0,
	    .limit = 0xffff,
	    .selector = 0,
	    .type = 0x2,
	    .present = 1,
	    .dpl = 0,
	    .db = 0,
	    .s = 0,
	    .l = 0,
	    .g = 0,
	    .avl = 0,
	};
	sregs->tr = (struct kvm_segment){
	    .base = 0,
	    .limit = 0xffff,
	    .selector = 0,
	    .type = 0xb,
	    .present = 1,
	    .dpl = 0,
	    .db = 0,
	    .s = 0,
	    .l = 0,
	    .g = 0,
	    .avl = 0,
	};
	sregs->apic_base = 0xfee00800ul;
}

static void kvm_bootstate__setup_regs(struct kvm_regs *regs)
{
	*regs = (struct kvm_regs){
	    .rip = 0xfff0,
	    .rflags = 0x2,
	};
}

static void kvm_bootstate__setup_fpu(struct kvm_fpu *fpu)
{
	/* provide pre-initialized fpu */
	fpu->fcw = 0x37f;
	fpu->mxcsr = 0x1f80;
}

static void kvm_bootstate__setup_xcrs(struct kvm_xcrs *xcrs)
{
	xcrs->nr_xcrs = 0;
	xcrs->xcrs[xcrs->nr_xcrs++] = (struct kvm_xcr){
	    .xcr = 0,
	    .value = 1,
	};
}

static struct kvm_msrs *kvm_bootstate__setup_msrs(void)
{
	struct kvm_msrs *ret = kvm_msrs__new(100);

	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_CS, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_ESP, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_EIP, 0x0);
#ifdef CONFIG_X86_64
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_STAR, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_CSTAR, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_KERNEL_GS_BASE, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_SYSCALL_MASK, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_LSTAR, 0x0);
#endif
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_IA32_TSC, 0x0);
	ret->entries[ret->nmsrs++] = KVM_MSR_ENTRY(MSR_IA32_MISC_ENABLE,
						   MSR_IA32_MISC_ENABLE_FAST_STRING);

	return ret;
}

static inline u32 selector_to_base(u16 selector)
{
	/*
	 * KVM on Intel requires 'base' to be 'selector * 16' in real mode.
	 */
	return (u32)selector << 4;
}

void kvm__bootstate_set_selectors(struct kvm *kvm, u16 boot_selector)
{
	struct kvm_sregs *sregs = &kvm->arch.bootstate.sregs;
	sregs->cs.selector = sregs->ds.selector = sregs->es.selector = sregs->fs.selector = sregs->gs.selector = sregs->ss.selector = boot_selector;
	sregs->cs.base = sregs->ds.base = sregs->es.base = sregs->fs.base = sregs->gs.base = sregs->ss.base = selector_to_base(boot_selector);
}

void kvm__bootstate_set_msr(struct kvm *kvm, u32 index, u64 data)
{
	struct kvm_msrs *msrs = kvm->arch.bootstate.msrs;
	for (u32 i = 0; i < msrs->nmsrs; i++)
	{
		if (msrs->entries[i].index == index)
		{
			msrs->entries[i].data = data;
			return;
		}
	}
	msrs->entries[msrs->nmsrs++] = KVM_MSR_ENTRY(index, data);
}

void kvm__bootstate_init(struct kvm *kvm)
{
	kvm_bootstate__setup_sregs(&kvm->arch.bootstate.sregs);
	kvm_bootstate__setup_regs(&kvm->arch.bootstate.regs);
	kvm_bootstate__setup_fpu(&kvm->arch.bootstate.fpu);
	kvm_bootstate__setup_xcrs(&kvm->arch.bootstate.xcrs);
	kvm->arch.bootstate.msrs = kvm_bootstate__setup_msrs();
}
