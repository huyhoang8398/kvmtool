#include "kvm/kvm-cpu.h"

#include "kvm/kvm.h"
#include "kvm/util.h"
#include "kvm/cpufeature.h"

#include <sys/ioctl.h>
#include <stdlib.h>

#define	MAX_KVM_CPUID_ENTRIES		100

static void filter_cpuid(struct kvm_cpu *vcpu)
{
	unsigned int i;
	struct kvm_cpuid2 *kvm_cpuid = vcpu->kvm_cpuid;

	/*
	 * Filter CPUID functions that are not supported by the hypervisor.
	 */
	for (i = 0; i < kvm_cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *entry = &kvm_cpuid->entries[i];
		struct cpuid_regs regs;

		switch (entry->function) {
		case 1:
			regs = (struct cpuid_regs){
				.eax = 1,
				.ecx = 0,
			};
			host_cpuid(&regs);

			if (entry->index == 0) {
				/* Expose TSC deadline */
				entry->ecx |= (1 << 24);
				/* Set X86_FEATURE_HYPERVISOR */
				entry->ecx |= (1 << 31);
				/* hide MCA/MCE */
				entry->edx &= ~((1 << 7) | (1 << 14));
			}

			entry->ebx = (regs.ebx & 0xffff) | (vcpu->kvm->nrcpus << 16) | (vcpu->cpu_id << 24);
			break;
		case 6:
			/* Clear X86_FEATURE_EPB */
			entry->ecx = entry->ecx & ~(1 << 3);
			break;
		case 10: { /* Architectural Performance Monitoring */
			union cpuid10_eax {
				struct {
					unsigned int version_id		:8;
					unsigned int num_counters	:8;
					unsigned int bit_width		:8;
					unsigned int mask_length	:8;
				} split;
				unsigned int full;
			} eax;

			/*
			 * If the host has perf system running,
			 * but no architectural events available
			 * through kvm pmu -- disable perf support,
			 * thus guest won't even try to access msr
			 * registers.
			 */
			if (entry->eax) {
				eax.full = entry->eax;
				if (eax.split.version_id != 2 ||
				    !eax.split.num_counters)
					entry->eax = 0;
			}
			break;
		}
		case 11: /* topology */
			if (entry->index == 0) {
				entry->eax = 0;
				entry->ebx = 1;
				entry->ecx = 1 << 8; /* SMT */
			} else if (entry->index == 1) {
				entry->eax = 8;
				entry->ebx = vcpu->kvm->nrcpus;
				entry->ecx = (2 << 8) | entry->index; /* core */
			} else {
				entry->eax = entry->ebx = 0;
				entry->ecx = entry->index & 0xff; /* invalid */
			}
			entry->edx = vcpu->cpu_id;
			break;
		default:
			/* Keep the CPUID function as -is */
			break;
		};
	}
}

void kvm_cpu__setup_cpuid(struct kvm_cpu *vcpu)
{
	if (vcpu->kvm_cpuid)
		return;

	vcpu->kvm_cpuid = calloc(1, sizeof(*vcpu->kvm_cpuid) +
				 MAX_KVM_CPUID_ENTRIES * sizeof(*vcpu->kvm_cpuid->entries));

	vcpu->kvm_cpuid->nent = MAX_KVM_CPUID_ENTRIES;
	if (ioctl(vcpu->kvm->sys_fd, KVM_GET_SUPPORTED_CPUID, vcpu->kvm_cpuid) < 0)
		die_perror("KVM_GET_SUPPORTED_CPUID failed");

	filter_cpuid(vcpu);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_CPUID2, vcpu->kvm_cpuid) < 0)
		die_perror("KVM_SET_CPUID2 failed");
}
