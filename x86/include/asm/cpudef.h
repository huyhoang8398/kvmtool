#ifndef _ASM_X86_CPUDEF_H
#define _ASM_X86_CPUDEF_H

#include <inttypes.h>

#define KVM_MAX_VCPUS 288
#define KVM_NR_VAR_MTRR 8

struct fpu_mm
{
        uint64_t lo;
        uint16_t hi;
        uint16_t pad[3];
} __attribute__((packed));

struct fpu_xmm
{
        uint64_t lo;
        uint64_t hi;
};

struct fpu_regs
{
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t res0;
        uint16_t fop;
        uint64_t fpuip;
        uint64_t fpudp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        struct fpu_mm mm[8];
        struct fpu_xmm xmm[16];
        uint64_t res1[12];
} __attribute__((packed));

enum xfeature
{
        XFEATURE_FP,
        XFEATURE_SSE,
        /*
         * Values above here are "legacy states".
         * Those below are "extended states".
         */
        XFEATURE_YMM,
        XFEATURE_BNDREGS,
        XFEATURE_BNDCSR,
        XFEATURE_OPMASK,
        XFEATURE_ZMM_Hi256,
        XFEATURE_Hi16_ZMM,
        XFEATURE_PT_UNIMPLEMENTED_SO_FAR,
        XFEATURE_PKRU,

        XFEATURE_MAX,
};

#define XFEATURE_MASK_FP (1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE (1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM (1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS (1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR (1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK (1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256 (1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM (1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT (1 << XFEATURE_PT_UNIMPLEMENTED_SO_FAR)
#define XFEATURE_MASK_PKRU (1 << XFEATURE_PKRU)

#define XFEATURE_MASK_FPSSE (XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512 (XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)

#define XFEATURE_MASK_EXTEND (~(XFEATURE_MASK_FPSSE | (1ULL << 63)))

#define XSTATE_CPUID 0x0000000d

#define FXSAVE_SIZE 512

#define XSAVE_HDR_SIZE 64
#define XSAVE_HDR_OFFSET FXSAVE_SIZE

#define XSAVE_YMM_SIZE 256
#define XSAVE_YMM_OFFSET (XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

#define MSR_IA32_TSC 0x00000010

/* x86-64 specific MSRs */
#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101        /* 64bit GS base */
#define MSR_KERNEL_GS_BASE 0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX 0xc0000103        /* Auxiliary TSC */

#define MSR_IA32_SYSENTER_CS 0x00000174
#define MSR_IA32_SYSENTER_ESP 0x00000175
#define MSR_IA32_SYSENTER_EIP 0x00000176

#define MSR_IA32_MISC_ENABLE 0x000001a0
#define MSR_IA32_MISC_ENABLE_FAST_STRING_BIT 0
#define MSR_IA32_MISC_ENABLE_FAST_STRING (1ULL << MSR_IA32_MISC_ENABLE_FAST_STRING_BIT)

#define MSR_IA32_APICBASE 0x0000001b
#define MSR_IA32_APICBASE_BSP (1 << 8)
#define MSR_IA32_APICBASE_ENABLE (1 << 11)
#define MSR_IA32_APICBASE_BASE (0xfffff << 12)

#define MSR_IA32_TSCDEADLINE 0x000006e0

#define MSR_MTRRcap 0x000000fe

#define MSR_MTRRfix64K_00000 0x00000250
#define MSR_MTRRfix16K_80000 0x00000258
#define MSR_MTRRfix16K_A0000 0x00000259
#define MSR_MTRRfix4K_C0000 0x00000268
#define MSR_MTRRfix4K_C8000 0x00000269
#define MSR_MTRRfix4K_D0000 0x0000026a
#define MSR_MTRRfix4K_D8000 0x0000026b
#define MSR_MTRRfix4K_E0000 0x0000026c
#define MSR_MTRRfix4K_E8000 0x0000026d
#define MSR_MTRRfix4K_F0000 0x0000026e
#define MSR_MTRRfix4K_F8000 0x0000026f
#define MSR_MTRRdefType 0x000002ff

#define MSR_IA32_CR_PAT 0x00000277

#define KVM_MSR_ENTRY(_index, _data)           \
        (struct kvm_msr_entry)                 \
        {                                      \
                .index = _index, .data = _data \
        }

#define VLAPIC_HW_DISABLED 0x1
#define VLAPIC_SW_DISABLED 0x2

#define LAPIC(ptr, offset) ((uint32_t *)&ptr[offset])

#endif
