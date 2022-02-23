#include "kvm/kvm.h"
#include "kvm/multiboot-def.h"
#include "kvm/kvm-arch.h"
#include "kvm/strbuf.h"
#include "kvm/e820.h"
#include "kvm/multiboot.h"
#include <elf.h>

#define MB_KERNEL_START 0x100000
#define CMDLINE_MAX_LEN 4096
#define MB_MMAP_ENTRY_SIZE (sizeof(multiboot_memory_map_t) - offsetof(multiboot_memory_map_t, addr))

#define ALIGN_UP(x, s) ALIGN((x) + (s)-1, (s))

struct mbi_full
{
	struct multiboot_info mbi;
	multiboot_memory_map_t mmap[E820MAX];
	char cmdline[CMDLINE_MAX_LEN];
	multiboot_module_t module;
};

struct mbl_state
{
	/* end of usable below-4g address region */
	u32 load_limit;
	u64 mb_offset;
	struct multiboot_header *mbh;
	u64 mbi_addr;
	struct mbi_full *mbi_buf;
	u64 entry_addr;
};

static bool load_multiboot_flat(struct kvm *kvm, int fd_kernel,
				struct mbl_state *s)
{
	void *p = guest_flat_to_host(kvm, s->mbh->load_addr);
	u64 file_offset = s->mb_offset - (s->mbh->header_addr - s->mbh->load_addr);
	u64 read_count;

	pr_debug("Loading Multiboot flat image");

	if (lseek(fd_kernel, file_offset, SEEK_SET) < 0)
		die_perror("lseek");
	if (s->mbh->load_end_addr)
	{
		read_count = s->mbh->load_end_addr - s->mbh->load_addr;
		// the two addresses should already be trusted
		if (read_in_full(fd_kernel, p, read_count) != (ssize_t)read_count)
			return false;
	}
	else
	{
		read_count = read_file(fd_kernel, p, s->load_limit - s->mbh->load_addr);
		if (read_count < 0)
			return false;
	}
	pr_debug("read %#llx bytes from file_offset %#llx into %#x", read_count, file_offset, s->mbh->load_addr);
	/* mbi immediately follows our loaded image */
	s->mbi_addr = ALIGN_UP(s->mbh->load_addr + read_count, PAGE_SIZE);

	if (s->mbh->bss_end_addr)
	{
		u64 bss_addr = (u64)s->mbh->load_addr + read_count;
		if (s->mbh->bss_end_addr > bss_addr)
		{
			void *bss = guest_flat_to_host(kvm, bss_addr);
			u64 bss_size = s->mbh->bss_end_addr - bss_addr;
			memset(bss, 0, bss_size);
			s->mbi_addr = ALIGN_UP(s->mbh->bss_end_addr, PAGE_SIZE);
			pr_debug("clearing bss from %#llx to %#x", bss_addr, s->mbh->bss_end_addr);
		}
	}

	if (s->mbi_addr + sizeof(struct mbi_full) > s->load_limit)
		return false;
	s->mbi_buf = guest_flat_to_host(kvm, s->mbi_addr);
	s->entry_addr = s->mbh->entry_addr;
	pr_debug("installing mbi at %#llx", s->mbi_addr);

	return true;
}

static bool load_multiboot_elf(struct kvm *kvm, int fd_kernel)
{
	pr_err("elf loading not implemented yet");
	return false;
}

static void prep_mbi(struct kvm *kvm, struct mbl_state *s, const char *kernel_cmdline)
{
	/* fill memory info */
	s->mbi_buf->mbi.flags |= MULTIBOOT_INFO_MEMORY;
	s->mbi_buf->mbi.mem_lower = (EBDA_START - REAL_MODE_IVT_BEGIN) >> 10;
	s->mbi_buf->mbi.mem_upper = (s->load_limit - MB_KERNEL_START) >> 10;

	if (kernel_cmdline)
	{
		s->mbi_buf->mbi.flags |= MULTIBOOT_INFO_CMDLINE;
		strlcpy(s->mbi_buf->cmdline, kernel_cmdline, CMDLINE_MAX_LEN);
		s->mbi_buf->mbi.cmdline = host_to_guest_flat(kvm, s->mbi_buf->cmdline);
	}

	/* fill memmap */
	s->mbi_buf->mbi.flags |= MULTIBOOT_INFO_MEM_MAP;
	for (u32 i = 0; i < kvm->arch.e820.nr_map; i++)
		s->mbi_buf->mmap[i] = (multiboot_memory_map_t){
		    .size = MB_MMAP_ENTRY_SIZE,
		    .addr = kvm->arch.e820.map[i].addr,
		    .len = kvm->arch.e820.map[i].size,
		    .type = kvm->arch.e820.map[i].type,
		};
	s->mbi_buf->mbi.mmap_length = kvm->arch.e820.nr_map * sizeof(multiboot_memory_map_t);
	s->mbi_buf->mbi.mmap_addr = host_to_guest_flat(kvm, s->mbi_buf->mmap);
}

static void prep_bootstate(struct kvm *kvm, struct mbl_state *s)
{
	struct kvm_arch_bootstate *bootstate = &kvm->arch.bootstate;

	bootstate->regs.rax = MULTIBOOT_BOOTLOADER_MAGIC;
	bootstate->regs.rbx = s->mbi_addr;
	bootstate->regs.rip = s->entry_addr;
	bootstate->sregs.cs = (struct kvm_segment){
	    .base = 0,
	    .limit = 0xffffffff, /* vmcs segment limit is always in bytes */
	    .selector = 0,
	    .type = 0xa,
	    .present = 1,
	    .dpl = 0,
	    .db = 1,
	    .s = 1,
	    .l = 0,
	    .g = 1,
	    .avl = 0,
	};
	bootstate->sregs.ds = bootstate->sregs.es = bootstate->sregs.fs = bootstate->sregs.gs = bootstate->sregs.ss = (struct kvm_segment){
	    .base = 0,
	    .limit = 0xffffffff,
	    .selector = 0,
	    .type = 0x2,
	    .present = 1,
	    .dpl = 0,
	    .db = 1,
	    .s = 1,
	    .l = 0,
	    .g = 1,
	    .avl = 0,
	};
	bootstate->sregs.cr0 = 0x11;
}

bool load_multiboot(struct kvm *kvm, int fd_kernel, int fd_initrd,
		    const char *kernel_cmdline)
{
	u32 mb_search[MULTIBOOT_SEARCH / sizeof(u32)];
	struct mbl_state s = {
	    .load_limit = min(kvm->ram_size, KVM_32BIT_GAP_START),
	};

	if (lseek(fd_kernel, 0, SEEK_SET) < 0)
		die_perror("lseek");

	if (read_in_full(fd_kernel, mb_search, MULTIBOOT_SEARCH) != MULTIBOOT_SEARCH)
		return false;

	for (u32 i = 0; i < ARRAY_SIZE(mb_search) - 2; i++)
	{
		if (mb_search[i] == MULTIBOOT_HEADER_MAGIC && (mb_search[i] + mb_search[i + 1] + mb_search[i + 2]) == 0)
		{
			s.mbh = (struct multiboot_header *)&mb_search[i];
			s.mb_offset = i * sizeof(u32);
			break;
		}
	}

	if (!s.mbh)
		return false;

	/* validate header flags */
	if ((s.mbh->flags & MULTIBOOT_VIDEO_MODE) && (s.mb_offset + sizeof(struct multiboot_header) > MULTIBOOT_SEARCH))
		return false;

	if (s.mbh->flags & MULTIBOOT_AOUT_KLUDGE)
	{
		if (s.mb_offset + offsetof(struct multiboot_header, mode_type) > MULTIBOOT_SEARCH)
			return false;

		if (s.mbh->load_addr > s.mbh->header_addr)
			return false;

		if (s.mbh->load_end_addr)
		{
			if (s.mbh->load_end_addr <= s.mbh->load_addr)
				return false;

			if (s.mbh->load_end_addr > s.load_limit)
				return false;

			if (s.mbh->entry_addr > s.mbh->load_end_addr)
				return false;
		}

		if (s.mbh->entry_addr < s.mbh->load_addr)
			/* entry_addr is supposed to be inside the loaded region */
			return false;

		if (s.mbh->header_addr - s.mbh->load_addr > s.mb_offset)
			/* ensure text section begins inside the file */
			return false;

		if (s.mbh->load_addr < MB_KERNEL_START)
			/* refuse to load into weird regions */
			return false;

		if (s.mbh->bss_end_addr)
		{
			if (s.mbh->bss_end_addr < s.mbh->load_end_addr)
				/* reject overlapping bss region */
				return false;

			if (s.mbh->bss_end_addr > s.load_limit)
				/* reject overly-big bss */
				return false;
		}

		if (!load_multiboot_flat(kvm, fd_kernel, &s))
			die("flat Multiboot kernel load failed");
	}
	else if (!load_multiboot_elf(kvm, fd_kernel))
		return false;

	if (fd_initrd >= 0)
	{
		u64 mod_start = ALIGN_UP(s.mbi_addr + sizeof(struct mbi_full), PAGE_SIZE);
		if (mod_start > s.load_limit)
			die("not enough memory for module");
		void *mod = guest_flat_to_host(kvm, mod_start);
		ssize_t modsz = read_file(fd_initrd, mod, s.load_limit - mod_start);
		if (modsz < 0)
			die("cannot read module, is module too large?");
		s.mbi_buf->module = (multiboot_module_t){
		    .mod_start = mod_start,
		    .mod_end = mod_start + modsz,
		};
		s.mbi_buf->mbi.mods_count = 1;
		s.mbi_buf->mbi.mods_addr = host_to_guest_flat(kvm, &s.mbi_buf->module);
		s.mbi_buf->mbi.flags |= MULTIBOOT_INFO_MODS;
	}

	prep_mbi(kvm, &s, kernel_cmdline);
	prep_bootstate(kvm, &s);

	return true;
}
