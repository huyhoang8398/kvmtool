#include "kvm/ioport.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include "vptrans.h"

static void dummy_io(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len,
		     u8 is_write, void *ptr)
{
}

static void criu_devirtualization(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len,
			   u8 is_write, void *ptr)
{

	static u64 value[16] = {0};
	static int pos = 0;
	struct vptrans_pin pin;
	if (addr == 1686)
	{
		// very weird FIX ME
		pos = 0;
	}
	value[pos] = ioport__read16((u16 *)data);
	pos++;

	int vpfd = open("/dev/vptrans", O_WRONLY);
	if (vpfd < 0)
	{
		perror("Open /dev/vptrans");
		return;
	}

	int done;

	if (addr == 1701)
	{
		pin.vaddr = 0;
		pin.nr_page = 0;
		pin.off = 0;
		for (int i = 0; i < 8; i++)
		{
			pin.vaddr = value[i] << (i * 8) | pin.vaddr;
		}

		for (int i = 8; i < 12; i++)
		{
			pin.off = value[i] << ((i - 8) * 8) | pin.off;
		}

		for (int i = 12; i < 16; i++)
		{
			pin.nr_page = value[i] << ((i - 12) * 8) | pin.nr_page;
		}

		fprintf(stderr, "%lx %llu %llu\n", (uintmax_t)pin.vaddr, pin.nr_page, pin.off);

		pin.kvm_addr = guest_flat_to_host(vcpu->kvm, pin.vaddr);

		done = ioctl(vpfd, VPTRANS_IOCTL_PIN, &pin);
		if (done < 0)
		{
			perror("ioctl");
			return;
		}
		else if (done == 0)
		{
			fprintf(stderr, "got nothing done\n");
			return;
		}
		else
		{
			fprintf(stderr, "done %#x\n", done);
		}
	}

	close(vpfd);
}

static void debug_io(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len,
		     u8 is_write, void *ptr)
{
	if (!vcpu->kvm->cfg.ioport_debug)
		return;

	fprintf(stderr, "debug port %s from VCPU%lu: port=0x%lx, size=%u",
		is_write ? "write" : "read", vcpu->cpu_id,
		(unsigned long)addr, len);
	if (is_write)
	{
		u32 value;

		switch (len)
		{
		case 1:
			value = ioport__read8(data);
			break;
		case 2:
			value = ioport__read16((u16 *)data);
			break;
		case 4:
			value = ioport__read32((u32 *)data);
			break;
		default:
			value = 0;
			break;
		}
		fprintf(stderr, ", data: 0x%x\n", value);
	}
	else
	{
		fprintf(stderr, "\n");
	}
}

static void seabios_debug_io(struct kvm_cpu *vcpu, u64 addr, u8 *data,
			     u32 len, u8 is_write, void *ptr)
{
	char ch;

	if (!is_write)
		return;

	ch = ioport__read8(data);

	putchar(ch);
}

static void qemu_isa_debug_io(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len,
			      u8 is_write, void *ptr)
{
	if (is_write)
		kvm__reboot(vcpu->kvm);
}

/*
 * The "fast A20 gate"
 */

static void ps2_control_io(struct kvm_cpu *vcpu, u64 addr, u8 *data, u32 len,
			   u8 is_write, void *ptr)
{
	/*
	 * A20 is always enabled.
	 */
	if (!is_write)
		ioport__write8(data, 0x02);
}

void ioport__map_irq(u8 *irq)
{
}

static int ioport__setup_arch(struct kvm *kvm)
{
	int r;
	/* Legacy ioport setup */

	/* 0000 - 001F - DMA1 controller */
	r = kvm__register_pio(kvm, 0x0000, 32, dummy_io, NULL);
	if (r < 0)
		return r;

	/* 0x0020 - 0x003F - 8259A PIC 1 */
	r = kvm__register_pio(kvm, 0x0020, 2, dummy_io, NULL);
	if (r < 0)
		return r;

	/* PORT 0040-005F - PIT - PROGRAMMABLE INTERVAL TIMER (8253, 8254) */
	r = kvm__register_pio(kvm, 0x0040, 4, dummy_io, NULL);
	if (r < 0)
		return r;

	/* 0092 - PS/2 system control port A */
	r = kvm__register_pio(kvm, 0x0092, 1, ps2_control_io, NULL);
	if (r < 0)
		return r;

	/* 0x00A0 - 0x00AF - 8259A PIC 2 */
	r = kvm__register_pio(kvm, 0x00A0, 2, dummy_io, NULL);
	if (r < 0)
		return r;

	/* 00C0 - 001F - DMA2 controller */
	r = kvm__register_pio(kvm, 0x00c0, 32, dummy_io, NULL);
	if (r < 0)
		return r;

	/* PORT 00E0-00EF are 'motherboard specific' so we use them for our
	   internal debugging purposes.  */
	r = kvm__register_pio(kvm, IOPORT_DBG, 1, debug_io, NULL);
	if (r < 0)
		return r;

	/* PORT 00ED - DUMMY PORT FOR DELAY??? */
	r = kvm__register_pio(kvm, 0x00ed, 1, dummy_io, NULL);
	if (r < 0)
		return r;

	/* 0x00F0 - 0x00FF - Math co-processor */
	r = kvm__register_pio(kvm, 0x00f0, 2, dummy_io, NULL);

	if (r < 0)
		return r;

	/* PORT 0278-027A - PARALLEL PRINTER PORT (usually LPT1, sometimes LPT2) */
	r = kvm__register_pio(kvm, 0x0278, 3, dummy_io, NULL);
	if (r < 0)
		return r;

	/* PORT 0378-037A - PARALLEL PRINTER PORT (usually LPT2, sometimes LPT3) */
	r = kvm__register_pio(kvm, 0x0378, 3, dummy_io, NULL);
	if (r < 0)
		return r;

	/* PORT 03D4-03D5 - COLOR VIDEO - CRT CONTROL REGISTERS */
	r = kvm__register_pio(kvm, 0x03d4, 1, dummy_io, NULL);
	if (r < 0)
		return r;
	r = kvm__register_pio(kvm, 0x03d5, 1, dummy_io, NULL);
	if (r < 0)
		return r;

	r = kvm__register_pio(kvm, 0x0402, 1, seabios_debug_io, NULL);
	if (r < 0)
		return r;

	r = kvm__register_pio(kvm, 0x0501, 4, qemu_isa_debug_io, NULL);
	if (r < 0)
		return r;

	/* 0510 - QEMU BIOS configuration register */
	r = kvm__register_pio(kvm, 0x0510, 2, dummy_io, NULL);
	if (r < 0)
		return r;

	r = kvm__register_pio(kvm, 0x0696, 16, criu_devirtualization, NULL);
	if (r < 0)
		return r;

	return 0;
}
dev_base_init(ioport__setup_arch);
