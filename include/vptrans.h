#ifndef VPTRANS_H
#define VPTRANS_H

#include <linux/types.h>

struct vptrans_pin {
	u64 vaddr;
	u64 kvm_addr;
	u64 off;
	u64 nr_page;
};

#define VPTRANS_IOCTL_PIN _IOW(VPTRANS_IOCTL_NR, 0xc0, struct vptrans_pin)
#endif