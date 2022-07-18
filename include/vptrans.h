#ifndef VPTRANS_H
#define VPTRANS_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define VPTRANS_IOCTL_NR 0xf1

struct vptrans_pin {
	void *vaddr;
	void *kvm_addr;
	u64 off;
	u64 nr_page;
};

#define VPTRANS_IOCTL_PIN _IOW(VPTRANS_IOCTL_NR, 0xc0, struct vptrans_pin)
#endif