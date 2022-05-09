#ifndef VPTRANS_H
#define VPTRANS_H

#include <linux/types.h>

struct vptrans_pin {
	uintptr_t vaddr;
	u64 off;
	u64 nr_page;
};

#endif
