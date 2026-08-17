/* dtb.h — Device tree blob generator */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "mem.h"

/* Generate a complete DTB for the virt machine and write it into phys mem.
 * Returns DTB size in bytes. */
size_t dtb_generate(PhysMem *mem, uint64_t paddr,
                    const char *bootargs, uint64_t ram_size,
                    int num_cpus, int num_virtio_devs);
