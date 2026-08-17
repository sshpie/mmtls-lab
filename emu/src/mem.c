/* mem.c — Physical memory + MMIO dispatch implementation */
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

void mem_init(PhysMem *m, uint64_t ram_size) {
    memset(m, 0, sizeof(*m));

    m->rom_size = ROM_SIZE;
    m->rom = calloc(1, ROM_SIZE);
    if (!m->rom) { perror("calloc rom"); exit(1); }

    m->ram_base = RAM_BASE;
    m->ram_size = ram_size ? ram_size : RAM_SIZE_DEFAULT;
    m->ram = mmap(NULL, m->ram_size, PROT_READ|PROT_WRITE,
                  MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (m->ram == MAP_FAILED) { perror("mmap ram"); exit(1); }
}

void mem_register_mmio(PhysMem *m, uint64_t base, uint64_t size,
                        void *dev, mmio_read_fn r, mmio_write_fn w,
                        const char *name) {
    if (m->mmio_count >= MAX_MMIO_REGIONS) {
        fprintf(stderr, "mem: too many MMIO regions\n");
        return;
    }
    MMIORegion *reg = &m->mmio[m->mmio_count++];
    reg->base  = base;
    reg->size  = size;
    reg->dev   = dev;
    reg->read  = r;
    reg->write = w;
    reg->name  = name;
}

static MMIORegion *mmio_find(PhysMem *m, uint64_t paddr) {
    for (int i = 0; i < m->mmio_count; i++) {
        MMIORegion *r = &m->mmio[i];
        if (paddr >= r->base && paddr < r->base + r->size)
            return r;
    }
    return NULL;
}

uint64_t mem_read(PhysMem *m, uint64_t paddr, int size) {
    /* ROM */
    if (paddr < m->rom_size) {
        uint64_t v = 0;
        memcpy(&v, m->rom + paddr, size);
        return v;
    }
    /* RAM */
    if (paddr >= m->ram_base && paddr + size <= m->ram_base + m->ram_size) {
        uint64_t v = 0;
        memcpy(&v, m->ram + (paddr - m->ram_base), size);
        return v;
    }
    /* MMIO */
    MMIORegion *r = mmio_find(m, paddr);
    if (r && r->read)
        return r->read(r->dev, paddr - r->base, size);
    fprintf(stderr, "mem: unmapped read  paddr=0x%016llx size=%d\n",
            (unsigned long long)paddr, size);
    return 0;
}

void mem_write(PhysMem *m, uint64_t paddr, uint64_t val, int size) {
    /* ROM — writes silently ignored */
    if (paddr < m->rom_size)
        return;
    /* RAM */
    if (paddr >= m->ram_base && paddr + size <= m->ram_base + m->ram_size) {
        /* Watchpoint: init_task.cgroups at PA 0x41c5e428 */
        if (paddr <= 0x41c5e428ULL && paddr + size > 0x41c5e428ULL) {
            static int wp_count = 0;
            if (++wp_count <= 4)
                fprintf(stderr, "[WP-CGROUPS] write PA=0x%llx val=0x%llx size=%d\n",
                        (unsigned long long)paddr, (unsigned long long)val, size);
        }
        memcpy(m->ram + (paddr - m->ram_base), &val, size);
        return;
    }
    /* MMIO */
    MMIORegion *r = mmio_find(m, paddr);
    if (r && r->write) {
        r->write(r->dev, paddr - r->base, val, size);
        return;
    }
    fprintf(stderr, "mem: unmapped write paddr=0x%016llx val=0x%016llx size=%d\n",
            (unsigned long long)paddr, (unsigned long long)val, size);
}

uint8_t *mem_ptr(PhysMem *m, uint64_t paddr) {
    if (paddr < m->rom_size)
        return m->rom + paddr;
    if (paddr >= m->ram_base && paddr < m->ram_base + m->ram_size)
        return m->ram + (paddr - m->ram_base);
    return NULL;
}

void mem_load_buf(PhysMem *m, uint64_t paddr, const void *buf, size_t len) {
    uint8_t *dst = mem_ptr(m, paddr);
    if (!dst) {
        fprintf(stderr, "mem: load_buf: paddr 0x%llx not in RAM/ROM\n",
                (unsigned long long)paddr);
        return;
    }
    memcpy(dst, buf, len);
}

void mem_load_file(PhysMem *m, uint64_t paddr, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); exit(1); }

    struct stat st;
    fstat(fd, &st);
    size_t size = (size_t)st.st_size;

    uint8_t *dst = mem_ptr(m, paddr);
    if (!dst) {
        fprintf(stderr, "mem: load_file %s: paddr 0x%llx not in RAM/ROM\n",
                path, (unsigned long long)paddr);
        close(fd);
        return;
    }

    size_t off = 0;
    while (off < size) {
        ssize_t n = read(fd, dst + off, size - off);
        if (n <= 0) break;
        off += n;
    }
    close(fd);
    fprintf(stderr, "mem: loaded %s (%zu bytes) at 0x%llx\n",
            path, size, (unsigned long long)paddr);
}
