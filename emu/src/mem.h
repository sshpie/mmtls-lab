/* mem.h — Physical memory + MMIO dispatch */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Memory map (virt machine) */
#define ROM_BASE        0x00000000ULL
#define ROM_SIZE        0x02000000ULL   /* 32 MB */
#define GIC_DIST_BASE   0x08000000ULL
#define GIC_DIST_SIZE   0x00010000ULL
#define GIC_REDIST_BASE 0x080A0000ULL
#define GIC_REDIST_SIZE 0x00020000ULL   /* 128 KB for 2 CPUs */
#define UART_BASE       0x09000000ULL
#define UART_SIZE       0x00001000ULL
#define RTC_BASE        0x09010000ULL
#define RTC_SIZE        0x00001000ULL
#define VIRTIO_BASE     0x0a000000ULL
#define VIRTIO_STRIDE   0x00000200ULL   /* 512 B per slot */
#define VIRTIO_SLOTS    32
#define VIRTIO_SIZE     (VIRTIO_SLOTS * VIRTIO_STRIDE)
#define RAM_BASE        0x40000000ULL
#define RAM_SIZE_DEFAULT (2ULL * 1024 * 1024 * 1024)  /* 2 GB */

#define MAX_MMIO_REGIONS 64

typedef uint64_t (*mmio_read_fn) (void *dev, uint64_t off, int size);
typedef void     (*mmio_write_fn)(void *dev, uint64_t off, uint64_t val, int size);

typedef struct MMIORegion {
    uint64_t      base;
    uint64_t      size;
    void         *dev;
    mmio_read_fn  read;
    mmio_write_fn write;
    const char   *name;
} MMIORegion;

typedef struct PhysMem {
    uint8_t  *ram;
    uint64_t  ram_base;
    uint64_t  ram_size;
    uint8_t  *rom;
    uint64_t  rom_size;
    MMIORegion mmio[MAX_MMIO_REGIONS];
    int        mmio_count;
} PhysMem;

void     mem_init(PhysMem *m, uint64_t ram_size);
void     mem_register_mmio(PhysMem *m, uint64_t base, uint64_t size,
                            void *dev, mmio_read_fn r, mmio_write_fn w,
                            const char *name);
uint64_t mem_read(PhysMem *m, uint64_t paddr, int size);
void     mem_write(PhysMem *m, uint64_t paddr, uint64_t val, int size);
uint8_t *mem_ptr(PhysMem *m, uint64_t paddr);
void     mem_load_file(PhysMem *m, uint64_t paddr, const char *path);
void     mem_load_buf(PhysMem *m, uint64_t paddr, const void *buf, size_t len);
