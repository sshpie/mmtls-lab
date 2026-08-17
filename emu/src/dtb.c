/* dtb.c — Minimal hand-rolled FDT/DTB builder for ARM64 virt machine */
#include "mem.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <endian.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#else
#include <endian.h>
#endif

#define FDT_MAGIC       0xd00dfeed
#define FDT_BEGIN_NODE  0x00000001
#define FDT_END_NODE    0x00000002
#define FDT_PROP        0x00000003
#define FDT_NOP         0x00000004
#define FDT_END         0x00000009

/* GIC interrupt type codes (as used in DT interrupt cells) */
#define GIC_SPI  0
#define GIC_PPI  1

/* Interrupt flags */
#define IRQ_TYPE_EDGE_RISING   1
#define IRQ_TYPE_LEVEL_HIGH    4
#define IRQ_TYPE_LEVEL_LOW     8

#define DTB_STRUCT_MAX  (128 * 1024)
#define DTB_STRINGS_MAX (16 * 1024)

typedef struct {
    uint8_t  *struct_buf;
    size_t    struct_off;
    char     *strings_buf;
    size_t    strings_off;
} DTBBuilder;

/* --- struct block helpers --- */

static void sb_align(DTBBuilder *b) {
    while (b->struct_off & 3) b->struct_buf[b->struct_off++] = 0;
}

static void sb_u32(DTBBuilder *b, uint32_t v) {
    uint32_t be = htobe32(v);
    memcpy(b->struct_buf + b->struct_off, &be, 4);
    b->struct_off += 4;
}

static void sb_bytes(DTBBuilder *b, const void *data, size_t len) {
    memcpy(b->struct_buf + b->struct_off, data, len);
    b->struct_off += len;
}

/* --- string table --- */

static uint32_t str_offset(DTBBuilder *b, const char *name) {
    /* Search for existing */
    size_t off = 0;
    while (off < b->strings_off) {
        if (strcmp(b->strings_buf + off, name) == 0) return (uint32_t)off;
        off += strlen(b->strings_buf + off) + 1;
    }
    uint32_t ret = (uint32_t)b->strings_off;
    size_t len = strlen(name) + 1;
    memcpy(b->strings_buf + b->strings_off, name, len);
    b->strings_off += len;
    return ret;
}

/* --- node/property emitters --- */

static void dtb_begin_node(DTBBuilder *b, const char *name) {
    sb_u32(b, FDT_BEGIN_NODE);
    size_t len = strlen(name) + 1;
    sb_bytes(b, name, len);
    sb_align(b);
}

static void dtb_end_node(DTBBuilder *b) {
    sb_u32(b, FDT_END_NODE);
}

static void dtb_prop_raw(DTBBuilder *b, const char *name,
                          const void *data, uint32_t len) {
    sb_u32(b, FDT_PROP);
    sb_u32(b, len);
    sb_u32(b, str_offset(b, name));
    if (len) sb_bytes(b, data, len);
    sb_align(b);
}

static void dtb_prop_u32(DTBBuilder *b, const char *name, uint32_t val) {
    uint32_t be = htobe32(val);
    dtb_prop_raw(b, name, &be, 4);
}

static void dtb_prop_u64(DTBBuilder *b, const char *name, uint64_t val) {
    uint32_t cells[2] = { htobe32((uint32_t)(val >> 32)),
                           htobe32((uint32_t)val) };
    dtb_prop_raw(b, name, cells, 8);
}

static void dtb_prop_str(DTBBuilder *b, const char *name, const char *val) {
    dtb_prop_raw(b, name, val, (uint32_t)(strlen(val) + 1));
}

static void dtb_prop_str_list(DTBBuilder *b, const char *name,
                               const char **vals, int n) {
    /* Compute total length */
    size_t total = 0;
    for (int i = 0; i < n; i++) total += strlen(vals[i]) + 1;
    uint8_t *tmp = malloc(total);
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        size_t l = strlen(vals[i]) + 1;
        memcpy(tmp + off, vals[i], l);
        off += l;
    }
    dtb_prop_raw(b, name, tmp, (uint32_t)total);
    free(tmp);
}

static void dtb_prop_empty(DTBBuilder *b, const char *name) {
    dtb_prop_raw(b, name, NULL, 0);
}

/* Write #address-cells + #size-cells + reg (2+2 cell format) */
static void dtb_prop_reg2(DTBBuilder *b, uint64_t addr, uint64_t size) {
    uint32_t cells[4] = {
        htobe32((uint32_t)(addr >> 32)), htobe32((uint32_t)addr),
        htobe32((uint32_t)(size >> 32)), htobe32((uint32_t)size)
    };
    dtb_prop_raw(b, "reg", cells, 16);
}

/* Single 3-cell interrupt (GIC format) */
static void dtb_irq_one(DTBBuilder *b, uint32_t type, uint32_t num, uint32_t flags) {
    uint32_t cells[3] = { htobe32(type), htobe32(num), htobe32(flags) };
    dtb_prop_raw(b, "interrupts", cells, 12);
}

/* Multiple 3-cell interrupts */
static void dtb_irqs(DTBBuilder *b, const uint32_t (*irqs)[3], int n) {
    uint32_t *tmp = malloc(n * 3 * 4);
    for (int i = 0; i < n; i++) {
        tmp[i*3+0] = htobe32(irqs[i][0]);
        tmp[i*3+1] = htobe32(irqs[i][1]);
        tmp[i*3+2] = htobe32(irqs[i][2]);
    }
    dtb_prop_raw(b, "interrupts", tmp, n * 12);
    free(tmp);
}

/* ------------------------------------------------------------------ */

static size_t build_dtb(uint8_t *out, size_t out_cap,
                         const char *bootargs, uint64_t ram_size,
                         int num_cpus, int num_virtio_devs)
{
    DTBBuilder b = {0};
    b.struct_buf  = malloc(DTB_STRUCT_MAX);
    b.strings_buf = malloc(DTB_STRINGS_MAX);

    /* ---- root node ---- */
    dtb_begin_node(&b, "");
    {
        const char *compat[] = { "linux,dummy-virt" };
        dtb_prop_str_list(&b, "compatible", compat, 1);
        dtb_prop_u32(&b, "#address-cells", 2);
        dtb_prop_u32(&b, "#size-cells", 2);
        dtb_prop_u32(&b, "interrupt-parent", 1); /* phandle 1 = GIC */

        /* /chosen */
        dtb_begin_node(&b, "chosen");
        dtb_prop_str(&b, "bootargs", bootargs);
        dtb_prop_str(&b, "stdout-path", "/pl011@9000000");
        dtb_end_node(&b);

        /* /memory */
        dtb_begin_node(&b, "memory@40000000");
        dtb_prop_str(&b, "device_type", "memory");
        dtb_prop_reg2(&b, 0x40000000ULL, ram_size);
        dtb_end_node(&b);

        /* /cpus */
        dtb_begin_node(&b, "cpus");
        dtb_prop_u32(&b, "#address-cells", 1);
        dtb_prop_u32(&b, "#size-cells", 0);
        for (int c = 0; c < num_cpus; c++) {
            char node_name[32];
            snprintf(node_name, sizeof(node_name), "cpu@%x", c);
            dtb_begin_node(&b, node_name);
            dtb_prop_str(&b, "device_type", "cpu");
            const char *cpu_compat[] = { "arm,cortex-a76" };
            dtb_prop_str_list(&b, "compatible", cpu_compat, 1);
            dtb_prop_str(&b, "enable-method", "psci");
            dtb_prop_u32(&b, "reg", c);
            dtb_end_node(&b);
        }
        dtb_end_node(&b);

        /* /psci */
        dtb_begin_node(&b, "psci");
        {
            const char *pc[] = { "arm,psci-1.0", "arm,psci-0.2", "arm,psci" };
            dtb_prop_str_list(&b, "compatible", pc, 3);
        }
        dtb_prop_str(&b, "method", "hvc");
        /* PSCI function IDs (PSCI 0.2 standard) */
        dtb_prop_u32(&b, "cpu_suspend",   0xc4000001);
        dtb_prop_u32(&b, "cpu_off",       0x84000002);
        dtb_prop_u32(&b, "cpu_on",        0xc4000003);
        dtb_prop_u32(&b, "migrate",       0xc4000005);
        dtb_end_node(&b);

        /* /gic — GICv3, phandle=1 */
        dtb_begin_node(&b, "gic@8000000");
        {
            const char *gc[] = { "arm,gic-v3" };
            dtb_prop_str_list(&b, "compatible", gc, 1);
        }
        dtb_prop_u32(&b, "phandle", 1);
        dtb_prop_u32(&b, "linux,phandle", 1);
        dtb_prop_empty(&b, "interrupt-controller");
        dtb_prop_u32(&b, "#interrupt-cells", 3);
        dtb_prop_u32(&b, "#address-cells", 2);
        dtb_prop_u32(&b, "#size-cells", 2);
        /* reg: GICD + GICR (num_cpus * 0x20000) */
        {
            uint32_t regcells[8] = {
                htobe32(0), htobe32(0x08000000), htobe32(0), htobe32(0x00010000),
                htobe32(0), htobe32(0x080A0000), htobe32(0),
                    htobe32(0x00020000 * num_cpus)
            };
            dtb_prop_raw(&b, "reg", regcells, 32);
        }
        dtb_end_node(&b);

        /* /timer — ARM generic timer */
        dtb_begin_node(&b, "timer");
        {
            const char *tc[] = { "arm,armv8-timer" };
            dtb_prop_str_list(&b, "compatible", tc, 1);
        }
        dtb_prop_empty(&b, "always-on");
        {
            /* PPI 13 (EL1 phys), PPI 14 (EL1 virt), PPI 11 (EL3 phys), PPI 10 (EL2 phys) */
            const uint32_t irqs[4][3] = {
                {GIC_PPI, 13, IRQ_TYPE_LEVEL_LOW},
                {GIC_PPI, 14, IRQ_TYPE_LEVEL_LOW},
                {GIC_PPI, 11, IRQ_TYPE_LEVEL_LOW},
                {GIC_PPI, 10, IRQ_TYPE_LEVEL_LOW},
            };
            dtb_irqs(&b, irqs, 4);
        }
        dtb_end_node(&b);

        /* /pl011 UART */
        dtb_begin_node(&b, "pl011@9000000");
        {
            const char *uc[] = { "arm,pl011", "arm,primecell" };
            dtb_prop_str_list(&b, "compatible", uc, 2);
        }
        dtb_prop_reg2(&b, 0x09000000ULL, 0x1000ULL);
        /* SPI 33 → Linux irq 33, which is SPI 1 (offset 32) */
        dtb_irq_one(&b, GIC_SPI, 1, IRQ_TYPE_LEVEL_HIGH);
        dtb_prop_u32(&b, "clocks", 0);  /* dummy */
        dtb_prop_u32(&b, "clock-names", 0);
        dtb_end_node(&b);

        /* /virtio-mmio nodes: SPI starts at 16 (GIC SPI 16 = Linux irq 48) */
        for (int i = 0; i < num_virtio_devs && i < 32; i++) {
            uint64_t virt_base = 0x0a000000ULL + (uint64_t)i * 0x200;
            char vnode[32];
            snprintf(vnode, sizeof(vnode), "virtio_mmio@%llx",
                     (unsigned long long)virt_base);
            dtb_begin_node(&b, vnode);
            {
                const char *vc[] = { "virtio,mmio" };
                dtb_prop_str_list(&b, "compatible", vc, 1);
            }
            dtb_prop_reg2(&b, virt_base, 0x200ULL);
            dtb_irq_one(&b, GIC_SPI, 16 + i, IRQ_TYPE_EDGE_RISING);
            dtb_end_node(&b);
        }
    }
    dtb_end_node(&b);  /* root end */
    sb_u32(&b, FDT_END);

    /* ---- Assemble final DTB ---- */
    size_t hdr_size    = 10 * 4;
    size_t rsvmap_size = 16;  /* one null entry: (0,0) */
    size_t total = hdr_size + rsvmap_size + b.struct_off + b.strings_off;

    if (total > out_cap) {
        fprintf(stderr, "dtb: buffer too small (%zu > %zu)\n", total, out_cap);
        free(b.struct_buf); free(b.strings_buf);
        return 0;
    }

    memset(out, 0, total);

    uint32_t off_rsvmap = (uint32_t)hdr_size;
    uint32_t off_struct  = off_rsvmap + (uint32_t)rsvmap_size;
    uint32_t off_strings = off_struct + (uint32_t)b.struct_off;

    uint32_t *hdr = (uint32_t*)out;
    hdr[0] = htobe32(FDT_MAGIC);
    hdr[1] = htobe32((uint32_t)total);
    hdr[2] = htobe32(off_struct);
    hdr[3] = htobe32(off_strings);
    hdr[4] = htobe32(off_rsvmap);
    hdr[5] = htobe32(17);   /* version */
    hdr[6] = htobe32(16);   /* last_comp_version */
    hdr[7] = htobe32(0);    /* boot_cpuid_phys */
    hdr[8] = htobe32((uint32_t)b.strings_off);
    hdr[9] = htobe32((uint32_t)b.struct_off);

    /* rsvmap: null terminator */
    memset(out + off_rsvmap, 0, rsvmap_size);

    /* struct block */
    memcpy(out + off_struct, b.struct_buf, b.struct_off);

    /* strings block */
    memcpy(out + off_strings, b.strings_buf, b.strings_off);

    free(b.struct_buf);
    free(b.strings_buf);
    return total;
}

size_t dtb_generate(PhysMem *mem, uint64_t paddr,
                    const char *bootargs, uint64_t ram_size,
                    int num_cpus, int num_virtio_devs)
{
    static uint8_t dtb_buf[256 * 1024];
    size_t sz = build_dtb(dtb_buf, sizeof(dtb_buf),
                           bootargs, ram_size, num_cpus, num_virtio_devs);
    if (sz == 0) return 0;
    mem_load_buf(mem, paddr, dtb_buf, sz);
    return sz;
}
