/* dev_gic.h — GICv3 interrupt controller */
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define GIC_NUM_SPI   256   /* shared peripheral interrupts */
#define GIC_NUM_PPI   16    /* private peripheral interrupts per CPU */
#define GIC_NUM_SGI   16    /* software generated interrupts */
#define GIC_NUM_IRQS  (GIC_NUM_SGI + GIC_NUM_PPI + GIC_NUM_SPI)

/* GICv3 memory map (virt machine):
 *   Distributor:   0x08000000  (64KB)
 *   Redistributor: 0x080A0000  (128KB per CPU, stride 2 * 64KB)
 */
#define GICD_BASE   0x08000000ULL
#define GICD_SIZE   0x00010000ULL
#define GICR_BASE   0x080A0000ULL
#define GICR_STRIDE 0x00020000ULL   /* 128KB per RD frame */

/* GIC Distributor register offsets */
#define GICD_CTLR       0x0000
#define GICD_TYPER      0x0004
#define GICD_IIDR       0x0008
#define GICD_IGROUPR    0x0080   /* [0..31], bit per SPI */
#define GICD_ISENABLER  0x0100
#define GICD_ICENABLER  0x0180
#define GICD_ISPENDR    0x0200
#define GICD_ICPENDR    0x0280
#define GICD_ISACTIVER  0x0300
#define GICD_ICACTIVER  0x0380
#define GICD_IPRIORITYR 0x0400   /* byte per interrupt */
#define GICD_ITARGETSR  0x0800   /* byte per SPI, CPU target mask */
#define GICD_ICFGR      0x0C00   /* 2 bits per interrupt */
#define GICD_IROUTER    0x6000   /* 64-bit per SPI */

/* GIC Redistributor LP register offsets */
#define GICR_CTLR       0x0000
#define GICR_TYPER      0x0008
#define GICR_WAKER      0x0014

/* SGI/PPI bank in redistributor (offset 0x10000 from RD base) */
#define GICR_IGROUPR0   0x10080
#define GICR_ISENABLER0 0x10100
#define GICR_ICENABLER0 0x10180
#define GICR_ISPENDR0   0x10200
#define GICR_ICPENDR0   0x10280
#define GICR_IPRIORITYR 0x10400
#define GICR_ICFGR0     0x10C00

typedef struct GICState {
    /* Distributor */
    uint32_t gicd_ctlr;
    uint32_t enabled[GIC_NUM_IRQS / 32];   /* enable bits */
    uint32_t pending[GIC_NUM_IRQS / 32];   /* pending bits */
    uint32_t active[GIC_NUM_IRQS / 32];    /* active bits */
    uint32_t group[GIC_NUM_IRQS / 32];     /* group (0=G0, 1=G1) */
    uint8_t  priority[GIC_NUM_IRQS];       /* priority per irq */
    uint8_t  target[GIC_NUM_IRQS];         /* CPU target (SPI only) */
    uint64_t irouter[GIC_NUM_IRQS];        /* affinity routing */
    uint32_t cfg[GIC_NUM_IRQS / 16];       /* level/edge config */

    /* Per-CPU redistributor */
    struct {
        uint32_t ctlr;
        uint32_t waker;
        uint32_t igrp0;
        uint32_t isen0;   /* SGI/PPI enables */
        uint32_t ipend0;  /* SGI/PPI pending */
        uint8_t  prio[GIC_NUM_SGI + GIC_NUM_PPI];
    } rd[4];   /* 4 CPUs */

    /* CPU interface (per CPU, via system registers) */
    struct {
        uint32_t icc_pmr;   /* priority mask */
        uint32_t icc_bpr;   /* binary point */
        uint32_t icc_ctlr;
        uint32_t icc_sre;
        uint32_t icc_igrpen1;
        uint32_t running_irq;  /* currently active irq (or 1023) */
    } cpu[4];

    int num_cpus;

    /* Callback to signal IRQ line to CPU */
    void (*signal_irq)(void *opaque, int cpu_id, bool level);
    void *opaque;
} GICState;

void    gic_init(GICState *g, int num_cpus,
                 void (*signal_irq)(void *opaque, int cpu_id, bool level),
                 void *opaque);
void    gic_set_irq(GICState *g, int irq, bool level);  /* raise/lower SPI */
uint32_t gic_cpu_read_iar(GICState *g, int cpu);        /* acknowledge IRQ */
void    gic_cpu_write_eoir(GICState *g, int cpu, uint32_t irq);

/* MMIO handlers */
uint64_t gicd_read(void *dev, uint64_t off, int size);
void     gicd_write(void *dev, uint64_t off, uint64_t val, int size);
uint64_t gicr_read(void *dev, uint64_t off, int size);  /* dev = GICState* */
void     gicr_write(void *dev, uint64_t off, uint64_t val, int size);

/* System register interface (called from CPU sysreg read/write) */
uint64_t gic_sysreg_read(GICState *g, int cpu, uint32_t sysreg_key);
void     gic_sysreg_write(GICState *g, int cpu, uint32_t sysreg_key, uint64_t val);

/* Find best pending+enabled IRQ for a CPU (-1 if none) */
int      gic_find_best_irq_for_cpu(GICState *g, int cpu);
