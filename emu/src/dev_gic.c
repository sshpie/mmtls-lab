/* dev_gic.c — GICv3 interrupt controller */
#include "dev_gic.h"
#include "arm64.h"
#include <string.h>
#include <stdio.h>

#define IRQ_NONE 1023

void gic_init(GICState *g, int num_cpus,
              void (*signal_irq)(void *opaque, int cpu_id, bool level),
              void *opaque)
{
    memset(g, 0, sizeof(*g));
    g->num_cpus   = num_cpus;
    g->signal_irq = signal_irq;
    g->opaque     = opaque;

    /* All IRQs start at group 1, priority 0xa0, disabled, not pending */
    for (int i = 0; i < GIC_NUM_IRQS; i++) {
        g->priority[i] = 0xa0;
    }
    for (int i = 0; i < GIC_NUM_IRQS / 32; i++) {
        g->group[i] = 0xffffffff;   /* all group 1 */
    }

    for (int c = 0; c < num_cpus; c++) {
        g->cpu[c].icc_pmr      = 0xff;   /* accept all */
        g->cpu[c].icc_bpr      = 0;
        g->cpu[c].icc_sre      = 0x7;    /* SRE enabled */
        g->cpu[c].icc_igrpen1  = 1;      /* G1 enabled */
        g->cpu[c].running_irq  = IRQ_NONE;
        g->rd[c].igrp0         = 0xffffffff;
    }
}

/* Find highest-priority pending+enabled IRQ for a CPU */
static int gic_find_best_irq(GICState *g, int cpu)
{
    int best = IRQ_NONE;
    uint8_t best_prio = 0xff;

    for (int i = 0; i < GIC_NUM_IRQS; i++) {
        int word = i / 32, bit = i % 32;

        /* Check enabled */
        uint32_t en;
        if (i < 32) {
            /* SGI/PPI — per-CPU in redistributor */
            en = g->rd[cpu].isen0;
        } else {
            en = g->enabled[word];
        }
        if (!(en & (1u << bit))) continue;

        /* Check pending */
        uint32_t pend;
        if (i < 32) {
            pend = g->rd[cpu].ipend0;
        } else {
            pend = g->pending[word];
        }
        if (!(pend & (1u << bit))) continue;

        /* Check target / affinity (SPI only) */
        if (i >= 32) {
            uint64_t aff = g->irouter[i];
            if (!(aff & (1ULL << 31))) {  /* not broadcast */
                /* Check if CPU is targeted */
                int tgt_cpu = aff & 0xff;   /* Aff0 → CPU id */
                if (tgt_cpu != cpu) continue;
            }
        }

        uint8_t prio = (i < 32) ? g->rd[cpu].prio[i] : g->priority[i];
        if (prio < best_prio) {
            best_prio = prio;
            best = i;
        }
    }
    return best;
}

static void gic_update(GICState *g)
{
    for (int c = 0; c < g->num_cpus; c++) {
        int best = gic_find_best_irq(g, c);
        bool has_irq = (best != IRQ_NONE) && g->cpu[c].icc_igrpen1;
        if (g->signal_irq)
            g->signal_irq(g->opaque, c, has_irq);
    }
}

void gic_set_irq(GICState *g, int irq, bool level)
{
    if (irq < 0 || irq >= GIC_NUM_IRQS) return;
    int word = irq / 32, bit = irq % 32;
    if (level) {
        if (irq < 32) {
            for (int c = 0; c < g->num_cpus; c++)
                g->rd[c].ipend0 |= (1u << bit);
        } else {
            g->pending[word] |= (1u << bit);
        }
    } else {
        if (irq < 32) {
            for (int c = 0; c < g->num_cpus; c++)
                g->rd[c].ipend0 &= ~(1u << bit);
        } else {
            g->pending[word] &= ~(1u << bit);
        }
    }
    gic_update(g);
}

uint32_t gic_cpu_read_iar(GICState *g, int cpu)
{
    if (cpu < 0 || cpu >= g->num_cpus) return IRQ_NONE;
    int irq = gic_find_best_irq(g, cpu);
    if (irq == IRQ_NONE) return IRQ_NONE;

    /* Mark active, clear pending */
    int word = irq / 32, bit = irq % 32;
    if (irq < 32) {
        g->rd[cpu].ipend0 &= ~(1u << bit);
    } else {
        g->pending[word]  &= ~(1u << bit);
        g->active[word]   |=  (1u << bit);
    }
    g->cpu[cpu].running_irq = irq;
    gic_update(g);
    return irq;
}

void gic_cpu_write_eoir(GICState *g, int cpu, uint32_t irq)
{
    if (irq >= GIC_NUM_IRQS) return;
    int word = irq / 32, bit = irq % 32;
    if (irq >= 32)
        g->active[word] &= ~(1u << bit);
    g->cpu[cpu].running_irq = IRQ_NONE;
    gic_update(g);
}

/* --- GICD MMIO --- */

uint64_t gicd_read(void *dev, uint64_t off, int size)
{
    GICState *g = dev;
    (void)size;

    if (off == GICD_CTLR)  return g->gicd_ctlr;
    if (off == GICD_TYPER) return ((GIC_NUM_IRQS / 32) - 1) | (g->num_cpus << 5);
    if (off == GICD_IIDR)  return 0x0043B;

    if (off >= GICD_IGROUPR  && off < GICD_IGROUPR  + GIC_NUM_IRQS/8)
        return g->group[(off-GICD_IGROUPR)/4];
    if (off >= GICD_ISENABLER && off < GICD_ISENABLER + GIC_NUM_IRQS/8)
        return g->enabled[(off-GICD_ISENABLER)/4];
    if (off >= GICD_ICENABLER && off < GICD_ICENABLER + GIC_NUM_IRQS/8)
        return g->enabled[(off-GICD_ICENABLER)/4];
    if (off >= GICD_ISPENDR  && off < GICD_ISPENDR  + GIC_NUM_IRQS/8)
        return g->pending[(off-GICD_ISPENDR)/4];
    if (off >= GICD_IPRIORITYR && off < GICD_IPRIORITYR + GIC_NUM_IRQS) {
        uint32_t v = 0;
        int base = off - GICD_IPRIORITYR;
        for (int i = 0; i < 4; i++) v |= (uint32_t)g->priority[base+i] << (i*8);
        return v;
    }
    if (off >= GICD_IROUTER && off < GICD_IROUTER + GIC_NUM_SPI*8) {
        int irq = (off - GICD_IROUTER) / 8 + 32;
        if (irq < GIC_NUM_IRQS) return g->irouter[irq];
    }
    return 0;
}

void gicd_write(void *dev, uint64_t off, uint64_t val, int size)
{
    GICState *g = dev;
    (void)size;

    if (off == GICD_CTLR) { g->gicd_ctlr = val; gic_update(g); return; }

    if (off >= GICD_IGROUPR && off < GICD_IGROUPR + GIC_NUM_IRQS/8) {
        g->group[(off-GICD_IGROUPR)/4] = val; return; }
    if (off >= GICD_ISENABLER && off < GICD_ISENABLER + GIC_NUM_IRQS/8) {
        g->enabled[(off-GICD_ISENABLER)/4] |= val; gic_update(g); return; }
    if (off >= GICD_ICENABLER && off < GICD_ICENABLER + GIC_NUM_IRQS/8) {
        g->enabled[(off-GICD_ICENABLER)/4] &= ~val; gic_update(g); return; }
    if (off >= GICD_ISPENDR && off < GICD_ISPENDR + GIC_NUM_IRQS/8) {
        g->pending[(off-GICD_ISPENDR)/4] |= val; gic_update(g); return; }
    if (off >= GICD_ICPENDR && off < GICD_ICPENDR + GIC_NUM_IRQS/8) {
        g->pending[(off-GICD_ICPENDR)/4] &= ~val; gic_update(g); return; }
    if (off >= GICD_IPRIORITYR && off < GICD_IPRIORITYR + GIC_NUM_IRQS) {
        int base = off - GICD_IPRIORITYR;
        for (int i = 0; i < 4; i++)
            g->priority[base+i] = (val >> (i*8)) & 0xff;
        return;
    }
    if (off >= GICD_IROUTER && off < GICD_IROUTER + GIC_NUM_SPI*8) {
        int irq = (off - GICD_IROUTER) / 8 + 32;
        if (irq < GIC_NUM_IRQS) {
            g->irouter[irq] = val;
            gic_update(g);
        }
        return;
    }
}

/* --- GICR MMIO --- */

uint64_t gicr_read(void *dev, uint64_t off, int size)
{
    GICState *g = dev;
    (void)size;

    /* Determine which CPU redistributor this offset maps to */
    int cpu = off / GICR_STRIDE;
    uint64_t local_off = off % GICR_STRIDE;

    if (cpu >= g->num_cpus) return 0;

    /* LP frame (low 64KB) */
    if (local_off < 0x10000) {
        switch (local_off) {
        case GICR_CTLR: return g->rd[cpu].ctlr;
        case GICR_TYPER:
            /* Aff0 at bits[39:32], Processor_Number at bits[23:8], Last at bit[4] */
            return ((uint64_t)cpu << 32) |
                   ((uint64_t)cpu << 8)  |
                   (cpu == g->num_cpus-1 ? (1ULL << 4) : 0);
        case GICR_WAKER: return g->rd[cpu].waker;
        default: return 0;
        }
    }

    /* SGI frame (64KB-128KB) */
    local_off -= 0x10000;
    if (local_off == 0x80)  return g->rd[cpu].igrp0;
    if (local_off == 0x100) return g->rd[cpu].isen0;
    if (local_off == 0x180) return g->rd[cpu].isen0;
    if (local_off == 0x200) return g->rd[cpu].ipend0;
    if (local_off >= 0x400 && local_off < 0x420) {
        uint32_t v = 0;
        int base = (local_off - 0x400);
        for (int i = 0; i < 4; i++) v |= (uint32_t)g->rd[cpu].prio[base+i] << (i*8);
        return v;
    }
    return 0;
}

void gicr_write(void *dev, uint64_t off, uint64_t val, int size)
{
    GICState *g = dev;
    (void)size;

    int cpu = off / GICR_STRIDE;
    uint64_t local_off = off % GICR_STRIDE;

    if (cpu >= g->num_cpus) return;

    if (local_off < 0x10000) {
        if (local_off == GICR_CTLR)  { g->rd[cpu].ctlr  = val; return; }
        if (local_off == GICR_WAKER) {
            g->rd[cpu].waker = val & ~(1u << 2);  /* ChildrenAsleep always 0 */
            return;
        }
        return;
    }

    local_off -= 0x10000;
    if (local_off == 0x80)  { g->rd[cpu].igrp0 = val; return; }
    if (local_off == 0x100) { g->rd[cpu].isen0 |= val; gic_update(g); return; }
    if (local_off == 0x180) { g->rd[cpu].isen0 &= ~val; gic_update(g); return; }
    if (local_off == 0x200) { g->rd[cpu].ipend0 |= val; gic_update(g); return; }
    if (local_off == 0x280) { g->rd[cpu].ipend0 &= ~val; gic_update(g); return; }
    if (local_off >= 0x400 && local_off < 0x420) {
        int base = local_off - 0x400;
        for (int i = 0; i < 4; i++)
            g->rd[cpu].prio[base+i] = (val >> (i*8)) & 0xff;
        return;
    }
}

/* Public wrapper for cpu_irq_check */
int gic_find_best_irq_for_cpu(GICState *g, int cpu)
{
    if (cpu < 0 || cpu >= g->num_cpus) return -1;
    if (!g->cpu[cpu].icc_igrpen1) return -1;
    int best = gic_find_best_irq(g, cpu);
    return (best == IRQ_NONE) ? -1 : best;
}

/* --- GIC system register interface --- */

uint64_t gic_sysreg_read(GICState *g, int cpu, uint32_t key)
{
    if (key == SR_ICC_IAR1_EL1)   return gic_cpu_read_iar(g, cpu);
    if (key == SR_ICC_PMR_EL1)    return g->cpu[cpu].icc_pmr;
    if (key == SR_ICC_BPR1_EL1)   return g->cpu[cpu].icc_bpr;
    if (key == SR_ICC_CTLR_EL1)   return g->cpu[cpu].icc_ctlr | (1 << 19); /* RSS */
    if (key == SR_ICC_SRE_EL1)    return g->cpu[cpu].icc_sre;
    if (key == SR_ICC_IGRPEN1_EL1) return g->cpu[cpu].icc_igrpen1;
    return 0;
}

void gic_sysreg_write(GICState *g, int cpu, uint32_t key, uint64_t val)
{
    if (key == SR_ICC_EOIR1_EL1)  { gic_cpu_write_eoir(g, cpu, val); return; }
    if (key == SR_ICC_PMR_EL1)    { g->cpu[cpu].icc_pmr = val; gic_update(g); return; }
    if (key == SR_ICC_BPR1_EL1)   { g->cpu[cpu].icc_bpr = val; return; }
    if (key == SR_ICC_CTLR_EL1)   { g->cpu[cpu].icc_ctlr = val; return; }
    if (key == SR_ICC_SRE_EL1)    { g->cpu[cpu].icc_sre = val; return; }
    if (key == SR_ICC_IGRPEN1_EL1) {
        g->cpu[cpu].icc_igrpen1 = val & 1;
        gic_update(g);
        return;
    }
}
