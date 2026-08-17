/* machine.h — EmuMachine: top-level emulator state */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "arm64.h"
#include "mem.h"
#include "dev_uart.h"
#include "dev_gic.h"
#include "dev_virtio.h"

#define MAX_VIRTIO_DEVS 8
#define VIRTIO_IRQ_BASE 32   /* GIC SPI 32 = IRQ 0 for first virtio dev */

/* virt machine memory map */
#define VIRT_ROM_BASE    0x00000000ULL
#define VIRT_ROM_SIZE    0x08000000ULL   /* 128MB */
#define VIRT_GICD_BASE   0x08000000ULL
#define VIRT_GICR_BASE   0x080A0000ULL
#define VIRT_UART_BASE   0x09000000ULL
#define VIRT_UART_SIZE   0x00001000ULL
#define VIRT_VIRTIO_BASE 0x0a000000ULL
#define VIRT_VIRTIO_SIZE 0x00000200ULL   /* 512B per slot */
#define VIRT_RAM_BASE    0x40000000ULL

/* GIC interrupt lines */
#define IRQ_UART    33   /* SPI 1 */
#define IRQ_TIMER   27   /* PPI 11 — ARM generic timer */

/* ARM generic timer */
typedef struct GenTimer {
    uint64_t cntfrq;    /* counter frequency (Hz) */
    uint64_t start_ns;  /* host ns at reset */
} GenTimer;

typedef struct EmuMachine {
    /* CPUs */
    ARM64CPU     cpu[NUM_CPUS];
    int          num_cpus;

    /* Memory */
    PhysMem      mem;

    /* Devices */
    PL011        uart;
    GICState     gic;
    GenTimer     timer;
    VirtioBlk    blk[MAX_VIRTIO_DEVS];
    int          num_blk;

    /* Control socket */
    struct CtrlServer *ctrl;   /* forward decl avoids circular include */

    /* Execution state */
    bool         running;       /* true = execution loop active */
    bool         exit_request;  /* signal main loop to stop */

    /* Statistics */
    uint64_t     total_insns;
    uint64_t     max_insns;    /* 0 = unlimited */

    /* Config */
    uint64_t     ram_size;
    const char  *kernel_path;
    const char  *dtb_path;      /* NULL = generate */
    const char  *initrd_path;
    const char  *cmdline;
    const char  *ctrl_sock_path;
} EmuMachine;

/* Forward declarations for ctrl.c compatibility */
struct CtrlServer;

/* Initialize machine, load images, start devices */
int  machine_init(EmuMachine *m, uint64_t ram_size,
                  const char *kernel, const char *initrd,
                  const char *cmdline, const char *ctrl_sock,
                  const char **disk_paths, bool *disk_ro, int num_disks);

/* Run the main execution loop (all CPUs, single-threaded) */
void machine_run(EmuMachine *m);

/* GIC→CPU IRQ signal callback */
void machine_signal_irq(void *opaque, int cpu_id, bool level);

/* GIC→UART IRQ raise callback */
void machine_raise_irq(void *gic, int irq, bool level);

/* Timer: read virtual counter */
uint64_t machine_read_cntpct(EmuMachine *m);

/* Timer: check if timer interrupt should fire */
void machine_timer_tick(EmuMachine *m);

/* Dump CPU state (for debugging) */
void machine_dump_cpu(EmuMachine *m, int cpu_id);
