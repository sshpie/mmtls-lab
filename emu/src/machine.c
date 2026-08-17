/* machine.c — EmuMachine: device init, main run loop, callbacks */
#include "machine.h"
#include "ctrl.h"
#include "mmu.h"
#include "dtb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* --- Callbacks --- */

void machine_signal_irq(void *opaque, int cpu_id, bool level)
{
    EmuMachine *m = opaque;
    (void)level;
    /* IRQ line state change — cpu_irq_check() handles actual delivery */
    (void)cpu_id;
    (void)m;
}

void machine_raise_irq(void *gic_ptr, int irq, bool level)
{
    GICState *g = gic_ptr;
    gic_set_irq(g, irq, level);
}

uint64_t machine_read_cntpct(EmuMachine *m)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    uint64_t elapsed_ns = ns - m->timer.start_ns;
    return (elapsed_ns * m->timer.cntfrq) / 1000000000ULL;
}

void machine_timer_tick(EmuMachine *m)
{
    for (int c = 0; c < m->num_cpus; c++) {
        ARM64CPU *cpu = &m->cpu[c];
        if (!(cpu->cntp_ctl_el0 & 1)) continue;       /* ENABLE=0 */
        if (cpu->cntp_ctl_el0 & 2)  continue;         /* IMASK=1 */
        uint64_t cntpct = machine_read_cntpct(m);
        if (cntpct >= cpu->cntp_cval_el0) {
            /* Timer fires: set ISTATUS, raise PPI 14 (physical timer) */
            if (!(cpu->cntp_ctl_el0 & 4)) {
                fprintf(stderr, "[TMR] CPU%d timer fired: cntpct=%llx cval=%llx isen0=%08x\n",
                        c, (unsigned long long)cntpct,
                        (unsigned long long)cpu->cntp_cval_el0,
                        m->gic.rd[c].isen0);
            }
            cpu->cntp_ctl_el0 |= 4;  /* ISTATUS */
            gic_set_irq(&m->gic, 14 + GIC_NUM_SGI, true);
        } else {
            cpu->cntp_ctl_el0 &= ~4;
            gic_set_irq(&m->gic, 14 + GIC_NUM_SGI, false);
        }
    }
}

void machine_dump_cpu(EmuMachine *m, int cpu_id)
{
    if (cpu_id < 0 || cpu_id >= m->num_cpus) return;
    ARM64CPU *c = &m->cpu[cpu_id];
    fprintf(stderr, "CPU%d  PC=%016llx  PSTATE=%08x\n",
            cpu_id, (unsigned long long)c->pc, c->pstate);
    for (int i = 0; i < 31; i += 4) {
        fprintf(stderr, "  x%-2d=%016llx  x%-2d=%016llx  x%-2d=%016llx  x%-2d=%016llx\n",
                i,   (unsigned long long)c->x[i],
                i+1, (unsigned long long)(i+1<31?c->x[i+1]:0),
                i+2, (unsigned long long)(i+2<31?c->x[i+2]:0),
                i+3, (unsigned long long)(i+3<31?c->x[i+3]:0));
    }
    fprintf(stderr, "  SP=%016llx  LR=%016llx\n",
            (unsigned long long)cpu_sp(c),
            (unsigned long long)c->x[30]);
}

/* --- Kernel image loader --- */

/* Load a possibly gzip-compressed kernel image.
 * If file starts with 0x1f8b (gzip magic): decompress via zcat to a temp file.
 * Otherwise load raw. */
static int load_kernel(PhysMem *mem, uint64_t load_addr, const char *path)
{
    /* Check for gzip magic */
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    uint8_t magic[2];
    fread(magic, 1, 2, f);
    fclose(f);

    if (magic[0] == 0x1f && magic[1] == 0x8b) {
        /* Decompress to temp */
        char tmp[] = "/tmp/emu64-kernel-XXXXXX";
        int fd = mkstemp(tmp);
        if (fd < 0) { perror("mkstemp"); return -1; }
        close(fd);

        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "zcat '%s' > '%s'", path, tmp);
        int rc = system(cmd);
        if (rc != 0) { fprintf(stderr, "zcat failed\n"); unlink(tmp); return -1; }

        mem_load_file(mem, load_addr, tmp);
        unlink(tmp);
        fprintf(stderr, "[+] Kernel (gzip) loaded at 0x%016llx\n",
                (unsigned long long)load_addr);
    } else {
        mem_load_file(mem, load_addr, path);
        fprintf(stderr, "[+] Kernel loaded at 0x%016llx\n",
                (unsigned long long)load_addr);
    }
    return 0;
}

/* --- Machine init --- */

int machine_init(EmuMachine *m, uint64_t ram_size,
                 const char *kernel, const char *initrd,
                 const char *cmdline, const char *ctrl_sock,
                 const char **disk_paths, bool *disk_ro, int num_disks)
{
    memset(m, 0, sizeof(*m));
    m->ram_size   = ram_size;
    m->num_cpus   = NUM_CPUS;
    m->kernel_path  = kernel;
    m->initrd_path  = initrd;
    m->cmdline      = cmdline;
    m->ctrl_sock_path = ctrl_sock;

    /* Timer init */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    m->timer.start_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    m->timer.cntfrq   = 62500000ULL;  /* 62.5 MHz */

    /* Memory init */
    mem_init(&m->mem, ram_size);

    /* GIC init */
    gic_init(&m->gic, m->num_cpus, machine_signal_irq, m);

    /* Register GIC MMIO regions */
    mem_register_mmio(&m->mem, VIRT_GICD_BASE, GICD_SIZE,
                      &m->gic, gicd_read, gicd_write, "GICD");
    mem_register_mmio(&m->mem, VIRT_GICR_BASE,
                      GICR_STRIDE * m->num_cpus,
                      &m->gic, gicr_read, gicr_write, "GICR");

    /* UART init */
    uart_init(&m->uart, STDOUT_FILENO, IRQ_UART,
              &m->gic, machine_raise_irq);
    mem_register_mmio(&m->mem, VIRT_UART_BASE, VIRT_UART_SIZE,
                      &m->uart, uart_read, uart_write, "PL011");

    /* virtio-blk devices */
    m->num_blk = (num_disks > MAX_VIRTIO_DEVS) ? MAX_VIRTIO_DEVS : num_disks;
    for (int i = 0; i < m->num_blk; i++) {
        int irq = VIRTIO_IRQ_BASE + i;
        uint64_t base = VIRT_VIRTIO_BASE + (uint64_t)i * VIRT_VIRTIO_SIZE;
        virtio_blk_init(&m->blk[i], disk_paths[i], disk_ro[i],
                        irq, &m->gic, machine_raise_irq, &m->mem);
        mem_register_mmio(&m->mem, base, VIRT_VIRTIO_SIZE,
                          &m->blk[i], virtio_blk_read, virtio_blk_write,
                          "virtio-blk");
        fprintf(stderr, "[+] virtio-blk[%d]: %s at 0x%llx irq %d\n",
                i, disk_paths[i], (unsigned long long)base, irq);
    }

    /* Load kernel
     * ARM64 Image header at offset 0x08 has text_offset (LE 64-bit).
     * If text_offset == 0, kernel must be 2MB-aligned (no additional offset).
     * We read text_offset from the decompressed image and use it. */
    uint64_t kernel_load = VIRT_RAM_BASE;  /* default: 2MB-aligned base */
    if (kernel) {
        /* Peek at text_offset in the Image header (after decompressing to temp).
         * For now: load at RAM_BASE with text_offset=0 (ranchu kernel).
         * The B instruction in code1 is PC-relative so loading at RAM_BASE works. */
        kernel_load = VIRT_RAM_BASE;
        if (load_kernel(&m->mem, kernel_load, kernel) < 0)
            return -1;
    }

    /* Load initrd */
    uint64_t initrd_start = 0, initrd_end = 0;
    if (initrd) {
        /* Place initrd after first 128MB of RAM */
        struct stat st;
        stat(initrd, &st);
        initrd_start = VIRT_RAM_BASE + 128ULL * 1024 * 1024;
        initrd_end   = initrd_start + st.st_size;
        mem_load_file(&m->mem, initrd_start, initrd);
        fprintf(stderr, "[+] initrd loaded at 0x%016llx (%lld bytes)\n",
                (unsigned long long)initrd_start, (long long)st.st_size);
    }

    /* Generate / load DTB */
    uint64_t dtb_addr = VIRT_RAM_BASE + 64ULL * 1024 * 1024;  /* 64MB into RAM */
    {
        char boot_args[4096];
        if (cmdline)
            snprintf(boot_args, sizeof(boot_args), "%s", cmdline);
        else
            strcpy(boot_args, "console=ttyAMA0 earlycon kasan.mode=off");

        size_t dtb_size = dtb_generate(&m->mem, dtb_addr,
                                       boot_args, ram_size,
                                       m->num_cpus, m->num_blk);
        fprintf(stderr, "[+] DTB generated at 0x%016llx (%zu bytes)\n",
                (unsigned long long)dtb_addr, dtb_size);
    }

    /* CPU init */
    for (int i = 0; i < m->num_cpus; i++) {
        cpu_init(&m->cpu[i], i);
    }

    /* Boot CPU (CPU 0): set up registers per Linux boot protocol for ARM64.
     * x0 = dtb_phys_addr, x1=x2=x3=0 */
    m->cpu[0].x[0] = dtb_addr;
    m->cpu[0].x[1] = 0;
    m->cpu[0].x[2] = 0;
    m->cpu[0].x[3] = 0;
    m->cpu[0].pc   = kernel_load;

    fprintf(stderr, "[+] CPU0 PC=0x%016llx DTB=0x%016llx\n",
            (unsigned long long)m->cpu[0].pc,
            (unsigned long long)dtb_addr);

    /* Control socket */
    if (ctrl_sock) {
        m->ctrl = malloc(sizeof(struct CtrlServer));
        if (!m->ctrl) { perror("malloc ctrl"); return -1; }
        extern int ctrl_init(struct CtrlServer *s, EmuMachine *m, const char *path);
        if (ctrl_init(m->ctrl, m, ctrl_sock) < 0) {
            fprintf(stderr, "[-] ctrl socket init failed\n");
            free(m->ctrl);
            m->ctrl = NULL;
        } else {
            fprintf(stderr, "[+] LLM control socket: %s\n", ctrl_sock);
        }
    }

    return 0;
}

/* --- Main run loop --- */

#define INSNS_PER_CHECK 1000   /* check timers/ctrl every N instructions */

void machine_run(EmuMachine *m)
{
    m->running = true;
    fprintf(stderr, "[+] Starting execution loop\n");

    uint64_t loop_count = 0;
    uint64_t prev_pc[NUM_CPUS] = {0};

    /* Instruction trace: dump every PC for the first 2000 insns */
#define ITRACE_MAX 2000
    uint64_t itrace_pc[ITRACE_MAX] = {0};
    uint32_t itrace_insn[ITRACE_MAX] = {0};
    uint64_t itrace_count = 0;

    while (!m->exit_request) {
        /* Execute one instruction per CPU */
        for (int c = 0; c < m->num_cpus; c++) {
            if (m->cpu[c].halted) {
                /* WFI: wake if IRQ pending and not masked */
                if (!(m->cpu[c].pstate & PSTATE_I)) {
                    int _wfi_irq = gic_find_best_irq_for_cpu(&m->gic, c);
                    if (_wfi_irq >= 0) {
                        fprintf(stderr, "[WFI] CPU%d woken by IRQ %d at PC=0x%llx\n",
                                c, _wfi_irq, (unsigned long long)m->cpu[c].pc);
                        m->cpu[c].halted = false;
                        m->cpu[c].pc += 4;  /* advance past WFI so ELR_EL1 returns after it */
                        cpu_irq_check(&m->cpu[c], m);
                    }
                }
            } else if (!m->cpu[c].stopped) {
                prev_pc[c] = m->cpu[c].pc;
                /* Record trace before stepping */
                if (c == 0 && itrace_count < ITRACE_MAX) {
                    itrace_pc[itrace_count] = m->cpu[c].pc;
                    itrace_insn[itrace_count] =
                        (uint32_t)mem_read(&m->mem, m->cpu[c].pc, 4);
                    itrace_count++;
                }
                cpu_step(&m->cpu[c], m);
                m->total_insns++;

                /* Trap: PC left valid RAM — halt and dump */
                uint64_t pc = m->cpu[c].pc;
                if (pc < VIRT_RAM_BASE || pc >= VIRT_RAM_BASE + m->ram_size) {
                    fprintf(stderr,
                        "\n[!] CPU%d PC LEFT RAM after %llu insns\n"
                        "    prev_pc=0x%016llx  new_pc=0x%016llx\n",
                        c, (unsigned long long)m->total_insns,
                        (unsigned long long)prev_pc[c],
                        (unsigned long long)pc);
                    /* Dump instruction trace */
                    fprintf(stderr, "\nINSTRUCTION TRACE (first %llu):\n",
                            itrace_count);
                    for (uint64_t t = 0; t < itrace_count; t++)
                        fprintf(stderr, "  [%3llu] 0x%016llx: 0x%08x\n",
                                t, (unsigned long long)itrace_pc[t],
                                itrace_insn[t]);
                    machine_dump_cpu(m, c);
                    m->cpu[c].stopped = true;
                    m->exit_request   = true;
                }
            }
        }

        loop_count++;

        /* Periodic: check control socket, timers */
        if ((loop_count & (INSNS_PER_CHECK - 1)) == 0) {
            if (m->ctrl) {
                extern void ctrl_poll(struct CtrlServer *s);
                ctrl_poll(m->ctrl);
            }
            machine_timer_tick(m);

            /* Boot-phase status every 5M instructions */
            if (m->total_insns > 0 && (m->total_insns % 5000000) == 0) {
                ARM64CPU *c0 = &m->cpu[0];
                fprintf(stderr, "[STATUS] insns=%llu PC=0x%llx EL=%u pstate=0x%08x SP_EL0=0x%llx SP_EL1=0x%llx TTBR0=0x%llx TTBR1=0x%llx VBAR=0x%llx SCTLR=0x%llx\n",
                        (unsigned long long)m->total_insns,
                        (unsigned long long)c0->pc,
                        (c0->pstate >> 2) & 3,
                        c0->pstate,
                        (unsigned long long)c0->sp_el0,
                        (unsigned long long)c0->sp_el1,
                        (unsigned long long)c0->ttbr0_el1,
                        (unsigned long long)c0->ttbr1_el1,
                        (unsigned long long)c0->vbar_el1,
                        (unsigned long long)c0->sctlr_el1);
                /* Print first ITRACE on first status */
                if (m->total_insns == 5000000 && itrace_count > 0) {
                    fprintf(stderr, "\nBOOT TRACE (first %llu insns):\n", itrace_count);
                    for (uint64_t t = 0; t < itrace_count; t++)
                        fprintf(stderr, "  [%4llu] 0x%016llx: 0x%08x\n",
                                t, (unsigned long long)itrace_pc[t],
                                itrace_insn[t]);
                    fprintf(stderr, "\n");
                }
            }
        }
    }

    m->running = false;
    fprintf(stderr, "[+] Emulator stopped after %llu instructions\n",
            (unsigned long long)m->total_insns);
}
