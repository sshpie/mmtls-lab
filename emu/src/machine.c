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

/* GIC PPI INTID for each timer (PPI_n → INTID 16+n) */
#define TIMER_PHYS_INTID  (14 + GIC_NUM_SGI)   /* CNTPNSIRQ: PPI 14 = INTID 30 */
#define TIMER_VIRT_INTID  (11 + GIC_NUM_SGI)   /* CNTVIRQ:   PPI 11 = INTID 27 */

void machine_timer_tick(EmuMachine *m)
{
    uint64_t cntpct = machine_read_cntpct(m);
    for (int c = 0; c < m->num_cpus; c++) {
        ARM64CPU *cpu = &m->cpu[c];

        /* Physical non-secure timer → INTID 30 */
        if ((cpu->cntp_ctl_el0 & 1) && !(cpu->cntp_ctl_el0 & 2)) {
            if (cntpct >= cpu->cntp_cval_el0) {
                if (!(cpu->cntp_ctl_el0 & 4))
                    fprintf(stderr, "[TMR-P] CPU%d phys fired cntpct=%llx cval=%llx\n",
                            c, (unsigned long long)cntpct,
                            (unsigned long long)cpu->cntp_cval_el0);
                cpu->cntp_ctl_el0 |= 4;
                gic_set_irq(&m->gic, TIMER_PHYS_INTID, true);
            } else {
                cpu->cntp_ctl_el0 &= ~4;
                gic_set_irq(&m->gic, TIMER_PHYS_INTID, false);
            }
        }

        /* Virtual timer → INTID 27 */
        if ((cpu->cntv_ctl_el0 & 1) && !(cpu->cntv_ctl_el0 & 2)) {
            if (cntpct >= cpu->cntv_cval_el0) {
                if (!(cpu->cntv_ctl_el0 & 4))
                    fprintf(stderr, "[TMR-V] CPU%d virt fired cntpct=%llx cval=%llx\n",
                            c, (unsigned long long)cntpct,
                            (unsigned long long)cpu->cntv_cval_el0);
                cpu->cntv_ctl_el0 |= 4;
                gic_set_irq(&m->gic, TIMER_VIRT_INTID, true);
            } else {
                cpu->cntv_ctl_el0 &= ~4;
                gic_set_irq(&m->gic, TIMER_VIRT_INTID, false);
            }
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
            strcpy(boot_args, "console=ttyAMA0 earlycon=pl011,mmio32,0x09000000 loglevel=8 kasan.mode=off");

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

#define INSNS_PER_CHECK 1024   /* check timers/ctrl every N instructions (must be power-of-2) */

void machine_run(EmuMachine *m)
{
    m->running = true;
    fprintf(stderr, "[+] Starting execution loop\n");

    uint64_t loop_count = 0;
    uint64_t prev_pc[NUM_CPUS] = {0};
    uint64_t last_status_milestone = 0;
    uint64_t last_status_period    = 0; /* detect period change to reset milestone */

    /* Instruction trace: rolling ring buffer — always captures last ITRACE_MAX insns.
     * Skip the __create_page_tables swapper-fill loop (0x41afac80-0x41afaca4) so
     * the buffer isn't dominated by thousands of identical loop iterations. */
#define ITRACE_MAX 2000
    uint64_t itrace_pc[ITRACE_MAX]   = {0};
    uint32_t itrace_insn[ITRACE_MAX] = {0};
    uint64_t itrace_count = 0;   /* total insns recorded (may exceed ITRACE_MAX) */

    while (!m->exit_request && !(m->max_insns && m->total_insns >= m->max_insns)) {
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
                    } else {
                        /* Periodically log why we can't wake */
                        static uint64_t wfi_poll_cnt = 0;
                        if ((++wfi_poll_cnt & 0x3FFFF) == 0) {  /* every ~256k loops */
                            ARM64CPU *cpu0 = &m->cpu[0];
                            uint64_t cntpct = machine_read_cntpct(m);
                            fprintf(stderr,
                                "[WFI-STALL] loop=%llu"
                                " pctl=%x pcval=%llx"
                                " vctl=%x vcval=%llx"
                                " cntpct=%llx isen0=%08x ipend0=%08x igrpen1=%x\n",
                                (unsigned long long)wfi_poll_cnt,
                                cpu0->cntp_ctl_el0,
                                (unsigned long long)cpu0->cntp_cval_el0,
                                cpu0->cntv_ctl_el0,
                                (unsigned long long)cpu0->cntv_cval_el0,
                                (unsigned long long)cntpct,
                                m->gic.rd[0].isen0,
                                m->gic.rd[0].ipend0,
                                m->gic.cpu[0].icc_igrpen1);
                        }
                    }
                }
            } else if (!m->cpu[c].stopped) {
                prev_pc[c] = m->cpu[c].pc;
                /* Record trace (ring buffer — skip tight loop to save slots) */
                if (c == 0) {
                    uint64_t tpc = m->cpu[c].pc;
                    int in_loop = (tpc >= 0x41afac80ULL && tpc <= 0x41afaca4ULL)
                              || (tpc >= 0x40ffcf2cULL && tpc <= 0x40ffcf38ULL)  /* DC ZVA BSS-clear */
                              || (tpc >= 0x41063484ULL && tpc <= 0x410634a0ULL);  /* self-relocation loop */
                    if (!in_loop) {
                        uint64_t slot = itrace_count % ITRACE_MAX;
                        itrace_pc[slot]   = tpc;
                        /* Read instruction bytes: pre-MMU physical, or post-MMU via KIMAGE_VOFFSET */
                        uint32_t insn_bytes;
                        if (tpc >= VIRT_RAM_BASE && tpc < VIRT_RAM_BASE + m->mem.ram_size) {
                            insn_bytes = (uint32_t)mem_read(&m->mem, tpc, 4);
                        } else if ((int64_t)tpc < 0) {
                            uint64_t pa = tpc - 0xffffffbfc8000000ULL;
                            if (pa >= VIRT_RAM_BASE && pa < VIRT_RAM_BASE + m->mem.ram_size)
                                insn_bytes = (uint32_t)mem_read(&m->mem, pa, 4);
                            else
                                insn_bytes = 0xDEAD0000;
                        } else {
                            insn_bytes = 0xDEADC0DE;
                        }
                        itrace_insn[slot] = insn_bytes;
                        itrace_count++;
                    }
                }
                /* One-shot trap: log caller when cpuset print function is entered */
                if (c == 0 && m->cpu[c].pc == 0xffffffc0081c6d60ULL) {
                    static int cpuset_trap = 0;
                    cpuset_trap++;
                    if (cpuset_trap <= 4) {
                        ARM64CPU *cx = &m->cpu[0];
                        fprintf(stderr,
                            "[CPUSET-ENTER#%d] insns=%llu LR=0x%llx X18=0x%llx SP=0x%llx\n",
                            cpuset_trap, (unsigned long long)m->total_insns,
                            (unsigned long long)cx->x[30],
                            (unsigned long long)cx->x[18],
                            (unsigned long long)cx->sp_el1);
                        /* Dump stack to find outer caller's LR */
                        uint64_t sp = cx->sp_el1;
                        for (int si = 0; si < 8; si++) {
                            uint64_t v = 0;
                            if (sp + si*8 >= 0xffffffc009000000ULL)
                                v = mem_read(&m->mem, sp + si*8 - 0xffffffbfc8000000ULL, 8);
                            if (v != 0 && (v >> 32) == 0xffffffc0)
                                fprintf(stderr, "  [SP+%d]=0x%llx\n", si*8, (unsigned long long)v);
                        }
                    }
                }
                /* One-shot trace: first time we enter the spin function */
                if (c == 0 && m->cpu[c].pc == 0xffffffc0080b7f78ULL) {
                    static uint64_t spin_hits = 0;
                    spin_hits++;
                    if (spin_hits == 1 || spin_hits == 10 || spin_hits == 100 ||
                        spin_hits == 1000 || (spin_hits % 1000000) == 0)
                        fprintf(stderr, "[SPIN-HIT#%llu] insns=%llu\n",
                                (unsigned long long)spin_hits,
                                (unsigned long long)m->total_insns);
                    static int spin_trace_done = 0;
                    if (!spin_trace_done++) {
                        ARM64CPU *cx = &m->cpu[0];
                        fprintf(stderr, "[SPIN-ENTRY] insns=%llu PC=0x%llx LR=0x%llx pstate=0x%08x SP=0x%llx\n",
                                (unsigned long long)m->total_insns,
                                (unsigned long long)cx->pc,
                                (unsigned long long)cx->x[30],
                                cx->pstate,
                                (unsigned long long)cx->sp_el1);
                        /* Real MMU walk: VA -> PA for the stuck PC */
                        {
                            uint64_t va   = cx->pc;
                            uint64_t ttbr = cx->ttbr1_el1 & ~0xFFFULL;
                            int t1sz  = (int)((cx->tcr_el1 >> 16) & 0x3F);
                            int va_bits = 64 - t1sz;
                            int start_lvl = 3 - (va_bits - 1 - 12) / 9;
                            fprintf(stderr, "[MMU-WALK] VA=0x%llx TTBR1=0x%llx T1SZ=%d VA_BITS=%d\n",
                                    (unsigned long long)va, (unsigned long long)ttbr, t1sz, va_bits);
                            for (int lv = start_lvl; lv <= 3; lv++) {
                                int shift = 39 - (lv - start_lvl) * 9 - (9 * start_lvl);
                                /* correct shift: highest level shift = 39 - 9*(lv) for 4K/L0 scheme */
                                shift = (start_lvl == 1) ? (30 - (lv-1)*9) : (39 - lv*9);
                                uint64_t idx = (va >> shift) & 0x1FF;
                                uint64_t epa = ttbr + idx * 8;
                                uint64_t entry = mem_read(&m->mem, epa, 8);
                                const char *type = !(entry&1) ? "INVALID" : ((lv<3&&(entry&2)) ? "TABLE" : "BLOCK/PAGE");
                                fprintf(stderr, "[MMU-WALK] L%d idx=%llu PA=0x%llx entry=0x%016llx [%s]\n",
                                        lv, (unsigned long long)idx, (unsigned long long)epa,
                                        (unsigned long long)entry, type);
                                if (!(entry & 1)) break;
                                if (lv < 3 && (entry & 2)) {
                                    ttbr = entry & 0x0000FFFFFFFFF000ULL;
                                } else {
                                    uint64_t mask = (1ULL << shift) - 1;
                                    uint64_t pa = (entry & 0x0000FFFFFFFFF000ULL) | (va & mask);
                                    uint32_t insn = (uint32_t)mem_read(&m->mem, pa, 4);
                                    fprintf(stderr, "[MMU-WALK] PA=0x%llx insn=0x%08x\n",
                                            (unsigned long long)pa, insn);
                                    /* Also dump PA+/-8 context */
                                    for (int d = -2; d <= 4; d++) {
                                        uint32_t w = (uint32_t)mem_read(&m->mem, pa + d*4, 4);
                                        fprintf(stderr, "[MMU-WALK] [PA%+d]=0x%08x\n", d*4, w);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                cpu_step(&m->cpu[c], m);
                m->total_insns++;

                /* LEB128 scanner trace: log first visit and exit from 0x81ae818 region.
                 * This is the ORC/kallsyms table parser — it runs N iterations per
                 * kernel symbol/function and terminates naturally. Do NOT kick it. */
                if (c == 0) {
                    static uint64_t leb_entry_count = 0;
                    static uint64_t leb_last_insns  = 0;
                    bool at_leb = (m->cpu[c].pc == 0xffffffc0081ae818ULL);
                    if (at_leb) {
                        leb_entry_count++;
                        if (leb_entry_count == 1 || leb_entry_count == 1000000) {
                            ARM64CPU *cx = &m->cpu[0];
                            fprintf(stderr,
                                "[LEB128#%llu] insns=%llu X9=0x%llx X10=0x%llx\n",
                                (unsigned long long)leb_entry_count,
                                (unsigned long long)m->total_insns,
                                (unsigned long long)cx->x[9],
                                (unsigned long long)cx->x[10]);
                        }
                        leb_last_insns = m->total_insns;
                    } else if (leb_entry_count > 0 && leb_last_insns > 0 &&
                               m->total_insns == leb_last_insns + 1) {
                        /* First instruction AFTER leaving 0x81ae818 */
                        fprintf(stderr,
                            "[LEB128-DONE] exited after %llu entries, insns=%llu PC=0x%llx\n",
                            (unsigned long long)leb_entry_count,
                            (unsigned long long)m->total_insns,
                            (unsigned long long)m->cpu[c].pc);
                        leb_last_insns = 0;  /* don't re-log */
                    }
                }
                /* Progress heartbeat every 100M instructions */
                if (c == 0 && (m->total_insns % 100000000ULL) == 0 && m->total_insns > 0) {
                    fprintf(stderr, "[PROGRESS] %llu M insns PC=0x%llx\n",
                        (unsigned long long)(m->total_insns / 1000000ULL),
                        (unsigned long long)m->cpu[c].pc);
                }

                /* Trap: PC left valid RAM — halt and dump.
                 * Only enforce physical range when MMU is off.  Once the MMU is on,
                 * kernel VAs (bit63=1) are valid — they translate through TTBR1.
                 * Physical range check still catches genuine PC=0 / runaway jumps to
                 * unmapped physical space while MMU is off. */
                uint64_t pc = m->cpu[c].pc;
                bool mmu_active = !!(m->cpu[c].sctlr_el1 & (1ULL << 0)); /* SCTLR_EL1.M */
                bool kernel_va  = (int64_t)pc < 0;                         /* bit63=1 */
                bool pc_ok_phys = (pc >= VIRT_RAM_BASE && pc < VIRT_RAM_BASE + m->ram_size);
                if (!(pc_ok_phys || (mmu_active && kernel_va))) {
                    fprintf(stderr,
                        "\n[!] CPU%d PC LEFT RAM after %llu insns\n"
                        "    prev_pc=0x%016llx  new_pc=0x%016llx\n",
                        c, (unsigned long long)m->total_insns,
                        (unsigned long long)prev_pc[c],
                        (unsigned long long)pc);
                    /* Dump instruction trace (ring buffer, chronological order) */
                    uint64_t n_rec = (itrace_count < ITRACE_MAX) ? itrace_count : ITRACE_MAX;
                    uint64_t oldest = (itrace_count <= ITRACE_MAX) ? 0 : (itrace_count % ITRACE_MAX);
                    fprintf(stderr, "\nINSTRUCTION TRACE (last %llu, total recorded %llu):\n",
                            n_rec, itrace_count);
                    for (uint64_t i = 0; i < n_rec; i++) {
                        uint64_t slot = (oldest + i) % ITRACE_MAX;
                        fprintf(stderr, "  [%4llu] 0x%016llx: 0x%08x\n",
                                itrace_count - n_rec + i,
                                (unsigned long long)itrace_pc[slot],
                                itrace_insn[slot]);
                    }
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

            /* Boot-phase status every 100k instructions (first 1M) then every 1M */
            {
                uint64_t period = (m->total_insns < 1000000) ? 100000 : 1000000;
                if (period != last_status_period) {
                    last_status_period    = period;
                    last_status_milestone = 0;  /* reset on period change */
                }
                uint64_t cur_ms = m->total_insns / period;
                if (cur_ms > last_status_milestone) {
                    last_status_milestone = cur_ms;
                    ARM64CPU *c0 = &m->cpu[0];
                    /* Read init_task.cgroups VA=0xffffffc009c5e428 PA=0x41c5e428 */
                    uint64_t it_cgroups = mem_read(&m->mem, 0x41c5e428ULL, 8);
                    fprintf(stderr, "[STATUS] insns=%llu PC=0x%llx LR=0x%llx X18=0x%llx EL=%u pstate=0x%08x SP=0x%llx TTBR1=0x%llx VBAR=0x%llx it_cgroups=0x%llx\n",
                            (unsigned long long)m->total_insns,
                            (unsigned long long)c0->pc,
                            (unsigned long long)c0->x[30],
                            (unsigned long long)c0->x[18],
                            (c0->pstate >> 2) & 3,
                            c0->pstate,
                            (unsigned long long)c0->sp_el1,
                            (unsigned long long)c0->ttbr1_el1,
                            (unsigned long long)c0->vbar_el1,
                            (unsigned long long)it_cgroups);
                    /* Dump trace at first milestone and every 10th thereafter */
                    if ((cur_ms == 1 || cur_ms % 10 == 0) && itrace_count > 0) {
                        uint64_t nr = (itrace_count < ITRACE_MAX) ? itrace_count : ITRACE_MAX;
                        uint64_t ol = (itrace_count <= ITRACE_MAX) ? 0 : (itrace_count % ITRACE_MAX);
                        const char *label = (cur_ms == 1) ? "BOOT" : "FREEZE";
                        fprintf(stderr, "\n%s TRACE (last %llu of %llu recorded):\n", label, nr, itrace_count);
                        for (uint64_t i = 0; i < nr; i++) {
                            uint64_t slot = (ol + i) % ITRACE_MAX;
                            fprintf(stderr, "  [%4llu] 0x%016llx: 0x%08x\n",
                                    itrace_count - nr + i,
                                    (unsigned long long)itrace_pc[slot],
                                    itrace_insn[slot]);
                        }
                        fprintf(stderr, "\n");
                    }
                }
            }
        }
    }

    m->running = false;
    fprintf(stderr, "[+] Emulator stopped after %llu instructions\n",
            (unsigned long long)m->total_insns);
}
