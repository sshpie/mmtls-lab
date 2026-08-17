/* arm64.c — ARMv8-A CPU interpreter (software decode/execute) */
#include "arm64.h"
#include "mem.h"
#include "mmu.h"
#include "machine.h"
#include "dev_gic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Forward declarations for sub-decoders */
static int exec_dp_imm(ARM64CPU *c, EmuMachine *m, uint32_t insn);
static int exec_branch(ARM64CPU *c, EmuMachine *m, uint32_t insn);
static int exec_ldst(ARM64CPU *c, EmuMachine *m, uint32_t insn);
static int exec_dp_reg(ARM64CPU *c, EmuMachine *m, uint32_t insn);
static int exec_simd(ARM64CPU *c, EmuMachine *m, uint32_t insn);

/* ============================================================
 * CPU lifecycle
 * ============================================================ */

void cpu_init(ARM64CPU *c, int id)
{
    memset(c, 0, sizeof(*c));
    c->id = id;
    cpu_reset(c);
}

void cpu_reset(ARM64CPU *c)
{
    c->pc = 0;
    c->pstate = (EL1 << PSTATE_EL_SHIFT) | PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F | PSTATE_SP;
    c->sctlr_el1 = 0x00C50078ULL;  /* minimal: no MMU, cache-off */
    c->cntp_ctl_el0 = 0;
    c->halted = (c->id != 0);  /* secondary CPUs wait for PSCI */
    c->stopped = false;
}

/* ============================================================
 * Condition code check
 * ============================================================ */

bool cpu_check_cond(ARM64CPU *c, uint32_t cond)
{
    bool n = !!(c->pstate & PSTATE_N);
    bool z = !!(c->pstate & PSTATE_Z);
    bool cv = !!(c->pstate & PSTATE_C);
    bool v = !!(c->pstate & PSTATE_V);
    switch (cond >> 1) {
    case 0: return z;
    case 1: return cv;
    case 2: return n;
    case 3: return v;
    case 4: return cv && !z;
    case 5: return n == v;
    case 6: return (n == v) && !z;
    case 7: return true;
    default: return false;
    }
    /* invert for odd conditions (except 0xF) */
    /* already handled above; done */
}

/* The actual implementation needs to handle the inversion */
static bool check_cond(ARM64CPU *c, uint32_t cond4)
{
    bool n = !!(c->pstate & PSTATE_N);
    bool z = !!(c->pstate & PSTATE_Z);
    bool cv = !!(c->pstate & PSTATE_C);
    bool v = !!(c->pstate & PSTATE_V);
    bool result;
    switch (cond4 >> 1) {
    case 0: result = z; break;
    case 1: result = cv; break;
    case 2: result = n; break;
    case 3: result = v; break;
    case 4: result = cv && !z; break;
    case 5: result = n == v; break;
    case 6: result = (n == v) && !z; break;
    case 7: result = true; break;
    default: result = false; break;
    }
    if ((cond4 & 1) && cond4 != 0xF) result = !result;
    return result;
}

/* ============================================================
 * Flag helpers
 * ============================================================ */

static void set_nzcv(ARM64CPU *c, bool n, bool z, bool cv, bool v)
{
    c->pstate &= ~(PSTATE_N | PSTATE_Z | PSTATE_C | PSTATE_V);
    if (n)  c->pstate |= PSTATE_N;
    if (z)  c->pstate |= PSTATE_Z;
    if (cv) c->pstate |= PSTATE_C;
    if (v)  c->pstate |= PSTATE_V;
}

static void add_flags64(ARM64CPU *c, uint64_t a, uint64_t b, uint64_t res)
{
    bool n = !!(res >> 63);
    bool z = (res == 0);
    bool cv = (res < a);
    bool v  = (~(a ^ b) & (a ^ res)) >> 63;
    set_nzcv(c, n, z, cv, v);
}

static void sub_flags64(ARM64CPU *c, uint64_t a, uint64_t b, uint64_t res)
{
    bool n = !!(res >> 63);
    bool z = (res == 0);
    bool cv = (a >= b);
    bool v  = ((a ^ b) & (a ^ res)) >> 63;
    set_nzcv(c, n, z, cv, v);
}

static void add_flags32(ARM64CPU *c, uint32_t a, uint32_t b, uint32_t res)
{
    bool n = !!(res >> 31);
    bool z = (res == 0);
    bool cv = ((uint64_t)a + b) > 0xFFFFFFFFULL;
    bool v  = (~(a ^ b) & (a ^ res)) >> 31;
    set_nzcv(c, n, z, cv, v);
}

static void sub_flags32(ARM64CPU *c, uint32_t a, uint32_t b, uint32_t res)
{
    bool n = !!(res >> 31);
    bool z = (res == 0);
    bool cv = (a >= b);
    bool v  = ((a ^ b) & (a ^ res)) >> 31;
    set_nzcv(c, n, z, cv, v);
}

/* ============================================================
 * DecodeBitMasks — ARM64 logical immediate encoding
 * ============================================================ */

static bool decode_bit_masks(uint32_t n, uint32_t imms, uint32_t immr,
                              bool is64, uint64_t *wmask, uint64_t *tmask)
{
    /* Determine element size len */
    int len;
    if (n) {
        len = 6;
    } else {
        int top = imms ^ 0x3f;
        if (top == 0) return false;
        len = 0;
        for (int i = 5; i >= 1; i--) {
            if ((top >> i) & 1) { len = i; break; }
        }
        if (!len) return false;
    }
    int esize = 1 << len;
    int S = imms & (esize - 1);
    int R = immr & (esize - 1);
    int diff = (S - R) & (esize - 1);
    int d = diff;

    /* Build element */
    uint64_t welem = (d == 63) ? ~0ULL : ((1ULL << (d + 1)) - 1);
    /* ROR element by R */
    uint64_t telem = welem;
    if (R) {
        telem = (welem >> R) | (welem << (esize - R));
        telem &= (esize == 64) ? ~0ULL : ((1ULL << esize) - 1);
    }

    /* Replicate across 64 bits */
    uint64_t result = 0;
    for (int i = 0; i < 64; i += esize)
        result |= telem << i;

    if (wmask) *wmask = result;
    if (tmask) {
        uint64_t t = (d == 63) ? ~0ULL : ((1ULL << (d + 1)) - 1);
        uint64_t tr = 0;
        for (int i = 0; i < 64; i += esize) tr |= t << i;
        *tmask = tr;
    }
    if (!is64) {
        if (wmask) *wmask &= 0xFFFFFFFF;
        if (tmask) *tmask &= 0xFFFFFFFF;
    }
    return true;
}

/* ============================================================
 * Memory access helpers (VA → PA via MMU or direct)
 * ============================================================ */

static inline bool mmu_on(ARM64CPU *c) {
    return !!(c->sctlr_el1 & SCTLR_M);
}

static int cpu_load(ARM64CPU *c, PhysMem *mem, uint64_t va, int sz,
                    bool is_signed, bool is64, uint64_t *out)
{
    uint64_t val = 0;
    if (mmu_on(c)) {
        int el = (c->pstate >> PSTATE_EL_SHIFT) & 3;
        (void)el;
        if (!mmu_load(c, mem, va, sz, is_signed, &val, MEM_READ)) {
            /* Translation fault → Data Abort at EL1.
             * Only inject exception if VBAR is set; before VBAR setup the kernel
             * uses idmap and small-VA accesses are early boot anomalies that are
             * handled gracefully with a 0 return. */
            if (c->vbar_el1 != 0) {
                static uint64_t dflt_count = 0;
                dflt_count++;
                if (dflt_count <= 50 || (dflt_count % 10000) == 0)
                    fprintf(stderr, "[DATA-ABORT-LOAD#%llu] VA=0x%016llx PC=0x%016llx\n",
                            (unsigned long long)dflt_count,
                            (unsigned long long)va, (unsigned long long)c->pc);
                /* Crash at task+0x968 deref: dump sp_el0 and its field */
                if (dflt_count == 1 && c->pc == 0xffffffc0081c6d88ULL) {
                    uint64_t task = c->sp_el0;
                    uint64_t field_pa = 0;
                    uint64_t field_val = 0;
                    fprintf(stderr, "[CRASH-DIAG] sp_el0=0x%llx X8=0x%llx X19=0x%llx\n",
                            (unsigned long long)task,
                            (unsigned long long)c->x[8],
                            (unsigned long long)c->x[19]);
                    /* Read back field at task+0x968 via MMU */
                    (void)field_pa; (void)field_val;
                    /* Also dump X0-X5 for context */
                    fprintf(stderr, "[CRASH-DIAG] X0=0x%llx X1=0x%llx X2=0x%llx X3=0x%llx X4=0x%llx X5=0x%llx LR=0x%llx\n",
                            (unsigned long long)c->x[0], (unsigned long long)c->x[1],
                            (unsigned long long)c->x[2], (unsigned long long)c->x[3],
                            (unsigned long long)c->x[4], (unsigned long long)c->x[5],
                            (unsigned long long)c->x[30]);
                }
                cpu_take_exception(c, (0x25ULL << 26) | 0x04ULL, va, EL1);
            }
            return -1;
        }
    } else {
        /* Physical access */
        switch (sz) {
        case 1: { uint8_t v;  v = mem_read(mem, va, 1); val = v; break; }
        case 2: { uint16_t v; v = mem_read(mem, va, 2); val = v; break; }
        case 4: { uint32_t v; v = mem_read(mem, va, 4); val = v; break; }
        case 8: { uint64_t v; v = mem_read(mem, va, 8); val = v; break; }
        default: val = mem_read(mem, va, sz); break;
        }
        if (is_signed) {
            switch (sz) {
            case 1: val = (int64_t)(int8_t)val; break;
            case 2: val = (int64_t)(int16_t)val; break;
            case 4: val = (int64_t)(int32_t)val; break;
            }
            if (!is64) val &= 0xFFFFFFFF;
        }
    }
    *out = val;
    return 1;
}

static int cpu_store(ARM64CPU *c, PhysMem *mem, uint64_t va, int sz, uint64_t val)
{
    /* Check watchpoints */
    for (int i = 0; i < c->wp_count; i++) {
        if (c->wp[i].type == 0) continue;
        uint64_t wp_end = c->wp[i].addr + c->wp[i].len;
        if (va >= c->wp[i].addr && va < wp_end &&
            (c->wp[i].type & 2)) {
            c->stopped = true;
        }
    }

    if (mmu_on(c)) {
        if (!mmu_store(c, mem, va, sz, val)) {
            /* Translation fault → Data Abort at EL1 (store). Only after VBAR is set. */
            if (c->vbar_el1 != 0) {
                static uint64_t store_fault_count = 0;
                store_fault_count++;
                if (store_fault_count <= 50 || (store_fault_count % 10000) == 0)
                    fprintf(stderr, "[DATA-ABORT-STORE#%llu] VA=0x%016llx PC=0x%016llx val=0x%llx\n",
                            (unsigned long long)store_fault_count,
                            (unsigned long long)va, (unsigned long long)c->pc,
                            (unsigned long long)val);
                cpu_take_exception(c, (0x25ULL << 26) | 0x44ULL, va, EL1);
            }
            return -1;
        }
    } else {
        mem_write(mem, va, val, sz);
    }
    return 1;
}

static int cpu_fetch(ARM64CPU *c, PhysMem *mem, uint64_t va, uint32_t *out)
{
    if (mmu_on(c)) {
        uint32_t v;
        if (!mmu_read_u32(c, mem, va, &v)) {
            /* Instruction fetch abort: EC=0x20 (InsnAbort lower EL) or 0x21 (InsnAbort same EL).
             * We're at EL1 fetching kernel code → same EL → EC=0x21.
             * IFSC=0x04 (translation fault level 0 — simplified; covers any page-not-present). */
            static int fetch_abort_log = 0;
            if (fetch_abort_log < 10) {
                fprintf(stderr, "[FETCH-ABORT#%d] VA=0x%llx insn_count=%llu\n",
                        ++fetch_abort_log, (unsigned long long)va,
                        (unsigned long long)c->insn_count);
                /* Manual L1 walk to pinpoint why translation failed */
                if (fetch_abort_log <= 2) {
                    uint64_t ttbr1 = c->ttbr1_el1 & ~0xFFFULL;
                    uint64_t l1_idx = (va >> 30) & 0x1FF;
                    uint64_t l1_pa  = ttbr1 + l1_idx * 8;
                    uint64_t l1_val = mem_read(mem, l1_pa, 8);   /* PHYSICAL read */
                    uint64_t l2_base = l1_val & ~0xFFFULL;
                    uint64_t l2_idx  = (va >> 21) & 0x1FF;
                    uint64_t l2_pa   = l2_base + l2_idx * 8;
                    uint64_t l2_val  = (l1_val & 3) == 3 ? mem_read(mem, l2_pa, 8) : 0xDEAD;
                    fprintf(stderr,
                        "  TTBR1=0x%llx L1[%llu]@0x%llx=0x%016llx"
                        "  L2[%llu]@0x%llx=0x%016llx\n",
                        (unsigned long long)ttbr1,
                        (unsigned long long)l1_idx, (unsigned long long)l1_pa,
                        (unsigned long long)l1_val,
                        (unsigned long long)l2_idx, (unsigned long long)l2_pa,
                        (unsigned long long)l2_val);
                }
            }
            cpu_take_exception(c, (0x21ULL << 26) | 0x04ULL, va, EL1);
            return -1;
        }
        *out = v;
    } else {
        *out = (uint32_t)mem_read(mem, va, 4);
    }
    return 0;
}

/* ============================================================
 * Exception injection
 * ============================================================ */

void cpu_take_exception(ARM64CPU *c, uint64_t esr, uint64_t far, int target_el)
{
    static uint64_t exc_count = 0;
    exc_count++;
    /* Also log first 30 exceptions near stuck PACIASP address */
    static int exc_near_spin = 0;
    bool near_spin = (c->pc >= 0xffffffc0080b7f70ULL && c->pc <= 0xffffffc0080b7fa0ULL)
                  && exc_near_spin < 30;
    if (near_spin) exc_near_spin++;
    if (exc_count <= 10 || (exc_count % 1000) == 0 || near_spin)
        fprintf(stderr, "[EXCEP#%llu] PC=0x%llx EC=0x%02x ESR=0x%08llx FAR=0x%016llx VBAR=0x%llx ELR=0x%llx SP=%llu caller=%p\n",
                (unsigned long long)exc_count,
                (unsigned long long)c->pc, (unsigned)(esr >> 26) & 0x3f,
                (unsigned long long)esr, (unsigned long long)far,
                (unsigned long long)c->vbar_el1,
                (unsigned long long)c->elr_el1,
                (unsigned long long)c->sp_el1,
                __builtin_return_address(0));
    /* Detect recursive exception loop: if the previous ELR_EL1 already points inside
     * the exception vector table (VBAR_EL1 .. VBAR_EL1+0x800), we are recursing.
     * After 5 such recursive faults at the same FAR, halt so we can inspect state. */
    if (c->vbar_el1 != 0 && c->elr_el1 != 0) {
        uint64_t vbar = c->vbar_el1;
        if (c->elr_el1 >= vbar && c->elr_el1 < vbar + 0x800) {
            static uint64_t rec_count = 0;
            static uint64_t rec_far   = 0;
            if (rec_far != far) { rec_far = far; rec_count = 0; }
            rec_count++;
            fprintf(stderr, "[RECURSIVE-EXCEP#%llu] elr=0x%llx far=0x%llx ec=0x%02x — exception handler itself faulted!\n",
                    (unsigned long long)rec_count,
                    (unsigned long long)c->elr_el1,
                    (unsigned long long)far,
                    (unsigned)(esr >> 26) & 0x3f);
            if (rec_count >= 5) {
                fprintf(stderr, "[HALT] Recursive exception loop detected at FAR=0x%llx. Dumping regs and stopping.\n",
                        (unsigned long long)far);
                fprintf(stderr, "  VBAR=0x%llx ELR=0x%llx SPSR=0x%llx ESR=0x%llx FAR=0x%llx\n",
                        (unsigned long long)c->vbar_el1, (unsigned long long)c->elr_el1,
                        (unsigned long long)c->spsr_el1, (unsigned long long)c->esr_el1,
                        (unsigned long long)c->far_el1);
                fprintf(stderr, "  SP_EL1=0x%llx\n", (unsigned long long)c->sp_el1);
                c->halted = true;
                return;
            }
        }
    }
    /* Detect kernel null-ptr write spiral: EC=0x25 (data abort EL1), WnR=1,
     * FAR in very low VA (< 4MB).  This is the kernel exception handler
     * following a null pointer and writing to sequential low addresses, each
     * faulting because TTBR0 doesn't cover VA=0.  After 50 such exceptions,
     * halt — the kernel has panicked and the loop is unproductive. */
    {
        uint32_t ec_field = (esr >> 26) & 0x3f;
        bool is_write_fault = (ec_field == 0x25) && (esr & (1u << 6));
        if (is_write_fault && far < 0x400000ULL) {
            static uint64_t low_write_count = 0;
            if (++low_write_count == 1)
                fprintf(stderr, "[LOW-WRITE-FAULT#1] PC=0x%llx FAR=0x%llx — kernel null-ptr spiral detected\n",
                        (unsigned long long)c->pc, (unsigned long long)far);
            if (low_write_count >= 50) {
                fprintf(stderr, "[HALT] Kernel null-ptr write spiral: %llu write faults at VA<4MB. Last FAR=0x%llx PC=0x%llx\n",
                        (unsigned long long)low_write_count,
                        (unsigned long long)far, (unsigned long long)c->pc);
                c->halted = true;
                return;
            }
        }
    }

    /* Exceptions invalidate the exclusive monitor per ARM spec */
    c->excl_valid = false;

    /* Save state to EL1 (we only support EL0/EL1) */
    c->spsr_el1 = c->pstate;
    c->elr_el1  = c->pc;
    c->esr_el1  = esr;
    c->far_el1  = far;

    /* Switch to EL1, SP_EL1, mask interrupts */
    c->pstate = (EL1 << PSTATE_EL_SHIFT) | PSTATE_SP |
                PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F;

    /* Vector offset:
     * Current EL with SP0: 0x000
     * Current EL with SPx: 0x200
     * Lower EL AArch64:    0x400
     * Lower EL AArch32:    0x600
     * +0x000 = Sync, +0x080 = IRQ, +0x100 = FIQ, +0x180 = SError
     */
    int src_el = (c->spsr_el1 >> PSTATE_EL_SHIFT) & 3;
    uint64_t vec_base = c->vbar_el1;
    uint64_t offset;

    /* Determine vector type (sync/irq) from ESR class */
    uint32_t ec = (esr >> 26) & 0x3f;
    bool is_irq = (ec == 0);  /* 0 = unknown/IRQ */

    if (src_el == 0) {
        offset = 0x400;  /* lower EL AArch64 */
    } else {
        /* Same EL: SP_EL1 (PSTATE.SP=1) */
        offset = 0x200;
    }
    if (is_irq) offset += 0x080;
    /* else sync: offset unchanged */

    c->pc = vec_base + offset;
    c->exc_taken = true;
    c->halted = false;  /* exception cancels WFI */
}

/* ============================================================
 * IRQ check
 * ============================================================ */

void cpu_irq_check(ARM64CPU *c, EmuMachine *m)
{
    /* Check if IRQs are unmasked */
    if (c->pstate & PSTATE_I) return;

    /* Ask GIC if there's a pending IRQ for this CPU */
    int irq = gic_find_best_irq_for_cpu(&m->gic, c->id);
    if (irq < 0) return;

    static uint64_t irq_exc_count = 0;
    if (++irq_exc_count <= 10)
        fprintf(stderr, "[IRQ-EXCEPTION#%llu] IRQ=%d PC=0x%llx pstate=0x%08x\n",
                (unsigned long long)irq_exc_count, irq,
                (unsigned long long)c->pc, c->pstate);

    /* ESR for IRQ = EC=0 (unknown), leave ISS=0 */
    cpu_take_exception(c, 0ULL, 0ULL, EL1);
}

/* ============================================================
 * System registers
 * ============================================================ */

static uint64_t sysreg_read(ARM64CPU *c, EmuMachine *m, uint32_t key)
{
    switch (key) {
    case SR_MIDR_EL1:      return 0x410FD034ULL;  /* Cortex-A53 */
    case SR_MPIDR_EL1:     return (uint64_t)c->id;  /* Aff0=cpu_id, U=0 (SMP) */
    case SR_CTR_EL0:       return 0x80030003ULL;
    case SR_SCTLR_EL1:     return c->sctlr_el1;
    case SR_CPACR_EL1:     return c->cpacr_el1;
    case SR_TCR_EL1:       return c->tcr_el1;
    case SR_TTBR0_EL1:     return c->ttbr0_el1;
    case SR_TTBR1_EL1:     return c->ttbr1_el1;
    case SR_MAIR_EL1:      return c->mair_el1;
    case SR_VBAR_EL1:      return c->vbar_el1;
    case SR_ESR_EL1:       return c->esr_el1;
    case SR_FAR_EL1:       return c->far_el1;
    case SR_ELR_EL1:       return c->elr_el1;
    case SR_SPSR_EL1:      return c->spsr_el1;
    case SR_SP_EL0:        return c->sp_el0;
    case SR_TPIDR_EL0:     return c->tpidr_el0;
    case SR_TPIDRRO_EL0:   return c->tpidrro_el0;
    case SR_TPIDR_EL1:     return c->tpidr_el1;
    case SR_CNTKCTL_EL1:   return c->cntkctl_el1;
    case SR_CNTFRQ_EL0:    return m->timer.cntfrq;
    case SR_CNTPCT_EL0:    return machine_read_cntpct(m);
    case SR_CNTVCT_EL0:    return machine_read_cntpct(m);  /* virtual = physical */
    case SR_CNTP_CTL_EL0: {
        uint64_t ctl = c->cntp_ctl_el0 & 3;
        if ((ctl & 1) && machine_read_cntpct(m) >= c->cntp_cval_el0)
            ctl |= 4;
        return ctl;
    }
    case SR_CNTP_CVAL_EL0: return c->cntp_cval_el0;
    case SR_CNTP_TVAL_EL0: {
        uint64_t cnt = machine_read_cntpct(m);
        return (uint32_t)(c->cntp_cval_el0 - cnt);
    }
    case SR_CNTV_CTL_EL0: {
        uint64_t ctl = c->cntv_ctl_el0 & 3;
        if ((ctl & 1) && machine_read_cntpct(m) >= c->cntv_cval_el0)
            ctl |= 4;
        return ctl;
    }
    case SR_CNTV_CVAL_EL0: return c->cntv_cval_el0;
    case SR_CNTV_TVAL_EL0: {
        uint64_t cnt = machine_read_cntpct(m);
        return (uint32_t)(c->cntv_cval_el0 - cnt);
    }
    case SR_CURRENTEL:     return c->pstate & PSTATE_EL_MASK;
    case SR_DAIF:          return c->pstate & (PSTATE_D|PSTATE_A|PSTATE_I|PSTATE_F);
    case SR_NZCV:          return c->pstate & (PSTATE_N|PSTATE_Z|PSTATE_C|PSTATE_V);
    case SR_SPSel:         return (c->pstate & PSTATE_SP) ? 1 : 0;
    case SR_DCZID_EL0:     return 4;  /* DC ZVA block size 64 bytes */
    case SR_ID_AA64MMFR0_EL1: return 0x1122ULL;  /* 48-bit VA/PA */
    case SR_ID_AA64MMFR1_EL1: return 0;
    case SR_ID_AA64MMFR2_EL1: return 0;
    case SR_ID_AA64PFR0_EL1:  return 0x11ULL;    /* EL0/EL1 AArch64 */
    case SR_ID_AA64PFR1_EL1:  return 0;
    case SR_ID_AA64ISAR0_EL1: return 0;
    case SR_ID_AA64ISAR1_EL1: return 0;
    case SR_ID_AA64DFR0_EL1:  return 0x6ULL;
    case SR_MDSCR_EL1:     return c->mdscr_el1;
    case SR_OSLAR_EL1:     return 0;
    case SR_OSLSR_EL1:     return 0;
    case SR_OSDLR_EL1:     return 0;
    case SR_DBGPRCR_EL1:   return 0;
    case SR_PMCR_EL0:      return 0x41000000ULL;
    case SR_PMCNTENSET_EL0:return 0;
    case SR_PMUSERENR_EL0: return 0;
    case SR_PMCCNTR_EL0:   return m->total_insns;
    case SR_HCR_EL2:       return c->hcr_el2;
    case SR_VPIDR_EL2:     return 0x410FD034ULL;
    case SR_VMPIDR_EL2:    return (uint64_t)c->id;
    case SR_CONTEXTIDR_EL1: return c->contextidr_el1;
    default:
        /* GIC system registers */
        return gic_sysreg_read(&m->gic, c->id, key);
    }
}

static void sysreg_write(ARM64CPU *c, EmuMachine *m, uint32_t key, uint64_t val)
{
    switch (key) {
    case SR_SCTLR_EL1:     c->sctlr_el1 = val; return;
    case SR_CPACR_EL1:     c->cpacr_el1 = val; return;
    case SR_TCR_EL1:       c->tcr_el1   = val; return;
    case SR_TTBR0_EL1: {
        static uint64_t ttbr0_count = 0; ttbr0_count++;
        if (ttbr0_count <= 5 || c->ttbr0_el1 != val)
            fprintf(stderr, "[MSR] TTBR0_EL1 <= 0x%016llx at PC=0x%016llx\n",
                    (unsigned long long)val, (unsigned long long)c->pc);
        c->ttbr0_el1 = val;
        mmu_tlb_flush_all(c);
        return;
    }
    case SR_TTBR1_EL1: {
        uint64_t old_ttbr1 = c->ttbr1_el1;
        static uint64_t ttbr1_count = 0; ttbr1_count++;
        if (ttbr1_count <= 5 || old_ttbr1 != val)
            fprintf(stderr, "[MSR] TTBR1_EL1 <= 0x%016llx at PC=0x%016llx\n",
                    (unsigned long long)val, (unsigned long long)c->pc);
        c->ttbr1_el1 = val;
        /* Boot fixup for ranchu arm64 kernel:
         * __create_page_tables only builds the idmap (TTBR0) and sets L1[257] of
         * swapper_pg_dir (linear map).  It never writes L1[256] (the kernel text
         * range 0xFFFFFFC000000000..0xFFFFFFC03FFFFFFF), so when __primary_switched
         * switches TTBR1 to swapper and BRs to a kernel VA, the translation faults.
         *
         * Fix: when swapper's L1[256] is still 0 after the second TTBR1 write,
         * synthesize a 4KB L2 table at a known-safe PA (0x4F000000, above kernel
         * BSS/initrd) and wire it in.  KIMAGE_VADDR = 0xFFFFFFC008000000 lands at
         * L2[64] within L1[256]; each entry maps a 2MB block.
         *
         * The L2 PA (0x4F000000) is above the 31MB kernel binary (~0x41F00000),
         * above initrd (~0x481D0000), and below RAM end (0x60000000). The BSS
         * clear in __primary_switched operates on kernel VAs (L1[256] mapping),
         * and BSS ends well below the VA that maps 0x4F000000, so it survives. */
        if (old_ttbr1 != 0 && val != 0 && old_ttbr1 != val) {
            uint64_t old_base = old_ttbr1 & ~0xFFFULL;
            uint64_t new_base = val       & ~0xFFFULL;
            uint64_t old_l1_256 = mem_read(&m->mem, old_base + 256*8, 8);
            uint64_t new_l1_256 = mem_read(&m->mem, new_base + 256*8, 8);
            fprintf(stderr, "[TTBR1-SWITCH] old=0x%llx L1[256]=0x%llx  new=0x%llx L1[256]=0x%llx\n",
                    (unsigned long long)old_base, (unsigned long long)old_l1_256,
                    (unsigned long long)new_base, (unsigned long long)new_l1_256);
            if (new_l1_256 == 0) {
                if (old_l1_256 != 0) {
                    /* Trampoline had it — just copy */
                    mem_write(&m->mem, new_base + 256*8, old_l1_256, 8);
                    fprintf(stderr, "[BOOT-FIXUP] Copied L1[256]=0x%llx from trampoline\n",
                            (unsigned long long)old_l1_256);
                } else {
                    /* Neither table has L1[256]: synthesize kernel text mapping.
                     * KIMAGE_VADDR=0xFFFFFFC008000000, PHYS_OFFSET=0x40000000.
                     * VA offset in L1[256] window = 0x08000000 → L2[64].
                     * PA formula: PA = 0x38000000 + L2_index * 2MB (derived from
                     *   PA = VA - KIMAGE_VOFFSET where KIMAGE_VOFFSET=0xFFFFFFBFC8000000). */
                    const uint64_t L2_PA    = 0x4F000000ULL; /* safe free PA */
                    const uint64_t L2_START = 64;            /* L2 idx of KIMAGE_VADDR */
                    const uint64_t L2_COUNT = 256;           /* 512MB / 2MB = enough */
                    const uint64_t kram_base = 0x40000000ULL;
                    const uint64_t kram_end  = 0x60000000ULL;
                    /* TABLE descriptor: L1[256] → L2 table at L2_PA */
                    mem_write(&m->mem, new_base + 256*8, L2_PA | 0x3ULL, 8);
                    /* 2MB block descriptors: AP=0 (EL1 RW), SH=3, AF=1, valid, block */
                    for (uint64_t i = L2_START; i < L2_START + L2_COUNT; i++) {
                        uint64_t pa = 0x38000000ULL + i * 0x200000ULL;
                        if (pa < kram_base || pa >= kram_end) continue;
                        uint64_t entry = pa | 0x701ULL; /* block, AF, SH=3, AP=0 */
                        mem_write(&m->mem, L2_PA + i * 8, entry, 8);
                    }
                    fprintf(stderr, "[BOOT-FIXUP] Synthesized kernel text L2 at 0x%llx"
                            " L1[256]=0x%llx\n",
                            (unsigned long long)L2_PA,
                            (unsigned long long)(L2_PA | 0x3ULL));

                    /* Synthesize linear map: L1[0] → L2_LM at 0x4F001000.
                     * PAGE_OFFSET = 0xFFFFFF8000000000 (T1SZ=25), PHYS_OFFSET=0x40000000.
                     * VA 0xFFFFFF8000000000 + i*2MB → PA 0x40000000 + i*2MB for i=0..255.
                     * The kernel needs this to access its own data structures, page tables,
                     * per-CPU areas, stack, kmalloc, etc. Without it, all linear-map
                     * accesses (which is nearly everything) return 0 or fault. */
                    const uint64_t LM_L2_PA  = 0x4F001000ULL; /* 4KB page just after ktext L2 */
                    const uint64_t LM_BLOCKS = 256;            /* 256 × 2MB = 512MB of RAM */
                    mem_write(&m->mem, new_base + 0*8, LM_L2_PA | 0x3ULL, 8); /* L1[0] = TABLE */
                    for (uint64_t i = 0; i < LM_BLOCKS; i++) {
                        uint64_t pa = kram_base + i * 0x200000ULL;
                        uint64_t entry = pa | 0x701ULL;
                        mem_write(&m->mem, LM_L2_PA + i * 8, entry, 8);
                    }
                    fprintf(stderr, "[BOOT-FIXUP] Synthesized linear map L2 at 0x%llx"
                            " L1[0]=0x%llx (PA 0x%llx..0x%llx)\n",
                            (unsigned long long)LM_L2_PA,
                            (unsigned long long)(LM_L2_PA | 0x3ULL),
                            (unsigned long long)kram_base,
                            (unsigned long long)(kram_base + LM_BLOCKS*0x200000ULL - 1));
                }
            }
            /* TCR_EL1 is 0 when booting at EL1: the only msr tcr_el1 in the binary
             * (PA 0x410469fc) copies from tcr_el12 which is only accessible at EL2.
             * Without a valid TCR, T1SZ=0 → VA_bits=64 → start_level=0, so the MMU
             * walks L0 (not L1) and finds nothing → all kernel VA loads return 0.
             * Force T1SZ=T0SZ=25 (39-bit VA), 4KB granule, IS, WB-WA, IPS=40-bit. */
            if (c->tcr_el1 == 0) {
                c->tcr_el1 = 0x00000002B5193519ULL;
                fprintf(stderr, "[BOOT-FIXUP] Set TCR_EL1=0x%016llx"
                        " (T1SZ=25 T0SZ=25 TG0=4K TG1=4K SH=IS IRGN/ORGN=WB IPS=40b)\n",
                        (unsigned long long)c->tcr_el1);
            }
            /* Dump all non-zero L1 entries of the new swapper table */
            fprintf(stderr, "[SWAPPER-L1-DUMP] base=0x%llx:\n", (unsigned long long)new_base);
            for (int li = 0; li < 512; li++) {
                uint64_t e = mem_read(&m->mem, new_base + (uint64_t)li * 8, 8);
                if (e != 0)
                    fprintf(stderr, "  L1[%d]=0x%016llx\n", li, (unsigned long long)e);
            }
        }
        /* Only invalidate snapshots when the page table root actually changes.
         * Linux ARM64 issues MSR TTBR1_EL1, Xn (same value) as an ASID-flush
         * idiom around context switches; this must NOT reset the snapshot or
         * the next fetch re-reads corrupted physical memory. */
        if ((c->ttbr1_el1 & ~0xFFFFULL) != (old_ttbr1 & ~0xFFFFULL))
            mmu_l1snap_invalidate(c);
        else
            mmu_tlb_flush_all(c);  /* same page table: flush TLB/PTC but keep snap */
        return;
    }
    case SR_MAIR_EL1:      c->mair_el1  = val; return;
    case SR_VBAR_EL1:
        fprintf(stderr, "[MSR] VBAR_EL1 <= 0x%016llx at PC=0x%016llx\n",
                (unsigned long long)val, (unsigned long long)c->pc);
        c->vbar_el1 = val;
        return;
    case SR_ELR_EL1:       c->elr_el1   = val; return;
    case SR_SPSR_EL1:      c->spsr_el1  = val; return;
    case SR_SP_EL0:        c->sp_el0    = val; return;
    case SR_ESR_EL1:       c->esr_el1   = val; return;
    case SR_FAR_EL1:       c->far_el1   = val; return;
    case SR_TPIDR_EL0:     c->tpidr_el0 = val; return;
    case SR_TPIDRRO_EL0:   c->tpidrro_el0 = val; return;
    case SR_TPIDR_EL1:     c->tpidr_el1 = val; return;
    case SR_CNTKCTL_EL1:   c->cntkctl_el1 = val; return;
    case SR_CNTP_CTL_EL0:
        /* ISTATUS (bit 2) is read-only; only ENABLE (0) and IMASK (1) are writable */
        c->cntp_ctl_el0 = (c->cntp_ctl_el0 & ~3ULL) | (val & 3);
        return;
    case SR_CNTP_CVAL_EL0: c->cntp_cval_el0 = val; return;
    case SR_CNTP_TVAL_EL0: {
        uint64_t cnt = machine_read_cntpct(m);
        c->cntp_cval_el0 = cnt + (int32_t)(uint32_t)val;
        return;
    }
    case SR_CNTV_CTL_EL0:
        c->cntv_ctl_el0 = (c->cntv_ctl_el0 & ~3ULL) | (val & 3);
        return;
    case SR_CNTV_CVAL_EL0: c->cntv_cval_el0 = val; return;
    case SR_CNTV_TVAL_EL0: {
        uint64_t cnt = machine_read_cntpct(m);
        c->cntv_cval_el0 = cnt + (int32_t)(uint32_t)val;
        return;
    }
    case SR_DAIF: {
        c->pstate &= ~(PSTATE_D|PSTATE_A|PSTATE_I|PSTATE_F);
        c->pstate |= val & (PSTATE_D|PSTATE_A|PSTATE_I|PSTATE_F);
        return;
    }
    case SR_NZCV: {
        c->pstate &= ~(PSTATE_N|PSTATE_Z|PSTATE_C|PSTATE_V);
        c->pstate |= val & (PSTATE_N|PSTATE_Z|PSTATE_C|PSTATE_V);
        return;
    }
    case SR_SPSel: {
        if (val & 1) c->pstate |= PSTATE_SP;
        else c->pstate &= ~PSTATE_SP;
        return;
    }
    case SR_MDSCR_EL1:     c->mdscr_el1 = val; return;
    case SR_OSLAR_EL1:
    case SR_OSLSR_EL1:
    case SR_OSDLR_EL1:
    case SR_DBGPRCR_EL1:
    case SR_PMCR_EL0:
    case SR_PMCNTENSET_EL0:
    case SR_PMUSERENR_EL0:
    case SR_PMCCNTR_EL0:
        return;  /* ignore perf/debug writes */
    case SR_HCR_EL2:       c->hcr_el2 = val; return;
    case SR_VPIDR_EL2:     c->vpidr_el2 = val; return;
    case SR_VMPIDR_EL2:    c->vmpidr_el2 = val; return;
    case SR_CONTEXTIDR_EL1: c->contextidr_el1 = val; return;
    default:
        /* TLBI instructions all have CRn=8; flush TLB on any such write */
        if (((key >> 7) & 0xF) == 8) {
            mmu_tlb_flush_all(c);
            return;
        }
        gic_sysreg_write(&m->gic, c->id, key, val);
        return;
    }
}

/* ============================================================
 * Data Processing Immediate
 * bits[28:23] classify sub-type
 * ============================================================ */

static int exec_dp_imm(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    (void)m;
    uint32_t op = (insn >> 23) & 0x7;  /* bits[25:23] */
    bool sf = (insn >> 31) & 1;

    switch (op) {
    /* ADR / ADRP */
    case 0:
    case 1: {
        if (((insn >> 24) & 0x1f) == 0x10) {
            /* ADR: immhi[23:5], immlo[30:29] */
            bool adrp = (insn >> 31) & 1;
            int64_t imm = ((int64_t)((insn >> 5) & 0x7ffff) << 2) |
                          ((insn >> 29) & 3);
            if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
            uint64_t rd = insn & 0x1f;
            uint64_t base = adrp ? (c->pc & ~0xFFFULL) : c->pc;
            if (adrp) imm <<= 12;
            cpu_set_xreg(c, rd, base + (uint64_t)imm);
            return 0;
        }
        break;
    }

    /* Add/Sub immediate: bits[28:23] = 0b00x_xxx, op=4..7 when bit23 */
    default:
        break;
    }

    /* More specific decode via bits[28:24] */
    uint32_t type = (insn >> 22) & 0x1ff;  /* bits[30:22] */

    /* Add/Sub imm12: bits[28:24] = 10001 or 11001 */
    if ((insn & 0x1f000000) == 0x11000000 || (insn & 0x1f000000) == 0x51000000 ||
        (insn & 0x1f000000) == 0x31000000 || (insn & 0x1f000000) == 0x71000000) {
        /* Decode as Add/Sub imm */
        bool is_sub = (insn >> 30) & 1;
        bool setflags = (insn >> 29) & 1;
        uint32_t shift = (insn >> 22) & 3;
        uint64_t imm = (insn >> 10) & 0xfff;
        if (shift == 1) imm <<= 12;
        uint32_t rn = (insn >> 5) & 0x1f;
        uint32_t rd = insn & 0x1f;

        uint64_t operand1 = rn == 31 ? cpu_sp(c) : cpu_xreg(c, rn);
        if (!sf) operand1 &= 0xFFFFFFFF;
        uint64_t result;

        if (is_sub) {
            result = operand1 - imm;
            if (setflags) {
                if (sf) sub_flags64(c, operand1, imm, result);
                else sub_flags32(c, (uint32_t)operand1, (uint32_t)imm, (uint32_t)result);
            }
        } else {
            result = operand1 + imm;
            if (setflags) {
                if (sf) add_flags64(c, operand1, imm, result);
                else add_flags32(c, (uint32_t)operand1, (uint32_t)imm, (uint32_t)result);
            }
        }
        if (!sf) result &= 0xFFFFFFFF;

        if (!setflags && rd == 31) {
            /* SP result */
            cpu_set_sp(c, result);
        } else {
            cpu_set_xreg(c, rd, result);
        }
        return 0;
    }

    /* Logical imm: bits[28:23] = 00100x / 10100x */
    if ((insn & 0x1f800000) == 0x12000000 || /* AND */
        (insn & 0x1f800000) == 0x32000000 || /* ORR */
        (insn & 0x1f800000) == 0x52000000 || /* EOR */
        (insn & 0x1f800000) == 0x72000000) { /* ANDS */
        uint32_t opc = (insn >> 29) & 3;
        uint32_t n_bit = (insn >> 22) & 1;
        uint32_t immr = (insn >> 16) & 0x3f;
        uint32_t imms = (insn >> 10) & 0x3f;
        uint32_t rn = (insn >> 5) & 0x1f;
        uint32_t rd = insn & 0x1f;
        uint64_t imm;
        if (!decode_bit_masks(n_bit, imms, immr, sf, &imm, NULL)) {
            /* UNDEFINED */
            cpu_take_exception(c, (0x0ULL << 26), c->pc, EL1);
            return -1;
        }
        uint64_t rn_val = (rn == 31) ? 0 : cpu_xreg(c, rn);
        if (!sf) rn_val &= 0xFFFFFFFF;
        uint64_t result;
        switch (opc) {
        case 0: result = rn_val & imm; break;
        case 1: result = rn_val | imm; break;
        case 2: result = rn_val ^ imm; break;
        case 3: result = rn_val & imm; /* ANDS */
            set_nzcv(c, !!(result >> (sf?63:31)), result==0, false, false);
            cpu_set_xreg(c, rd, sf ? result : (result & 0xFFFFFFFF));
            return 0;
        default: result = 0; break;
        }
        if (!sf) result &= 0xFFFFFFFF;
        if (opc == 0 && rd == 31) cpu_set_sp(c, result);
        else cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* MOV (wide immediate): bits[28:23] = 10010x / 11010x / 11110x */
    /* MOVN = 0b00, MOVZ = 0b10, MOVK = 0b11 */
    if ((insn & 0x1F800000) == 0x12800000 ||  /* MOVN 32 */
        (insn & 0x1F800000) == 0x52800000 ||  /* MOVZ 32 */
        (insn & 0x1F800000) == 0x72800000 ||  /* MOVK 32 */
        (insn & 0x1F800000) == 0x92800000 ||  /* MOVN 64 */
        (insn & 0x1F800000) == 0xD2800000 ||  /* MOVZ 64 */
        (insn & 0x1F800000) == 0xF2800000) {  /* MOVK 64 */
        uint32_t opc = (insn >> 29) & 3;
        uint32_t hw  = (insn >> 21) & 3;
        uint64_t imm16 = (insn >> 5) & 0xffff;
        uint32_t rd = insn & 0x1f;
        uint64_t imm = imm16 << (hw * 16);
        uint64_t result;
        switch (opc) {
        case 0: /* MOVN */ result = ~imm; if (!sf) result &= 0xFFFFFFFF; break;
        case 2: /* MOVZ */ result = imm;  if (!sf) result &= 0xFFFFFFFF; break;
        case 3: /* MOVK */ {
            uint64_t mask = ~(0xFFFFULL << (hw * 16));
            result = (cpu_xreg(c, rd) & mask) | imm;
            if (!sf) result &= 0xFFFFFFFF;
            break;
        }
        default: result = 0; break;
        }
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Bitfield: SBFM / BFM / UBFM */
    if ((insn & 0x1F800000) == 0x13000000 ||  /* SBFM 32 */
        (insn & 0x1F800000) == 0x33000000 ||  /* BFM  32 */
        (insn & 0x1F800000) == 0x53000000 ||  /* UBFM 32 */
        (insn & 0x1F800000) == 0x93000000 ||  /* SBFM 64 */
        (insn & 0x1F800000) == 0xB3000000 ||  /* BFM  64 */
        (insn & 0x1F800000) == 0xD3000000) {  /* UBFM 64 */
        uint32_t opc  = (insn >> 29) & 3;
        uint32_t immr = (insn >> 16) & 0x3f;
        uint32_t imms = (insn >> 10) & 0x3f;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        uint64_t wmask, tmask;
        if (!decode_bit_masks((insn>>22)&1, imms, immr, sf, &wmask, &tmask))
            return 0; /* UNDEFINED but ignore */

        uint64_t rn_val = cpu_xreg(c, rn);
        if (!sf) rn_val &= 0xFFFFFFFF;

        /* ROR(rn, immr) */
        uint64_t src = sf ? ((rn_val >> immr) | (rn_val << (64 - immr)))
                          : (((rn_val & 0xFFFFFFFF) >> immr) | ((rn_val & 0xFFFFFFFF) << (32 - immr)));
        if (!sf) src &= 0xFFFFFFFF;

        uint64_t result;
        switch (opc) {
        case 0: { /* SBFM: sign extend */
            result = src & tmask;
            /* sign extend from bit imms */
            if (imms < (sf ? 63 : 31)) {
                uint64_t sign = (rn_val >> imms) & 1;
                if (sign) result |= ~tmask;
            }
            break;
        }
        case 1: { /* BFM */
            uint64_t rd_val = cpu_xreg(c, rd);
            result = (rd_val & ~wmask) | (src & wmask);
            break;
        }
        case 2: /* UBFM */
            result = src & tmask;
            break;
        default: result = 0; break;
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* EXTR (rotate right into register) */
    if ((insn & 0x1F800000) == 0x13800000 ||
        (insn & 0x1F800000) == 0x93C00000) {
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t imms = (insn >> 10) & 0x3f;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        uint64_t hi = cpu_xreg(c, rn);
        uint64_t lo = cpu_xreg(c, rm);
        uint64_t result;
        if (sf) {
            if (imms == 0) result = hi;
            else result = (hi << (64 - imms)) | (lo >> imms);
        } else {
            uint64_t pair = ((hi & 0xFFFFFFFF) << 32) | (lo & 0xFFFFFFFF);
            result = (pair >> imms) & 0xFFFFFFFF;
        }
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Unknown DP-imm: treat as NOP (many Linux init regs we don't need) */
    return 0;
}

/* ============================================================
 * Branches and system instructions
 * ============================================================ */

static int exec_branch(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    uint32_t op = (insn >> 25) & 0x7f;

    /* B / BL unconditional: bit31=0/1, bits[25:24]=00,01 → op=0b00 */
    if ((insn & 0x7C000000) == 0x14000000) {
        bool link = (insn >> 31) & 1;
        int64_t imm = (int64_t)(insn & 0x03FFFFFF);
        if (imm & (1LL << 25)) imm |= ~((1LL << 26) - 1);
        imm <<= 2;
        if (link) c->x[30] = c->pc + 4;
        c->pc += (uint64_t)imm;
        return 1;  /* PC already updated */
    }

    /* B.cond: 0101 0100 ... */
    if ((insn & 0xFF000010) == 0x54000000) {
        uint32_t cond4 = insn & 0xF;
        int64_t imm = (int64_t)((insn >> 5) & 0x7FFFF);
        if (imm & (1LL << 18)) imm |= ~((1LL << 19) - 1);
        imm <<= 2;
        if (check_cond(c, cond4)) {
            c->pc += (uint64_t)imm;
            return 1;
        }
        return 0;
    }

    /* CBZ / CBNZ: 0x1A4... */
    if ((insn & 0x7E000000) == 0x34000000) {
        bool nz = (insn >> 24) & 1;
        bool sf = (insn >> 31) & 1;
        uint32_t rt = insn & 0x1f;
        int64_t imm = (int64_t)((insn >> 5) & 0x7FFFF);
        if (imm & (1LL << 18)) imm |= ~((1LL << 19) - 1);
        imm <<= 2;
        uint64_t val = cpu_xreg(c, rt);
        if (!sf) val &= 0xFFFFFFFF;
        bool taken = nz ? (val != 0) : (val == 0);
        if (taken) { c->pc += (uint64_t)imm; return 1; }
        return 0;
    }

    /* TBZ / TBNZ */
    if ((insn & 0x7E000000) == 0x36000000) {
        bool nz = (insn >> 24) & 1;
        uint32_t b5 = (insn >> 31) & 1;
        uint32_t b40 = (insn >> 19) & 0x1f;
        uint32_t bit_pos = (b5 << 5) | b40;
        uint32_t rt = insn & 0x1f;
        int64_t imm = (int64_t)((insn >> 5) & 0x3FFF);
        if (imm & (1LL << 13)) imm |= ~((1LL << 14) - 1);
        imm <<= 2;
        uint64_t val = cpu_xreg(c, rt);
        bool bit_set = !!(val & (1ULL << bit_pos));
        bool taken = nz ? bit_set : !bit_set;
        if (taken) { c->pc += (uint64_t)imm; return 1; }
        return 0;
    }

    /* BR / BLR / RET / ERET / SVC / HVC / SMC / BRK / HLT / MRS / MSR */
    if ((insn & 0xFF000000) == 0xD4000000) {
        uint32_t opc = (insn >> 21) & 3;
        uint32_t imm16 = (insn >> 5) & 0xFFFF;
        switch (opc) {
        case 0: /* SVC */
            cpu_take_exception(c, (0x15ULL << 26) | imm16, c->pc, EL1);
            return 1;
        case 1: { /* HVC — PSCI dispatch */
            uint64_t fn = c->x[0];
            static uint64_t hvc_log = 0;
            if (hvc_log < 16)
                fprintf(stderr, "[HVC#%llu] PC=0x%llx fn=0x%llx X1=0x%llx X2=0x%llx X3=0x%llx\n",
                        ++hvc_log, (unsigned long long)c->pc,
                        (unsigned long long)fn,
                        (unsigned long long)c->x[1],
                        (unsigned long long)c->x[2],
                        (unsigned long long)c->x[3]);
            else hvc_log++;
            switch (fn) {
            case 0x84000000: /* PSCI_VERSION */
                c->x[0] = 0x00020000;  /* version 2.0 */
                break;
            case 0x84000001: /* CPU_SUSPEND 32 */
            case 0xC4000001: /* CPU_SUSPEND 64 */
                c->x[0] = 0;  /* SUCCESS — shallow suspend, return immediately */
                break;
            case 0x84000002: /* CPU_OFF */
                c->halted = true;
                c->x[0] = 0;
                break;
            case 0x84000003: /* CPU_ON 32 */
            case 0xC4000003: /* CPU_ON 64 */ {
                uint64_t target_mpidr = c->x[1];
                uint64_t entry_pa     = c->x[2];
                uint64_t context_id   = c->x[3];
                int target_aff0 = (int)(target_mpidr & 0xff);
                ARM64CPU *tgt = NULL;
                for (int ci = 0; ci < m->num_cpus; ci++) {
                    if (m->cpu[ci].id == target_aff0) { tgt = &m->cpu[ci]; break; }
                }
                if (!tgt) { c->x[0] = (uint64_t)-2; break; }  /* INVALID_PARAMS */
                if (!tgt->halted) { c->x[0] = (uint64_t)-4; break; }  /* ALREADY_ON */
                /* Initialize secondary CPU state per PSCI spec */
                memset(tgt->x, 0, sizeof(tgt->x));
                tgt->x[0]      = context_id;
                tgt->pc        = entry_pa;
                tgt->pstate    = (EL1 << PSTATE_EL_SHIFT) | PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F | PSTATE_SP;
                tgt->sctlr_el1 = 0x00C50078ULL;  /* MMU off */
                tgt->sp_el0    = 0;
                tgt->sp_el1    = 0;
                tgt->halted    = false;
                tgt->exc_taken = false;
                fprintf(stderr, "[PSCI CPU_ON] cpu%d entry=0x%llx ctx=0x%llx\n",
                        target_aff0, (unsigned long long)entry_pa, (unsigned long long)context_id);
                c->x[0] = 0;  /* SUCCESS */
                break;
            }
            case 0x84000004: /* AFFINITY_INFO 32 */
            case 0xC4000004: /* AFFINITY_INFO 64 */
                c->x[0] = 0;  /* ON */
                break;
            case 0x84000008: /* SYSTEM_OFF */
                fprintf(stderr, "[PSCI SYSTEM_OFF]\n");
                m->exit_request = true;
                c->x[0] = 0;
                break;
            case 0x84000009: /* SYSTEM_RESET */
                fprintf(stderr, "[PSCI SYSTEM_RESET]\n");
                m->exit_request = true;
                c->x[0] = 0;
                break;
            default:
                /* KVM/pKVM host hypercalls (fn < 0x80000000) and unknown PSCI:
                 * return success so kernel doesn't loop or take broken fallback path */
                if (hvc_log <= 32)
                    fprintf(stderr, "[HVC-UNK] fn=0x%llx -> returning 0\n",
                            (unsigned long long)fn);
                c->x[0] = 0;
                break;
            }
            return 0;
        }
        case 2: /* SMC — treat as NOP */
            return 0;
        }
    }

    /* BRK — software breakpoint; vector to kernel's EL1 sync handler (VBAR+0x200).
     * Do NOT set c->stopped: the kernel's own BUG/WARN handler runs in the handler. */
    if ((insn & 0xFFE0001F) == 0xD4200000) {
        uint32_t imm16 = (insn >> 5) & 0xFFFF;
        static uint64_t brk_count = 0;
        brk_count++;
        if (brk_count <= 5 || (brk_count % 1000) == 0)
            fprintf(stderr, "[BRK#%llu] PC=0x%llx imm=0x%x\n",
                    (unsigned long long)brk_count, (unsigned long long)c->pc, imm16);
        cpu_take_exception(c, (0x3cULL << 26) | imm16, c->pc, EL1);
        return 1;
    }

    /* HLT */
    if ((insn & 0xFFE0001F) == 0xD4400000) {
        uint32_t imm16 = (insn >> 5) & 0xFFFF;
        fprintf(stderr, "[HLT] PC=0x%llx imm16=%u LR=0x%llx\n",
                (unsigned long long)c->pc, imm16, (unsigned long long)c->x[30]);
        c->halted = true;
        return 1;
    }

    /* BR/BLR/RET/ERET: unconditional branch (register) family
     * Pattern: bits[31:25]=1101011, bit[24]=0, bits[20:16]=11111
     * opc = bits[23:21]: 000=BR, 001=BLR, 010=RET, 100=ERET */
    if ((insn & 0xFE1F0000) == 0xD61F0000) {
        uint32_t opc = (insn >> 21) & 7;  /* 3-bit opc: bits[23:21] */
        uint32_t rn  = (insn >>  5) & 0x1f;
        switch (opc) {
        case 0: /* BR  */ c->pc = cpu_xreg(c, rn); break;
        case 1: /* BLR */ c->x[30] = c->pc + 4; c->pc = cpu_xreg(c, rn); break;
        case 2: /* RET */ {
            uint64_t ret_target = cpu_xreg(c, rn ? rn : 30);
            /* Log RET near the stuck PC range */
            if (c->pc >= 0x410630c0ULL && c->pc <= 0x410635d0ULL) {
                static int ret_log = 0;
                if (ret_log < 8)
                    fprintf(stderr, "[RET] PC=0x%llx X30=0x%llx (target)\n",
                            (unsigned long long)c->pc,
                            (unsigned long long)ret_target);
                ret_log++;
            }
            c->pc = ret_target;
            break;
        }
        case 4: /* ERET */ {
            static uint64_t eret_count = 0;
            eret_count++;
            if (eret_count <= 5 || (eret_count % 100000) == 0)
                fprintf(stderr, "[ERET#%llu] PC=0x%llx ELR=0x%llx SPSR=0x%08x\n",
                        (unsigned long long)eret_count,
                        (unsigned long long)c->pc,
                        (unsigned long long)c->elr_el1,
                        c->spsr_el1);
            c->pc     = c->elr_el1;
            c->pstate = c->spsr_el1;
            break;
        }
        default: /* DRPS, unallocated — treat as NOP */ break;
        }
        return 1;
    }

    /* MRS: read system register to Xt */
    if ((insn & 0xFFF00000) == 0xD5300000) {
        uint32_t o0  = (insn >> 19) & 1;
        uint32_t op1 = (insn >> 16) & 7;
        uint32_t crn = (insn >> 12) & 0xF;
        uint32_t crm = (insn >>  8) & 0xF;
        uint32_t op2 = (insn >>  5) & 7;
        uint32_t rt  = insn & 0x1f;
        uint32_t key = SYSREG_KEY(o0+2, op1, crn, crm, op2);
        cpu_set_xreg(c, rt, sysreg_read(c, m, key));
        return 0;
    }

    /* MSR immediate: MSR <pstatefield>, #imm */
    if ((insn & 0xFFF8F01F) == 0xD500401F) {
        uint32_t op1 = (insn >> 16) & 7;
        uint32_t crm = (insn >>  8) & 0xF;
        uint32_t op2 = (insn >>  5) & 7;
        uint64_t imm4 = crm & 0xF;
        /* DAIF clear/set: op1=3, op2=6=clear, op2=7=set */
        if (op1 == 3 && op2 == 6) {
            /* MSR DAIFClr */
            if (imm4 & 8) c->pstate &= ~PSTATE_D;
            if (imm4 & 4) c->pstate &= ~PSTATE_A;
            if (imm4 & 2) c->pstate &= ~PSTATE_I;
            if (imm4 & 1) c->pstate &= ~PSTATE_F;
        } else if (op1 == 3 && op2 == 7) {
            /* MSR DAIFSet */
            if (imm4 & 8) c->pstate |= PSTATE_D;
            if (imm4 & 4) c->pstate |= PSTATE_A;
            if (imm4 & 2) c->pstate |= PSTATE_I;
            if (imm4 & 1) c->pstate |= PSTATE_F;
        } else if (op1 == 0 && op2 == 5) {
            /* MSR SPSel */
            if (imm4 & 1) c->pstate |= PSTATE_SP;
            else c->pstate &= ~PSTATE_SP;
        }
        return 0;
    }

    /* MSR register: write system register from Xt */
    if ((insn & 0xFFF00000) == 0xD5100000) {
        uint32_t o0  = (insn >> 19) & 1;
        uint32_t op1 = (insn >> 16) & 7;
        uint32_t crn = (insn >> 12) & 0xF;
        uint32_t crm = (insn >>  8) & 0xF;
        uint32_t op2 = (insn >>  5) & 7;
        uint32_t rt  = insn & 0x1f;
        uint32_t key = SYSREG_KEY(o0+2, op1, crn, crm, op2);
        sysreg_write(c, m, key, cpu_xreg(c, rt));
        return 0;
    }

    /* ISB / DSB / DMB — memory barriers, treat as NOP */
    if ((insn & 0xFFFFF09F) == 0xD503309F) return 0;

    /* NOP */
    if (insn == 0xD503201F) return 0;

    /* Unknown branch/system — NOP rather than fault (many WFE/WFI etc.) */
    /* WFI */
    if (insn == 0xD503207F) {
        static uint64_t wfi_count = 0;
        ++wfi_count;
        if (wfi_count <= 4 || (wfi_count & 0xFFFF) == 0)
            fprintf(stderr, "[WFI#%llu] PC=0x%llx LR=0x%llx pstate=0x%08x VBAR=0x%llx SCTLR=0x%llx\n",
                    (unsigned long long)wfi_count,
                    (unsigned long long)c->pc,
                    (unsigned long long)c->x[30],
                    c->pstate,
                    (unsigned long long)c->vbar_el1,
                    (unsigned long long)c->sctlr_el1);
        c->halted = true;
        return 1;
    }
    /* WFE, SEV, SEVL, YIELD — NOP */
    if ((insn & 0xFFFFFFDF) == 0xD503205F) return 0;

    /* CLREX */
    if (insn == 0xD503304F) { c->excl_valid = false; return 0; }

    return 0;
}

/* ============================================================
 * Load/Store
 * ============================================================ */

static int exec_ldst(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    PhysMem *mem = &m->mem;
    /* Load/Store Exclusive: bits[29:24] = 001000.
     * Covers: LDXR, LDAXR, STXR, STLXR, LDXP, LDAXP, STXP, STLXP.
     * All have (insn & 0x3F000000) == 0x08000000. */
    if ((insn & 0x3F000000) == 0x08000000) {
        bool     sf      = (insn >> 30) & 1;   /* 0=32-bit, 1=64-bit */
        bool     is_pair = (insn >> 21) & 1;   /* LDXP/STXP */
        bool     L       = (insn >> 22) & 1;   /* 1=Load, 0=Store */
        uint32_t Rs      = (insn >> 16) & 0x1f;/* store-status dest */
        uint32_t Rt2     = (insn >> 10) & 0x1f;/* pair second reg */
        uint32_t Rn      = (insn >>  5) & 0x1f;/* base */
        uint32_t Rt      = insn & 0x1f;         /* data register */
        int sz           = sf ? 8 : 4;
        uint64_t addr    = (Rn == 31) ? cpu_sp(c) : cpu_xreg(c, Rn);
        PhysMem *mem     = &m->mem;
        if (L) {
            /* LDXR / LDAXR / LDXP / LDAXP */
            uint64_t val = 0;
            cpu_load(c, mem, addr, sz, false, sf, &val);
            if (Rt != 31) cpu_set_xreg(c, Rt, sf ? val : (val & 0xFFFFFFFF));
            if (is_pair) {
                uint64_t val2 = 0;
                cpu_load(c, mem, addr + sz, sz, false, sf, &val2);
                if (Rt2 != 31) cpu_set_xreg(c, Rt2, sf ? val2 : (val2 & 0xFFFFFFFF));
            }
            c->excl_valid = true;
            c->excl_addr  = addr;
        } else {
            /* STXR / STLXR / STXP / STLXP.
             * Single-CPU: always succeed if reservation was set. */
            bool ok = c->excl_valid;
            if (ok) {
                uint64_t val = (Rt == 31) ? 0 : (sf ? cpu_xreg(c, Rt) : cpu_xreg(c, Rt) & 0xFFFFFFFF);
                cpu_store(c, mem, addr, sz, val);
                if (is_pair) {
                    uint64_t val2 = (Rt2 == 31) ? 0 : (sf ? cpu_xreg(c, Rt2) : cpu_xreg(c, Rt2) & 0xFFFFFFFF);
                    cpu_store(c, mem, addr + sz, sz, val2);
                }
                c->excl_valid = false;
            }
            /* Rs = 0 on success, 1 on failure */
            if (Rs != 31) cpu_set_xreg(c, Rs, ok ? 0 : 1);
        }
        return 0;
    }

    /* LDR/STR literal (PC-relative) */
    if ((insn & 0x3B000000) == 0x18000000) {
        uint32_t opc = (insn >> 30) & 3;
        int64_t imm  = (int64_t)((insn >> 5) & 0x7FFFF);
        if (imm & (1LL << 18)) imm |= ~((1LL << 19) - 1);
        imm <<= 2;
        uint32_t rt  = insn & 0x1f;
        uint64_t addr = c->pc + (uint64_t)imm;
        uint64_t val = 0;
        switch (opc) {
        case 0: cpu_load(c, mem, addr, 4, false, false, &val); break;
        case 1: cpu_load(c, mem, addr, 8, false, true, &val); break;
        case 2: cpu_load(c, mem, addr, 4, true, true, &val); break; /* LDRSW */
        case 3: { /* PRFM — NOP */ return 0; }
        }
        cpu_set_xreg(c, rt, val);
        return 0;
    }

    /* LDP / STP */
    if ((insn & 0x3A000000) == 0x28000000) {
        bool is_store = !((insn >> 22) & 1);
        bool sf = (insn >> 31) & 1;
        bool is_simd = (insn >> 26) & 1;
        uint32_t opc = (insn >> 30) & 3;
        int sz = sf ? 8 : 4;
        if (opc == 1 && !sf) { /* LDPSW */ is_store = false; sz = 4; }

        int64_t imm7 = (int64_t)((insn >> 15) & 0x7F);
        if (imm7 & 0x40) imm7 |= ~0x7FLL;
        imm7 *= sz;

        uint32_t rt1 = insn & 0x1f;
        uint32_t rt2 = (insn >> 10) & 0x1f;
        uint32_t rn  = (insn >>  5) & 0x1f;
        uint32_t idx_mode = (insn >> 23) & 3; /* 1=post, 2=offset, 3=pre */

        uint64_t base = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        uint64_t addr = (idx_mode >= 2) ? base + (uint64_t)imm7 : base;

        if (is_simd) {
            /* FP/SIMD LDP/STP — simplified: treat as int */
        }

        if (is_store) {
            uint64_t v1 = cpu_xreg(c, rt1);
            uint64_t v2 = cpu_xreg(c, rt2);
            cpu_store(c, mem, addr,     sz, v1);
            cpu_store(c, mem, addr + sz, sz, v2);
        } else {
            uint64_t v1 = 0, v2 = 0;
            cpu_load(c, mem, addr,     sz, (opc==1), sf, &v1);
            cpu_load(c, mem, addr + sz, sz, (opc==1), sf, &v2);
            cpu_set_xreg(c, rt1, v1);
            cpu_set_xreg(c, rt2, v2);
        }

        if (idx_mode == 1) {
            /* post-index */
            uint64_t wb = base + (uint64_t)imm7;
            if (rn == 31) cpu_set_sp(c, wb);
            else cpu_set_xreg(c, rn, wb);
        } else if (idx_mode == 3) {
            /* pre-index */
            if (rn == 31) cpu_set_sp(c, addr);
            else cpu_set_xreg(c, rn, addr);
        }
        return 0;
    }

    /* Load/Store register (all modes) bits[29:28] */
    /* First decode size/opc */
    uint32_t size = (insn >> 30) & 3;   /* 0=8bit 1=16bit 2=32bit 3=64bit */
    uint32_t v    = (insn >> 26) & 1;   /* SIMD */
    uint32_t opc  = (insn >> 22) & 3;   /* 00=str 01=ldr 10=ldrs-64 11=ldrs-32 */
    uint32_t rt   = insn & 0x1f;
    uint32_t rn   = (insn >>  5) & 0x1f;

    int elem_sz = 1 << size;
    bool is_store = (opc == 0 || opc == 2 /* LDRSW on 32-bit is load */);
    is_store = (opc == 0);
    bool is_signed = (opc >= 2);
    bool is64 = (opc != 3);  /* LDRS 32-bit zero extends? no — LDRS sign extends to 64 or 32 */
    if (opc == 3 && size != 3) { is_signed = true; is64 = false; }
    if (size == 3) { is_signed = false; is64 = true; }

    uint64_t addr = 0;
    uint32_t mode = (insn >> 24) & 3;

    if ((insn & 0x3B000000) == 0x18000000) return 0;  /* already handled literal */

    /* Register offset: bit[21]=1 is the definitive discriminator */
    if ((insn >> 21) & 1) {
        /* Register offset */
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t opt  = (insn >> 13) & 7;
        uint32_t shift = (insn >> 12) & 1;
        uint64_t base = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        uint64_t offset = cpu_xreg(c, rm);
        if (opt == 2 || opt == 6) offset &= 0xFFFFFFFF;  /* W extend */
        if (opt == 2) offset = (uint64_t)(int64_t)(int32_t)offset; /* SXTW */
        if (shift) offset <<= size;
        addr = base + offset;
    } else if ((insn & 0x3B200C00) == 0x38000400) {
        /* Post-index */
        int64_t imm9 = (int64_t)((insn >> 12) & 0x1FF);
        if (imm9 & 0x100) imm9 |= ~0x1FFLL;
        uint64_t base = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        addr = base;
        uint64_t wb = base + (uint64_t)imm9;
        if (rn == 31) cpu_set_sp(c, wb);
        else cpu_set_xreg(c, rn, wb);
    } else if ((insn & 0x3B200C00) == 0x38000C00) {
        /* Pre-index */
        int64_t imm9 = (int64_t)((insn >> 12) & 0x1FF);
        if (imm9 & 0x100) imm9 |= ~0x1FFLL;
        uint64_t base = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        addr = base + (uint64_t)imm9;
        if (rn == 31) cpu_set_sp(c, addr);
        else cpu_set_xreg(c, rn, addr);
    } else {
        /* Unsigned offset / other */
        uint64_t imm12 = (insn >> 10) & 0xFFF;
        uint64_t base = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        addr = base + (imm12 << size);
    }

    /* Watchpoint check on load */
    if (!is_store) {
        for (int i = 0; i < c->wp_count; i++) {
            if (c->wp[i].type == 0) continue;
            if (addr >= c->wp[i].addr && addr < c->wp[i].addr + c->wp[i].len &&
                (c->wp[i].type & 1)) {
                c->stopped = true;
            }
        }
    }

    if (v) {
        /* SIMD load/store: simplified — use 8-byte ops */
        if (is_store) {
            cpu_store(c, mem, addr, elem_sz < 8 ? elem_sz : 8, c->v[rt].lo);
            if (elem_sz == 16) cpu_store(c, mem, addr+8, 8, c->v[rt].hi);
        } else {
            uint64_t val = 0;
            cpu_load(c, mem, addr, elem_sz < 8 ? elem_sz : 8, false, true, &val);
            c->v[rt].lo = val;
            c->v[rt].hi = 0;
            if (elem_sz == 16) cpu_load(c, mem, addr+8, 8, false, true, &c->v[rt].hi);
        }
        return 0;
    }

    if (is_store) {
        uint64_t val = (rt == 31) ? 0 : cpu_xreg(c, rt);
        cpu_store(c, mem, addr, elem_sz, val);
    } else {
        uint64_t val = 0;
        /* Determine sign and width */
        bool sign = is_signed;
        bool w64  = (opc == 1 && size == 3) || (opc == 2 && size <= 2);
        if (size == 3) { sign = false; w64 = true; }
        if (!cpu_load(c, mem, addr, elem_sz, sign, w64, &val)) return -1;
        cpu_set_xreg(c, rt, val);
    }
    return 0;
}

/* ============================================================
 * Data Processing Register
 * ============================================================ */

static uint64_t do_shift(uint64_t val, uint32_t type, uint32_t amount, bool sf)
{
    if (!sf) { val &= 0xFFFFFFFF; amount &= 31; }
    else amount &= 63;
    if (amount == 0) return val;
    switch (type & 3) {
    case 0: return sf ? (val << amount) : ((val << amount) & 0xFFFFFFFF);
    case 1: return val >> amount;
    case 2: return sf ? (uint64_t)((int64_t)val >> amount)
                      : (uint64_t)((int32_t)(val & 0xFFFFFFFF) >> amount);
    case 3: /* ROR */
        if (sf) return (val >> amount) | (val << (64 - amount));
        else { val &= 0xFFFFFFFF; return ((val >> amount) | (val << (32 - amount))) & 0xFFFFFFFF; }
    }
    return val;
}

static int exec_dp_reg(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    (void)m;
    bool sf = (insn >> 31) & 1;
    uint32_t op = (insn >> 29) & 7;

    /* Data processing 2 source (CLZ, RBIT, REV, etc.) — bits[28:21] = 110 1011 0 */
    if ((insn & 0x5FE00000) == 0x5AC00000) {
        uint32_t opcode = (insn >> 10) & 0x3f;
        uint32_t rn = (insn >> 5) & 0x1f;
        uint32_t rd = insn & 0x1f;
        uint64_t x = cpu_xreg(c, rn);
        uint64_t result = 0;
        switch (opcode) {
        case 0x00: /* RBIT */ {
            uint64_t v = sf ? x : (x & 0xFFFFFFFF);
            uint64_t r = 0;
            int bits = sf ? 64 : 32;
            for (int i = 0; i < bits; i++) r |= ((v >> i) & 1) << (bits-1-i);
            result = r;
            break;
        }
        case 0x01: case 0x02: case 0x03: /* REV16/REV32/REV */ {
            /* byte-reverse */
            uint64_t v = x;
            if (!sf || opcode < 3) v &= 0xFFFFFFFF;
            if (opcode == 1) {
                /* REV16: swap bytes within each halfword */
                result = ((v & 0xFF00FF00FF00FF00ULL) >> 8) | ((v & 0x00FF00FF00FF00FFULL) << 8);
            } else if (opcode == 2) {
                result = __builtin_bswap32(v & 0xFFFFFFFF);
            } else {
                result = sf ? __builtin_bswap64(v) : __builtin_bswap32(v & 0xFFFFFFFF);
            }
            break;
        }
        case 0x04: /* CLZ */
            result = sf ? (x ? __builtin_clzll(x) : 64) : (x & 0xFFFFFFFF ? __builtin_clz(x & 0xFFFFFFFF) : 32);
            break;
        case 0x05: /* CLS */
            if (sf) {
                result = x == 0 || x == ~0ULL ? 63 : __builtin_clzll(x ^ (x << 1));
            } else {
                uint32_t v = x & 0xFFFFFFFF;
                result = v == 0 || v == 0xFFFFFFFF ? 31 : __builtin_clz(v ^ (v << 1));
            }
            break;
        default: break;
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Multiply — MADD/MSUB/SMADDL/SMSUBL/UMADDL/UMSUBL/SMULH/UMULH: bits[28:24]=11011
     * Bit layout: bit23=U (unsigned), bits[22:21]=op, bit15=o1 (subtract)
     * op=00: MADD/MSUB (32 or 64-bit depending on sf)
     * op=01: SMADDL/SMSUBL (U=0) or UMADDL/UMSUBL (U=1): 32-bit inputs, 64-bit result
     * op=10: SMULH (U=0) or UMULH (U=1): high 64 bits of 64×64 product
     * NOTE: Previous code used bits[24:23] for 'u' — wrong because bit24 is always 1
     *       in this group (fixed 11011 at [28:24]), so UMADDL was misidentified as SMULH. */
    if ((insn & 0x1F000000) == 0x1B000000) {
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t ra   = (insn >> 10) & 0x1f;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        bool is_sub   = (insn >> 15) & 1;
        bool U        = (insn >> 23) & 1;     /* bit23: 1=unsigned */
        uint32_t op   = (insn >> 21) & 3;     /* bits[22:21]: operation class */

        uint64_t n  = cpu_xreg(c, rn);
        uint64_t mm = cpu_xreg(c, rm);
        uint64_t a  = (ra == 31) ? 0 : cpu_xreg(c, ra);
        uint64_t result;

        switch (op) {
        case 0: /* MADD / MSUB — 32-bit (sf=0) or 64-bit (sf=1) */
            if (!sf) {
                uint32_t prod32 = (uint32_t)n * (uint32_t)mm;
                uint32_t acc32  = (uint32_t)(a & 0xFFFFFFFFULL);
                result = (uint64_t)(uint32_t)(is_sub ? acc32 - prod32 : acc32 + prod32);
            } else {
                result = a + (is_sub ? -(n * mm) : (n * mm));
            }
            break;
        case 1: /* SMADDL/SMSUBL (U=0) or UMADDL/UMSUBL (U=1) */
            if (U) {
                uint64_t prod = (uint64_t)(uint32_t)n * (uint64_t)(uint32_t)mm;
                result = a + (is_sub ? -prod : prod);
            } else {
                int64_t prod = (int64_t)(int32_t)n * (int64_t)(int32_t)mm;
                result = (uint64_t)((int64_t)a + (is_sub ? -prod : prod));
            }
            break;
        case 2: /* SMULH (U=0) or UMULH (U=1) — high 64 bits, no accumulator */
            if (U) {
                __uint128_t prod = (__uint128_t)(uint64_t)n * (uint64_t)mm;
                result = (uint64_t)(prod >> 64);
            } else {
                __int128_t prod = (__int128_t)(int64_t)n * (int64_t)mm;
                result = (uint64_t)((unsigned __int128)prod >> 64);
            }
            break;
        default: result = 0; break;
        }
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Divide: UDIV/SDIV */
    if ((insn & 0x7FE0FC00) == 0x1AC00800) {
        uint32_t rm = (insn >> 16) & 0x1f;
        uint32_t rn = (insn >>  5) & 0x1f;
        uint32_t rd = insn & 0x1f;
        bool is_signed = (insn >> 10) & 1;
        uint64_t n = cpu_xreg(c, rn), d = cpu_xreg(c, rm);
        uint64_t result;
        if (d == 0) result = 0;
        else if (is_signed) {
            if (sf) result = (uint64_t)((int64_t)n / (int64_t)d);
            else result = (uint64_t)((int32_t)(n&0xFFFFFFFF) / (int32_t)(d&0xFFFFFFFF));
        } else {
            if (sf) result = n / d;
            else result = (n & 0xFFFFFFFF) / (d & 0xFFFFFFFF);
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Variable shifts: LSLV/LSRV/ASRV/RORV */
    if ((insn & 0x7FE0FC00) == 0x1AC02000) {
        uint32_t rm = (insn >> 16) & 0x1f;
        uint32_t rn = (insn >>  5) & 0x1f;
        uint32_t rd = insn & 0x1f;
        uint32_t op2 = (insn >> 10) & 3;
        uint64_t n = cpu_xreg(c, rn);
        uint64_t amount = cpu_xreg(c, rm) & (sf ? 63 : 31);
        uint64_t result = do_shift(n, op2, amount, sf);
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Add/Sub shifted: bits[28:24] = 01011 / 11011 — but that overlaps multiply above */
    /* Add/Sub shifted: opc bit[29]=0/1, bit[28]=0, bit[27]=1, bit[24]=1 */
    /* bits[28:24] for add-shifted = 01011 */
    if ((insn & 0x1F200000) == 0x0B000000) {
        bool is_sub    = (insn >> 30) & 1;
        bool setflags  = (insn >> 29) & 1;
        uint32_t shift = (insn >> 22) & 3;
        uint32_t rm    = (insn >> 16) & 0x1f;
        uint32_t imm6  = (insn >> 10) & 0x3f;
        uint32_t rn    = (insn >>  5) & 0x1f;
        uint32_t rd    = insn & 0x1f;
        uint64_t operand1 = cpu_xreg(c, rn);
        uint64_t operand2 = do_shift(cpu_xreg(c, rm), shift, imm6, sf);
        if (!sf) { operand1 &= 0xFFFFFFFF; operand2 &= 0xFFFFFFFF; }
        uint64_t result = is_sub ? operand1 - operand2 : operand1 + operand2;
        if (setflags) {
            if (sf) (is_sub ? sub_flags64 : add_flags64)(c, operand1, operand2, result);
            else (is_sub ? sub_flags32 : add_flags32)(c, operand1, operand2, result);
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Add/Sub extended: bits[28:24] = 01011, bit[21]=1 */
    if ((insn & 0x1F200000) == 0x0B200000) {
        bool is_sub   = (insn >> 30) & 1;
        bool setflags = (insn >> 29) & 1;
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t opt  = (insn >> 13) & 7;
        uint32_t imm3 = (insn >> 10) & 7;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        uint64_t operand1 = (rn == 31) ? cpu_sp(c) : cpu_xreg(c, rn);
        uint64_t ext = cpu_xreg(c, rm);
        switch (opt & 7) {
        case 0: ext = (uint8_t)ext; break;
        case 1: ext = (uint16_t)ext; break;
        case 2: ext = (uint32_t)ext; break;
        case 3: break;
        case 4: ext = (uint64_t)(int8_t)ext; break;
        case 5: ext = (uint64_t)(int16_t)ext; break;
        case 6: ext = (uint64_t)(int32_t)ext; break;
        case 7: break;
        }
        ext <<= imm3;
        if (!sf) { operand1 &= 0xFFFFFFFF; ext &= 0xFFFFFFFF; }
        uint64_t result = is_sub ? operand1 - ext : operand1 + ext;
        if (setflags) {
            if (sf) (is_sub ? sub_flags64 : add_flags64)(c, operand1, ext, result);
            else (is_sub ? sub_flags32 : add_flags32)(c, operand1, ext, result);
        }
        if (!sf) result &= 0xFFFFFFFF;
        if (rd == 31 && !setflags) cpu_set_sp(c, result);
        else cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Logical (shifted register): bits[28:24] = 01010 / 11010 */
    if ((insn & 0x1F000000) == 0x0A000000) {
        uint32_t opc   = (insn >> 29) & 3;
        uint32_t shift = (insn >> 22) & 3;
        bool n_bit     = (insn >> 21) & 1;
        uint32_t rm    = (insn >> 16) & 0x1f;
        uint32_t imm6  = (insn >> 10) & 0x3f;
        uint32_t rn    = (insn >>  5) & 0x1f;
        uint32_t rd    = insn & 0x1f;
        uint64_t operand1 = cpu_xreg(c, rn);
        uint64_t operand2 = do_shift(cpu_xreg(c, rm), shift, imm6, sf);
        if (n_bit) operand2 = ~operand2;
        if (!sf) { operand1 &= 0xFFFFFFFF; operand2 &= 0xFFFFFFFF; }
        uint64_t result;
        switch (opc) {
        case 0: result = operand1 & operand2; break;  /* AND/BIC */
        case 1: result = operand1 | operand2; break;  /* ORR/ORN */
        case 2: result = operand1 ^ operand2; break;  /* EOR/EON */
        case 3: result = operand1 & operand2;          /* ANDS/BICS */
            set_nzcv(c, !!(result >> (sf?63:31)), result==0, false, false);
            cpu_set_xreg(c, rd, sf ? result : (result & 0xFFFFFFFF));
            return 0;
        default: result = 0; break;
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* CCMP / CCMN */
    if ((insn & 0x5FE00000) == 0x7A400000) {
        bool is_sub = (insn >> 30) & 1;  /* CCMP vs CCMN */
        bool imm_mode = (insn >> 11) & 1;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t nzcv = insn & 0xF;
        uint32_t cond4 = (insn >> 12) & 0xF;
        if (check_cond(c, cond4)) {
            uint64_t a = cpu_xreg(c, rn);
            uint64_t b = imm_mode ? ((insn >> 16) & 0x1f) : cpu_xreg(c, (insn>>16)&0x1f);
            uint64_t res;
            if (!sf) { a &= 0xFFFFFFFF; b &= 0xFFFFFFFF; }
            if (is_sub) { res = a - b; if (sf) sub_flags64(c,a,b,res); else sub_flags32(c,a,b,res); }
            else         { res = a + b; if (sf) add_flags64(c,a,b,res); else add_flags32(c,a,b,res); }
        } else {
            /* Condition not met: use nzcv field */
            c->pstate &= ~(PSTATE_N|PSTATE_Z|PSTATE_C|PSTATE_V);
            if (nzcv & 8) c->pstate |= PSTATE_N;
            if (nzcv & 4) c->pstate |= PSTATE_Z;
            if (nzcv & 2) c->pstate |= PSTATE_C;
            if (nzcv & 1) c->pstate |= PSTATE_V;
        }
        return 0;
    }

    /* CSEL / CSINC / CSINV / CSNEG */
    if ((insn & 0x1FE00000) == 0x1A800000) {
        uint32_t op   = (insn >> 30) & 1;
        uint32_t op2  = (insn >> 10) & 3;
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t cond4= (insn >> 12) & 0xF;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        uint64_t true_val  = cpu_xreg(c, rn);
        uint64_t false_val = cpu_xreg(c, rm);
        bool cond_ok = check_cond(c, cond4);
        uint64_t result;
        if (cond_ok) {
            result = true_val;
        } else {
            switch (op2) {
            case 0: result = false_val; break;         /* CSEL */
            case 1: result = false_val + 1; break;     /* CSINC */
            case 2: result = ~false_val; break;        /* CSINV */
            case 3: result = (uint64_t)(-(int64_t)false_val); break; /* CSNEG */
            default: result = false_val; break;
            }
        }
        if (!sf) result &= 0xFFFFFFFF;
        cpu_set_xreg(c, rd, result);
        return 0;
    }

    /* Unknown DP-reg: NOP */
    return 0;
}

/* ============================================================
 * SIMD/FP (minimal — FMOV, basic scalar)
 * ============================================================ */

static int exec_simd(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    (void)m;
    /* FMOV (register): move between FP and GP regs */
    /* ftype=01 (single) or ftype=11 (double) */
    uint32_t ftype = (insn >> 22) & 3;
    uint32_t opc   = (insn >> 16) & 7;
    uint32_t rn    = (insn >>  5) & 0x1f;
    uint32_t rd    = insn & 0x1f;

    /* FMOV scalar to GP or GP to scalar */
    if ((insn & 0x5F200000) == 0x1E200000) {
        /* Scalar FP data processing */
        /* Just NOp most — we don't need FP for Linux kernel boot */
        return 0;
    }

    /* FMOV (general) — integer to/from FP register */
    if ((insn & 0x7F3FFC00) == 0x1E270000) {
        /* FMOV Vn.D[0], Xn */
        c->v[rd].lo = cpu_xreg(c, rn);
        return 0;
    }
    if ((insn & 0x7F3FFC00) == 0x1E260000) {
        /* FMOV Xd, Vn.D[0] */
        cpu_set_xreg(c, rd, c->v[rn].lo);
        return 0;
    }

    /* DUP / INS / UMOV / SMOV — vector element operations */
    /* Mostly NOP for our boot purposes */
    return 0;
}

/* ============================================================
 * Main step function
 * ============================================================ */

int cpu_step(ARM64CPU *c, EmuMachine *m)
{
    /* Breakpoint check */
    for (int i = 0; i < c->bp_count; i++) {
        if (c->bp[i] == c->pc) {
            c->stopped = true;
            return 0;
        }
    }

    /* Fetch */
    uint32_t insn = 0;
    if (cpu_fetch(c, &m->mem, c->pc, &insn) < 0) {
        /* Instruction fetch fault — exception already taken */
        return -1;
    }

    /* Log actual fetched instruction at stuck address */
    if (c->pc == 0xffffffc0080b7f78ULL) {
        static int fetch_logged = 0;
        if (c->insn_count > 43000000 && fetch_logged < 5) {
            fetch_logged++;
            /* Also read linear-mapped PA for comparison */
            uint64_t lin_pa = c->pc - 0xffffffbfc8000000ULL;
            uint32_t lin_insn = (uint32_t)mem_read(&m->mem, lin_pa, 4);
            fprintf(stderr, "[FETCH-SPIN#%d] insn_count=%llu fetched=0x%08x lin_pa=0x%llx lin_insn=0x%08x\n",
                    fetch_logged, (unsigned long long)c->insn_count,
                    insn, (unsigned long long)lin_pa, lin_insn);
        }
    }

    /* Instruction trace for primary_entry region (first 32 insns) */
    if (c->pc >= 0x41afac10ULL && c->pc <= 0x41afac90ULL) {
        static int primary_trace = 0;
        if (primary_trace < 64) {
            uint32_t raw = (uint32_t)mem_read(&m->mem, c->pc, 4);
            fprintf(stderr, "[PRIMARY] PC=0x%llx INSN=0x%08x X0=0x%llx X1=0x%llx X2=0x%llx\n",
                    (unsigned long long)c->pc, raw,
                    (unsigned long long)c->x[0],
                    (unsigned long long)c->x[1],
                    (unsigned long long)c->x[2]);
            primary_trace++;
        }
    }

    /* Instruction trace for __create_page_tables region */
    if (c->pc >= 0x41afaca8ULL && c->pc <= 0x41afb000ULL) {
        static int cpt_trace = 0;
        if (cpt_trace < 128) {
            uint32_t raw = (uint32_t)mem_read(&m->mem, c->pc, 4);
            fprintf(stderr, "[CPT] PC=0x%llx INSN=0x%08x X0=0x%llx X3=0x%llx X6=0x%llx\n",
                    (unsigned long long)c->pc, raw,
                    (unsigned long long)c->x[0],
                    (unsigned long long)c->x[3],
                    (unsigned long long)c->x[6]);
            cpt_trace++;
        }
    }

    /* One-time dump before BR X8 (0x4106350c) that branches to kernel VA.
     * Dump: TTBR1 base + swapper L1 table around the entry for ffffffc009afae64.
     * T1SZ=25 → L1 walk: L1_idx = (va >> 30) & 0x1FF = 256 for our target VA.
     * Also dump 4 entries either side of 256 to catch off-by-one alignment. */
    if (c->pc == 0x4106350cULL) {
        static int _once_br = 0;
        if (!_once_br++) {
            uint64_t ttbr1 = c->ttbr1_el1 & ~0xFFFULL;
            uint64_t target_va = c->x[8]; /* X8 = ffffffc009afae64 */
            int t1sz = (int)((c->tcr_el1 >> 16) & 0x3F);
            int va_bits = 64 - t1sz;
            int start_lvl = 3 - (va_bits - 1 - 12) / 9;
            int shift0 = 39 - start_lvl * 9;
            uint64_t l1_idx = (target_va >> shift0) & 0x1FF;
            fprintf(stderr, "[SWAPPER-DUMP] BR X8=0x%llx TTBR1=0x%llx T1SZ=%d VA_BITS=%d start_level=%d shift=%d L1_idx=%llu\n",
                    (unsigned long long)target_va,
                    (unsigned long long)ttbr1, t1sz, va_bits, start_lvl, shift0,
                    (unsigned long long)l1_idx);
            /* Dump L1 entries [idx-4 .. idx+4] */
            for (int di = -4; di <= 4; di++) {
                uint64_t idx_i = l1_idx + (uint64_t)di;
                uint64_t epa = ttbr1 + idx_i * 8;
                uint64_t entry = mem_read(&m->mem, epa, 8);
                fprintf(stderr, "[SWAPPER-L1] [%llu] PA=0x%llx entry=0x%016llx%s\n",
                        (unsigned long long)idx_i,
                        (unsigned long long)epa,
                        (unsigned long long)entry,
                        (idx_i == l1_idx) ? " <-- TARGET" : "");
            }
            /* If L1 entry is a TABLE, follow to L2 */
            uint64_t l1_epa = ttbr1 + l1_idx * 8;
            uint64_t l1_entry = mem_read(&m->mem, l1_epa, 8);
            if (l1_entry & 1) { /* valid */
                if (l1_entry & 2) { /* TABLE */
                    uint64_t l2_base = l1_entry & ~0xFFFULL;
                    int shift1 = shift0 - 9;
                    uint64_t l2_idx = (target_va >> shift1) & 0x1FF;
                    fprintf(stderr, "[SWAPPER-L2] Following TABLE to 0x%llx, L2_idx=%llu shift=%d\n",
                            (unsigned long long)l2_base, (unsigned long long)l2_idx, shift1);
                    for (int di = -2; di <= 2; di++) {
                        uint64_t idx_i = l2_idx + (uint64_t)di;
                        uint64_t epa = l2_base + idx_i * 8;
                        uint64_t entry = mem_read(&m->mem, epa, 8);
                        if (entry) fprintf(stderr, "[SWAPPER-L2] [%llu] PA=0x%llx entry=0x%016llx%s\n",
                                (unsigned long long)idx_i, (unsigned long long)epa,
                                (unsigned long long)entry,
                                (idx_i == l2_idx) ? " <-- TARGET" : "");
                    }
                } else {
                    fprintf(stderr, "[SWAPPER-L1] L1 is BLOCK entry (not TABLE)\n");
                }
            } else {
                fprintf(stderr, "[SWAPPER-L1] L1 entry INVALID (not mapped)\n");
            }
        }
    }

    uint64_t next_pc = c->pc + 4;
    int pc_updated = 0;
    c->exc_taken = false;

    /* Decode via bits[28:25] */
    uint32_t group = (insn >> 25) & 0xF;
    int ret = 0;

    switch (group) {
    case 0x0: case 0x1: case 0x2: case 0x3:
        /* Reserved / unallocated */
        /* Many SMC/HVC/WFI fall here — treat as NOP */
        ret = 0;
        break;

    case 0x8: case 0x9:
        /* Data processing — immediate */
        ret = exec_dp_imm(c, m, insn);
        break;

    case 0xA: case 0xB:
        /* Branches, system instructions */
        ret = exec_branch(c, m, insn);
        if (ret == 1) pc_updated = 1;
        ret = (ret < 0) ? ret : 0;
        break;

    case 0x4: case 0x6: case 0xC: case 0xE:
        /* Load/Store */
        ret = exec_ldst(c, m, insn);
        break;

    case 0x5: case 0xD:
        /* Data processing — register */
        ret = exec_dp_reg(c, m, insn);
        break;

    case 0x7: case 0xF:
        /* SIMD/FP */
        ret = exec_simd(c, m, insn);
        break;

    default:
        ret = 0;
        break;
    }

    if (!pc_updated && !c->exc_taken)
        c->pc = next_pc;

    c->insn_count++;

    /* IRQ check after every instruction */
    cpu_irq_check(c, m);

    return ret;
}

/* ============================================================
 * GIC helper — find best IRQ for CPU
 * (called from cpu_irq_check; defined here to avoid circular dep)
 * ============================================================ */

/* This calls into dev_gic.c's internal function via the exported gic_sysreg_read
 * path. We expose a small wrapper in machine.c instead via gic_find_best_irq_for_cpu.
 * Declare it here for linking — machine.c implements it. */
