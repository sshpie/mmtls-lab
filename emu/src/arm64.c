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
        if (!mmu_load(c, mem, va, sz, is_signed, &val, MEM_READ)) {
            /* fault already injected by mmu_load */
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
    return 0;
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
        if (!mmu_store(c, mem, va, sz, val)) return -1;
    } else {
        mem_write(mem, va, val, sz);
    }
    return 0;
}

static int cpu_fetch(ARM64CPU *c, PhysMem *mem, uint64_t va, uint32_t *out)
{
    if (mmu_on(c)) {
        uint32_t v;
        if (!mmu_read_u32(c, mem, va, &v)) return -1;
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
    fprintf(stderr, "[EXCEP] PC=0x%llx EC=0x%02x ESR=0x%08llx FAR=0x%016llx VBAR=0x%llx\n",
            (unsigned long long)c->pc, (unsigned)(esr >> 26) & 0x3f,
            (unsigned long long)esr, (unsigned long long)far,
            (unsigned long long)c->vbar_el1);
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
    case SR_MPIDR_EL1:     return 0x80000000ULL | c->id;
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
    case SR_CNTP_CTL_EL0: {
        /* ISTATUS is read-only and derived: set when ENABLE=1 and CNTPCT >= CVAL */
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
    case SR_VMPIDR_EL2:    return 0x80000000ULL | c->id;
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
    case SR_TTBR0_EL1:     c->ttbr0_el1 = val; return;
    case SR_TTBR1_EL1:     c->ttbr1_el1 = val; return;
    case SR_MAIR_EL1:      c->mair_el1  = val; return;
    case SR_VBAR_EL1:      c->vbar_el1  = val; return;
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
        case 1: /* HVC — treat as NOP in EL1 */
            return 0;
        case 2: /* SMC — treat as NOP */
            return 0;
        }
    }

    /* BRK */
    if ((insn & 0xFFE0001F) == 0xD4200000) {
        uint32_t imm16 = (insn >> 5) & 0xFFFF;
        /* Check software breakpoints */
        c->stopped = true;
        /* Raise software breakpoint exception */
        cpu_take_exception(c, (0x3cULL << 26) | imm16, c->pc, EL1);
        return 1;
    }

    /* HLT */
    if ((insn & 0xFFE0001F) == 0xD4400000) {
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
        case 2: /* RET */ c->pc = cpu_xreg(c, rn ? rn : 30); break;
        case 4: /* ERET */
            fprintf(stderr, "[ERET] PC=0x%llx ELR_EL1=0x%llx SPSR_EL1=0x%08x SP_EL0=0x%llx SP_EL1=0x%llx\n",
                    (unsigned long long)c->pc,
                    (unsigned long long)c->elr_el1,
                    c->spsr_el1,
                    (unsigned long long)c->sp_el0,
                    (unsigned long long)c->sp_el1);
            c->pc     = c->elr_el1;
            c->pstate = c->spsr_el1;
            fprintf(stderr, "[ERET] -> new pstate=0x%08x EL=%u SP_sel=%u\n",
                    c->pstate, (c->pstate >> 2) & 3, c->pstate & 1);
            break;
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
        if ((++wfi_count & 0xFFFF) == 0)
            fprintf(stderr, "[WFI] count=%llu PC=0x%llx pstate=0x%08x VBAR=0x%llx\n",
                    (unsigned long long)wfi_count,
                    (unsigned long long)c->pc,
                    c->pstate,
                    (unsigned long long)c->vbar_el1);
        c->halted = true;
        return 1;
    }
    /* WFE, SEV, SEVL, YIELD — NOP */
    if ((insn & 0xFFFFFFDF) == 0xD503205F) return 0;

    /* CLREX */
    if (insn == 0xD503304F) return 0;

    return 0;
}

/* ============================================================
 * Load/Store
 * ============================================================ */

static int exec_ldst(ARM64CPU *c, EmuMachine *m, uint32_t insn)
{
    PhysMem *mem = &m->mem;

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
        uint64_t addr = (idx_mode == 3) ? base + (uint64_t)imm7 : base;
        if (idx_mode == 1) addr = base;

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

    if ((insn & 0x1A000000) == 0x18000000) return 0;  /* already handled literal */

    /* Register offset: bit[21] */
    if (mode == 2 && ((insn >> 21) & 1)) {
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

    /* Multiply — MADD/MSUB/SMULH/UMULH: bits[28:24]=11011 */
    if ((insn & 0x1F000000) == 0x1B000000) {
        uint32_t rm   = (insn >> 16) & 0x1f;
        uint32_t ra   = (insn >> 10) & 0x1f;
        uint32_t rn   = (insn >>  5) & 0x1f;
        uint32_t rd   = insn & 0x1f;
        bool is_sub   = (insn >> 15) & 1;
        uint32_t u    = (insn >> 23) & 3;  /* 00=MADD/MSUB 64, 01=SMADDL, 10=SMSUBL, 11=SMULH */

        uint64_t n = cpu_xreg(c, rn);
        uint64_t mm = cpu_xreg(c, rm);
        uint64_t a = (ra == 31) ? 0 : cpu_xreg(c, ra);
        uint64_t result;

        switch (u) {
        case 0:
            if (!sf) {
                result = (a & 0xFFFFFFFF) + (is_sub ? -((n & 0xFFFFFFFF) * (mm & 0xFFFFFFFF))
                                                     :  ((n & 0xFFFFFFFF) * (mm & 0xFFFFFFFF)));
                result &= 0xFFFFFFFF;
            } else {
                result = a + (is_sub ? -(n * mm) : (n * mm));
            }
            break;
        case 1: { /* SMADDL / SMSUBL: 32-bit signed × signed + 64-bit accumulate */
            int64_t prod = (int64_t)(int32_t)n * (int64_t)(int32_t)mm;
            result = (int64_t)a + (is_sub ? -prod : prod);
            break;
        }
        case 2: { /* UMADDL */
            uint64_t prod = (uint64_t)(uint32_t)n * (uint64_t)(uint32_t)mm;
            result = a + (is_sub ? -prod : prod);
            break;
        }
        case 3: {
            if ((insn >> 22) & 1) {
                /* UMULH */
                __uint128_t prod = (__uint128_t)(uint64_t)n * (uint64_t)mm;
                result = (uint64_t)(prod >> 64);
            } else {
                /* SMULH */
                __int128_t prod = (__int128_t)(int64_t)n * (int64_t)mm;
                result = (uint64_t)((unsigned __int128)prod >> 64);
            }
            break;
        }
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

    uint64_t next_pc = c->pc + 4;
    int pc_updated = 0;

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

    if (!pc_updated)
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
