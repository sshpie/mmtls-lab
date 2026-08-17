/* arm64.h — ARMv8-A CPU state */
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define NUM_CPUS    4
#define NUM_REGS    31   /* x0-x30 (x31 is SP/XZR context-dependent) */

/* Exception levels */
#define EL0 0
#define EL1 1
#define EL2 2
#define EL3 3

/* PSTATE / SPSR bits */
#define PSTATE_N    (1u << 31)
#define PSTATE_Z    (1u << 30)
#define PSTATE_C    (1u << 29)
#define PSTATE_V    (1u << 28)
#define PSTATE_SS   (1u << 21)
#define PSTATE_IL   (1u << 20)
#define PSTATE_D    (1u << 9)
#define PSTATE_A    (1u << 8)
#define PSTATE_I    (1u << 7)
#define PSTATE_F    (1u << 6)
#define PSTATE_M4   (1u << 4)   /* mode[4] — 0=AArch64 */
#define PSTATE_EL_SHIFT 2
#define PSTATE_EL_MASK  (3u << 2)
#define PSTATE_SP   (1u << 0)   /* SP select: 0=SP_EL0, 1=SP_ELn */

/* System register encoding (op0, op1, crn, crm, op2) packed as 16-bit key */
#define SYSREG_KEY(op0,op1,crn,crm,op2) \
    (((op0)<<14)|((op1)<<11)|((crn)<<7)|((crm)<<3)|(op2))

/* Common system registers */
#define SR_MIDR_EL1      SYSREG_KEY(3,0, 0,0,0)
#define SR_MPIDR_EL1     SYSREG_KEY(3,0, 0,0,5)
#define SR_CTR_EL0       SYSREG_KEY(3,3, 0,0,1)
#define SR_SCTLR_EL1     SYSREG_KEY(3,0, 1,0,0)
#define SR_CPACR_EL1     SYSREG_KEY(3,0, 1,0,2)
#define SR_TCR_EL1       SYSREG_KEY(3,0, 2,0,2)
#define SR_TTBR0_EL1     SYSREG_KEY(3,0, 2,0,0)
#define SR_TTBR1_EL1     SYSREG_KEY(3,0, 2,0,1)
#define SR_ESR_EL1       SYSREG_KEY(3,0, 5,2,0)
#define SR_FAR_EL1       SYSREG_KEY(3,0, 6,0,0)
#define SR_ELR_EL1       SYSREG_KEY(3,0, 4,0,1)
#define SR_SPSR_EL1      SYSREG_KEY(3,0, 4,0,0)
#define SR_SP_EL0        SYSREG_KEY(3,0, 4,1,0)
#define SR_MAIR_EL1      SYSREG_KEY(3,0, 10,2,0)
#define SR_VBAR_EL1      SYSREG_KEY(3,0, 12,0,0)
#define SR_CONTEXTIDR_EL1 SYSREG_KEY(3,0,13,0,1)
#define SR_TPIDR_EL1     SYSREG_KEY(3,0,13,0,4)
#define SR_TPIDR_EL0     SYSREG_KEY(3,3,13,0,2)
#define SR_TPIDRRO_EL0   SYSREG_KEY(3,3,13,0,3)
#define SR_CNTKCTL_EL1   SYSREG_KEY(3,0,14,1,0)
#define SR_CNTFRQ_EL0    SYSREG_KEY(3,3,14,0,0)
#define SR_CNTP_TVAL_EL0 SYSREG_KEY(3,3,14,2,0)
#define SR_CNTP_CTL_EL0  SYSREG_KEY(3,3,14,2,1)
#define SR_CNTP_CVAL_EL0 SYSREG_KEY(3,3,14,2,2)
#define SR_CNTPCT_EL0    SYSREG_KEY(3,3,14,0,1)
#define SR_CNTV_TVAL_EL0 SYSREG_KEY(3,3,14,3,0)
#define SR_CNTV_CTL_EL0  SYSREG_KEY(3,3,14,3,1)
#define SR_CNTV_CVAL_EL0 SYSREG_KEY(3,3,14,3,2)
#define SR_CNTVCT_EL0    SYSREG_KEY(3,3,14,0,2)
#define SR_ICC_SRE_EL1   SYSREG_KEY(3,0,12,12,5)
#define SR_ICC_CTLR_EL1  SYSREG_KEY(3,0,12,12,4)
#define SR_ICC_IGRPEN1_EL1 SYSREG_KEY(3,0,12,12,7)
#define SR_ICC_IAR1_EL1  SYSREG_KEY(3,0,12,12,0)
#define SR_ICC_EOIR1_EL1 SYSREG_KEY(3,0,12,12,1)
#define SR_ICC_PMR_EL1   SYSREG_KEY(3,0, 4,6,0)
#define SR_ICC_BPR1_EL1  SYSREG_KEY(3,0,12,12,3)
#define SR_ID_AA64MMFR0_EL1 SYSREG_KEY(3,0,0,7,0)
#define SR_ID_AA64MMFR1_EL1 SYSREG_KEY(3,0,0,7,1)
#define SR_ID_AA64MMFR2_EL1 SYSREG_KEY(3,0,0,7,2)
#define SR_ID_AA64PFR0_EL1  SYSREG_KEY(3,0,0,4,0)
#define SR_ID_AA64PFR1_EL1  SYSREG_KEY(3,0,0,4,1)
#define SR_ID_AA64ISAR0_EL1 SYSREG_KEY(3,0,0,6,0)
#define SR_ID_AA64ISAR1_EL1 SYSREG_KEY(3,0,0,6,1)
#define SR_ID_AA64DFR0_EL1  SYSREG_KEY(3,0,0,5,0)
#define SR_DCZID_EL0     SYSREG_KEY(3,3,0,0,7)
#define SR_CURRENTEL     SYSREG_KEY(3,0,4,2,2)
#define SR_DAIF          SYSREG_KEY(3,3,4,2,1)
#define SR_NZCV          SYSREG_KEY(3,3,4,2,0)
#define SR_SPSel         SYSREG_KEY(3,0,4,2,0)
#define SR_HCR_EL2       SYSREG_KEY(3,4,1,1,0)
#define SR_VPIDR_EL2     SYSREG_KEY(3,4,0,0,0)
#define SR_VMPIDR_EL2    SYSREG_KEY(3,4,0,0,5)
#define SR_MDSCR_EL1     SYSREG_KEY(2,0,0,2,2)
#define SR_OSLAR_EL1     SYSREG_KEY(2,0,1,0,4)
#define SR_OSLSR_EL1     SYSREG_KEY(2,0,1,1,4)
#define SR_OSDLR_EL1     SYSREG_KEY(2,0,1,3,4)
#define SR_DBGPRCR_EL1   SYSREG_KEY(2,0,1,4,4)
#define SR_PMCR_EL0      SYSREG_KEY(3,3,9,12,0)
#define SR_PMCNTENSET_EL0 SYSREG_KEY(3,3,9,12,1)
#define SR_PMUSERENR_EL0  SYSREG_KEY(3,3,9,14,0)
#define SR_PMCCNTR_EL0    SYSREG_KEY(3,3,9,13,0)

/* SIMD/FP register: 128-bit */
typedef struct { uint64_t lo, hi; } uint128_t;

/* A single ARM64 CPU */
typedef struct ARM64CPU {
    uint64_t  x[31];       /* x0-x30 */
    uint64_t  sp_el0;      /* SP_EL0 */
    uint64_t  sp_el1;      /* SP_EL1 */
    uint64_t  pc;          /* Program counter */
    uint32_t  pstate;      /* PSTATE (N,Z,C,V, EL, SP, DAIF...) */

    /* System registers (EL1) */
    uint64_t  sctlr_el1;
    uint64_t  tcr_el1;
    uint64_t  ttbr0_el1;
    uint64_t  ttbr1_el1;
    uint64_t  mair_el1;
    uint64_t  vbar_el1;
    uint64_t  esr_el1;
    uint64_t  far_el1;
    uint64_t  elr_el1;
    uint64_t  spsr_el1;
    uint64_t  cpacr_el1;
    uint64_t  tpidr_el0;
    uint64_t  tpidrro_el0;
    uint64_t  tpidr_el1;
    uint64_t  contextidr_el1;
    uint64_t  cntkctl_el1;

    /* EL2 minimal */
    uint64_t  hcr_el2;
    uint64_t  vpidr_el2;
    uint64_t  vmpidr_el2;

    /* Physical timer */
    uint64_t  cntp_cval_el0;
    uint32_t  cntp_ctl_el0;
    /* Virtual timer */
    uint64_t  cntv_cval_el0;
    uint32_t  cntv_ctl_el0;

    /* Debug */
    uint64_t  mdscr_el1;

    /* FP/SIMD */
    uint128_t v[32];
    uint32_t  fpsr;
    uint32_t  fpcr;

    /* CPU id */
    int       id;

    /* Execution state */
    bool      halted;       /* WFI */
    bool      stopped;      /* breakpoint / single-step */
    uint64_t  insn_count;

    /* Single-step flag */
    bool      single_step;

    /* Set by cpu_take_exception so cpu_step knows not to overwrite PC with next_pc */
    bool      exc_taken;

    /* Exclusive monitor (for LDXR/STXR) */
    bool      excl_valid;
    uint64_t  excl_addr;

    /* Watchpoints: up to 16 */
    struct {
        uint64_t addr;
        uint32_t len;
        uint8_t  type;   /* 1=read 2=write 3=rw 0=disabled */
    } wp[16];
    int wp_count;

    /* Breakpoints: up to 64 */
    uint64_t bp[64];
    int      bp_count;
} ARM64CPU;

/* Read GPR (handles XZR at index 31) */
static inline uint64_t cpu_xreg(ARM64CPU *c, int n) {
    return (n == 31) ? 0 : c->x[n];
}
static inline void cpu_set_xreg(ARM64CPU *c, int n, uint64_t v) {
    if (n != 31) c->x[n] = v;
}

/* Current SP (depends on PSTATE.SP and current EL).
 * Defined before cpu_reg_sp so the inline can reference it. */
static inline uint64_t cpu_sp(ARM64CPU *c) {
    int el = (c->pstate >> 2) & 3;
    if (el == 0 || !(c->pstate & PSTATE_SP))
        return c->sp_el0;
    return c->sp_el1;
}
static inline void cpu_set_sp(ARM64CPU *c, uint64_t v) {
    int el = (c->pstate >> 2) & 3;
    if (el == 0 || !(c->pstate & PSTATE_SP))
        c->sp_el0 = v;
    else
        c->sp_el1 = v;
}

/* SP-aware variants: register 31 = current SP (not XZR).
 * Use for ADD/SUB (extended register) destinations and load/store bases. */
static inline uint64_t cpu_reg_sp(ARM64CPU *c, int n) {
    return (n == 31) ? cpu_sp(c) : c->x[n];
}
static inline void cpu_set_reg_sp(ARM64CPU *c, int n, uint64_t v) {
    if (n == 31) cpu_set_sp(c, v);
    else c->x[n] = v;
}

/* Forward declaration for EmuMachine (defined in machine.h) */
typedef struct EmuMachine EmuMachine;

/* Condition code test */
bool cpu_check_cond(ARM64CPU *c, uint32_t cond);

/* Main step function */
int  cpu_step(ARM64CPU *c, EmuMachine *m);
void cpu_init(ARM64CPU *c, int id);
void cpu_reset(ARM64CPU *c);

/* Exception injection */
void cpu_take_exception(ARM64CPU *c, uint64_t esr, uint64_t far, int target_el);
void cpu_irq_check(ARM64CPU *c, EmuMachine *m);
