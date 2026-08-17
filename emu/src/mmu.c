/* mmu.c — ARMv8-A stage-1 MMU (4KB granule, 48-bit VA) */
#include "mmu.h"
#include "arm64.h"
#include <stdio.h>

/* Read a 64-bit value from physical memory, handling both RAM and MMIO */
static uint64_t phys_read64(PhysMem *mem, uint64_t pa)
{
    uint8_t *p = mem_ptr(mem, pa);
    if (p) {
        uint64_t v;
        __builtin_memcpy(&v, p, 8);
        return v;
    }
    return mem_read(mem, pa, 8);
}

/* Write 64-bit to physical, used for AF update */
static void phys_write64(PhysMem *mem, uint64_t pa, uint64_t val)
{
    uint8_t *p = mem_ptr(mem, pa);
    if (p) {
        __builtin_memcpy(p, &val, 8);
        return;
    }
    mem_write(mem, pa, val, 8);
}

TLBEntry mmu_translate(struct ARM64CPU *cpu, PhysMem *mem,
                        uint64_t va, MemAccess access, int el)
{
    TLBEntry t = { .pa = va, .ok = true, .write_ok = true, .exec_ok = true };

    /* MMU disabled: identity map */
    if (!(cpu->sctlr_el1 & SCTLR_M)) {
        return t;
    }

    /* Choose TTBR based on VA top bits */
    uint64_t ttbr;
    if ((va >> 48) == 0xFFFF) {
        ttbr = cpu->ttbr1_el1;
    } else {
        ttbr = cpu->ttbr0_el1;
    }

    uint64_t table_pa = ttbr & PTE_ADDR_MASK;
    uint64_t entry    = 0;
    uint64_t entry_pa = 0;

    /* 4-level page table walk: L0→L1→L2→L3 */
    for (int level = 0; level <= 3; level++) {
        int shift = 39 - level * 9;
        uint64_t idx = (va >> shift) & 0x1FF;
        entry_pa = table_pa + idx * 8;
        entry    = phys_read64(mem, entry_pa);

        if (!(entry & PTE_VALID)) {
            t.ok = false;
            return t;
        }

        /* Block mapping (level 1 = 1GB, level 2 = 2MB) */
        if (level < 3 && !(entry & PTE_TABLE)) {
            /* Block: combine block PA with VA offset */
            uint64_t block_mask = (1ULL << shift) - 1;
            t.pa = (entry & PTE_ADDR_MASK) | (va & block_mask);
            goto check_perms;
        }

        if (level == 3) {
            /* Page descriptor */
            if (!(entry & PTE_TABLE)) { /* must be 1 for page at L3 */
                t.ok = false;
                return t;
            }
            t.pa = (entry & PTE_ADDR_MASK) | (va & 0xFFF);
            goto check_perms;
        }

        table_pa = entry & PTE_ADDR_MASK;
    }

    t.ok = false;
    return t;

check_perms:
    /* AP bits: [7:6] */
    uint64_t ap = (entry >> 6) & 3;
    /* AP=0 or AP=2: EL1 RW / RO, EL0 no access */
    /* AP=1 or AP=3: EL0+EL1 RW / RO */
    if (ap == 2 || ap == 3) {
        t.write_ok = false; /* read-only */
    }

    /* UXN/PXN */
    if (entry & PTE_UXN) { /* user execute never — affects EL0 */
        if (el == 0) t.exec_ok = false;
    }
    if (entry & PTE_PXN) { /* privileged execute never — EL1 */
        if (el >= 1) t.exec_ok = false;
    }

    /* Access flag update */
    if (!(entry & PTE_AF)) {
        entry |= PTE_AF;
        phys_write64(mem, entry_pa, entry);
    }

    if (access == MEM_WRITE && !t.write_ok) {
        t.ok = false;
    }
    if (access == MEM_EXEC && !t.exec_ok) {
        t.ok = false;
    }

    return t;
}

bool mmu_load(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, int size,
              bool is_signed, uint64_t *out, MemAccess acc)
{
    int el = (cpu->pstate >> 2) & 3;
    TLBEntry t = mmu_translate(cpu, mem, va, acc, el);
    if (!t.ok) return false;
    uint64_t v = mem_read(mem, t.pa, size);
    if (is_signed) {
        switch (size) {
        case 1: v = (int64_t)(int8_t)v;  break;
        case 2: v = (int64_t)(int16_t)v; break;
        case 4: v = (int64_t)(int32_t)v; break;
        }
    }
    *out = v;
    return true;
}

bool mmu_store(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, int size,
               uint64_t val)
{
    int el = (cpu->pstate >> 2) & 3;
    TLBEntry t = mmu_translate(cpu, mem, va, MEM_WRITE, el);
    if (!t.ok) return false;
    mem_write(mem, t.pa, val, size);
    return true;
}

bool mmu_read_u64(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint64_t *out) {
    return mmu_load(cpu, mem, va, 8, false, out, MEM_READ);
}
bool mmu_write_u64(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint64_t val) {
    return mmu_store(cpu, mem, va, 8, val);
}
bool mmu_read_u32(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint32_t *out) {
    uint64_t v; bool r = mmu_load(cpu, mem, va, 4, false, &v, MEM_READ);
    *out = (uint32_t)v; return r;
}
bool mmu_read_u16(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint16_t *out) {
    uint64_t v; bool r = mmu_load(cpu, mem, va, 2, false, &v, MEM_READ);
    *out = (uint16_t)v; return r;
}
bool mmu_read_u8(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint8_t *out) {
    uint64_t v; bool r = mmu_load(cpu, mem, va, 1, false, &v, MEM_READ);
    *out = (uint8_t)v; return r;
}
