/* mmu.h — ARMv8-A stage-1 MMU */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "mem.h"

/* Page sizes */
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PAGE_MASK   (~(uint64_t)(PAGE_SIZE-1))

/* Page descriptor bits */
#define PTE_VALID       (1ULL << 0)
#define PTE_TABLE       (1ULL << 1)
#define PTE_AF          (1ULL << 10)
#define PTE_SH_INNER    (3ULL << 8)
#define PTE_AP_RW_EL1   (0ULL << 6)
#define PTE_AP_RW_ALL   (1ULL << 6)
#define PTE_AP_RO_EL1   (2ULL << 6)
#define PTE_AP_RO_ALL   (3ULL << 6)
#define PTE_UXN         (1ULL << 54)
#define PTE_PXN         (1ULL << 53)
#define PTE_ADDR_MASK   (0x0000FFFFFFFFF000ULL)
#define PTE_AP_MASK     (3ULL << 6)

/* SCTLR_EL1 bits */
#define SCTLR_M     (1ULL << 0)
#define SCTLR_C     (1ULL << 2)
#define SCTLR_I     (1ULL << 12)
#define SCTLR_SPAN  (1ULL << 23)

/* Access type for translation */
typedef enum { MEM_READ, MEM_WRITE, MEM_EXEC } MemAccess;

/* Translation result */
typedef struct {
    uint64_t pa;
    bool     ok;
    bool     write_ok;
    bool     exec_ok;
} TLBEntry;

struct ARM64CPU;

TLBEntry mmu_translate(struct ARM64CPU *cpu, PhysMem *mem,
                        uint64_t va, MemAccess access, int el);

bool mmu_read_u64(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint64_t *out);
bool mmu_write_u64(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint64_t val);
bool mmu_read_u32(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint32_t *out);
bool mmu_read_u16(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint16_t *out);
bool mmu_read_u8(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, uint8_t *out);

bool mmu_load(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, int size,
              bool is_signed, uint64_t *out, MemAccess acc);
bool mmu_store(struct ARM64CPU *cpu, PhysMem *mem, uint64_t va, int size,
               uint64_t val);
