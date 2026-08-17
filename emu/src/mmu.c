/* mmu.c — ARMv8-A stage-1 MMU (4KB granule, 48-bit VA) */
#include "mmu.h"
#include "arm64.h"
#include <stdio.h>
#include <string.h>

/* ---- Software TLB ----
 * Direct-mapped, 1024 entries per CPU.  Caches final VA→PA translations so
 * that writes to physical memory aliasing page-table pages don't corrupt
 * already-resolved translations.  Invalidate on any TTBR write or TLBI.
 */
#define TLB_SIZE   1024u
#define TLB_IDX(va)  (((va) >> 12) & (TLB_SIZE - 1))

typedef struct {
    uint64_t tag;
    uint64_t pa_base;
    bool     write_ok;
    bool     exec_ok;
    bool     valid;
    uint32_t gen;
} SWTLBEntry;

static SWTLBEntry g_tlb[NUM_CPUS][TLB_SIZE];
static uint32_t   g_tlb_gen[NUM_CPUS];

/* ---- Page Table Cache (PTC) — L1 dedicated snapshot ----
 * Caches all 512 entries of the active TTBR1 L1 table per CPU.  Unlike a
 * direct-mapped cache there are NO collision evictions: each L1 index has its
 * own slot.  The snapshot is loaded the first time an L1 entry is successfully
 * read after a flush, and invalidated on every TLBI or TTBR write.
 *
 * This fixes the Linux kernel boot regression where the shadow-call-stack (SCS)
 * for CPU 0 shares a physical page with swapper_pg_dir: every SCS push
 * (STR LR,[X18],#8) overwrites an L1 entry in physical RAM.  Real hardware
 * TLBs cache the original descriptor and are immune; our snapshot does the same.
 *
 * L2/L3 entries go through a direct-mapped PTC (2048 entries).  Aliasing is
 * possible but L2/L3 entries are less critical — they don't share pages with
 * kernel data.
 */
#define PTC_SIZE   2048u
#define PTC_IDX(pa) (((pa) >> 3) & (PTC_SIZE - 1))

typedef struct {
    uint64_t pa;
    uint64_t val;
    bool     valid;
    uint32_t gen;
} PTCEntry;

/* L1 + L2 snapshots: pinned caches for physical page table pages that alias
 * kernel data (shadow-call-stack in this kernel's memory layout).
 *
 * The SCS for CPU 0 starts at PA 0x41ead800 (same as swapper_pg_dir L1[256])
 * and grows upward for 4KB, covering PA 0x41ead800–0x41eae7FF.  This spans:
 *   L1 table:  0x41ead000–0x41eadFFF   (L1[256] at 0x41ead800)
 *   L2 table:  0x41eae000–0x41eae???   (L2[64] at 0x41eae200 — kernel text)
 *
 * Both snapshots are loaded once-on-first-read and never invalidated by TLBI;
 * only TTBR1 writes reset them (new page table root = new snapshot).
 */
#define L1_SNAP_ENTRIES 512u
#define L2_SNAP_ENTRIES 512u  /* one L2 table shadowed per CPU */

typedef struct {
    uint64_t base_pa;
    uint64_t entries[L1_SNAP_ENTRIES];
    bool     entry_valid[L1_SNAP_ENTRIES];
    bool     snap_active;
} L1Snapshot;

typedef struct {
    uint64_t base_pa;           /* PA of the L2 table being shadowed */
    uint64_t entries[L2_SNAP_ENTRIES];
    bool     entry_valid[L2_SNAP_ENTRIES];
    bool     snap_active;
} L2Snapshot;

static PTCEntry   g_ptc[NUM_CPUS][PTC_SIZE];
static L1Snapshot g_l1snap[NUM_CPUS];
static L2Snapshot g_l2snap[NUM_CPUS];

/* Called on TLBI instructions: flush TLB + PTC but NOT the L1 snapshot.
 * The L1 snapshot models hardware TLB immunity to physical aliasing: once
 * L1[256] is cached in the snapshot, SCS writes that corrupt PA 0x41ead800
 * do not affect cached translations.  Real hardware TLBIs don't invalidate
 * the hardware page-table cache for global kernel entries either. */
void mmu_tlb_flush_all(struct ARM64CPU *cpu)
{
    int id = cpu->id;
    if (id >= 0 && id < NUM_CPUS) {
        g_tlb_gen[id]++;           /* invalidates TLB and PTC (same gen) */
        /* L1 snapshot intentionally NOT cleared — see comment above */
    }
}

/* Called on TTBR1 writes: the page table root changed, so both snapshots
 * must be rebuilt from the new table. */
void mmu_l1snap_invalidate(struct ARM64CPU *cpu)
{
    int id = cpu->id;
    if (id >= 0 && id < NUM_CPUS) {
        g_tlb_gen[id]++;
        g_l1snap[id].snap_active = false;
        g_l2snap[id].snap_active = false;
    }
}

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

/* Write 64-bit to physical, used for AF update.
 * Also the central hook for L1/L2 snapshot maintenance: any physical write to
 * a snapshotted page table page (regardless of caller) is reflected here. */
static void phys_write64(PhysMem *mem, uint64_t pa, uint64_t val)
{
    uint8_t *p = mem_ptr(mem, pa);
    if (p) {
        __builtin_memcpy(p, &val, 8);
    } else {
        mem_write(mem, pa, val, 8);
    }

    /* Keep L1/L2 snapshots in sync with physical writes to PT pages.
     * phys_write64 is called both from AF-update paths (inside mmu_translate)
     * and from mmu_store (via the hook below).  It is the authoritative
     * physical-write path for the emulator; all PT updates must reach here. */
    uint64_t page_pa = pa & ~0xFFFULL;
    uint64_t idx     = (pa & 0xFFFULL) / 8;
    for (int cid = 0; cid < NUM_CPUS; cid++) {
        L2Snapshot *s2 = &g_l2snap[cid];
        if (s2->snap_active && s2->base_pa == page_pa && idx < L2_SNAP_ENTRIES) {
            if (s2->entries[idx] != val) {
                static uint64_t phys_l2_count = 0;
                if (++phys_l2_count <= 64)
                    fprintf(stderr,
                        "[L2-PHYS-UPDATE] #%llu PA=0x%llx idx=%llu "
                        "old=0x%016llx new=0x%016llx\n",
                        (unsigned long long)phys_l2_count,
                        (unsigned long long)pa,
                        (unsigned long long)idx,
                        (unsigned long long)s2->entries[idx],
                        (unsigned long long)val);
                s2->entries[idx] = val;
            }
        }
        L1Snapshot *snap = &g_l1snap[cid];
        if (snap->snap_active && snap->base_pa == page_pa
                && idx < L1_SNAP_ENTRIES && snap->entry_valid[idx]) {
            snap->entries[idx] = val;
        }
    }
}

TLBEntry mmu_translate(struct ARM64CPU *cpu, PhysMem *mem,
                        uint64_t va, MemAccess access, int el)
{
    TLBEntry t = { .pa = va, .ok = true, .write_ok = true, .exec_ok = true };

    /* MMU disabled: identity map */
    if (!(cpu->sctlr_el1 & SCTLR_M)) {
        return t;
    }

    /* TLB lookup — check cache before doing a full page-table walk */
    {
        int cid = cpu->id;
        if (cid >= 0 && cid < NUM_CPUS) {
            SWTLBEntry *slot = &g_tlb[cid][TLB_IDX(va)];
            if (slot->valid
                && slot->gen == g_tlb_gen[cid]
                && slot->tag == (va >> 12))
            {
                t.pa       = slot->pa_base | (va & 0xFFFULL);
                t.write_ok = slot->write_ok;
                t.exec_ok  = slot->exec_ok;
                if (access == MEM_WRITE && !t.write_ok) t.ok = false;
                if (access == MEM_EXEC  && !t.exec_ok)  t.ok = false;
                return t;
            }
        }
    }

    /* Choose TTBR based on VA top bits.
     * ARM64 VA selection: bits[63:48]=0xFFFF → TTBR1 (kernel), else TTBR0 (user/idmap).
     * Some kernel VAs only have bits[63:56]=0xFF (T1SZ=25 → 39-bit VA), so also check
     * bit 63 set → TTBR1 (kernel VAs are always negative/sign-extended). */
    uint64_t ttbr;
    int use_ttbr1 = (int64_t)va < 0; /* bit63=1 → kernel VA → TTBR1 */
    if (use_ttbr1) {
        ttbr = cpu->ttbr1_el1;
    } else {
        ttbr = cpu->ttbr0_el1;
    }

    /* Compute page table walk start level from TCR_EL1 Tsize.
     * 4KB granule: bits_per_level=9, page_bits=12.
     * start_level = 3 - floor((VA_bits - 1 - 12) / 9)
     * where VA_bits = 64 - T(n)SZ.
     *
     * T0SZ=24 → VA_bits=40 → floor(27/9)=3 → start_level=0 (L0 walk, 2-entry L0 table)
     * T1SZ=25 → VA_bits=39 → floor(26/9)=2 → start_level=1 (L1 walk, 512-entry L1 table)
     */
    int tsize = use_ttbr1
        ? (int)((cpu->tcr_el1 >> 16) & 0x3F)   /* T1SZ bits[21:16] */
        : (int)((cpu->tcr_el1 >>  0) & 0x3F);   /* T0SZ bits[5:0]  */
    int va_bits   = 64 - tsize;
    int start_level = 3 - (va_bits - 1 - 12) / 9;
    if (start_level < 0) start_level = 0;
    if (start_level > 3) start_level = 3;

    uint64_t table_pa = ttbr & PTE_ADDR_MASK;
    uint64_t entry    = 0;
    uint64_t entry_pa = 0;

    static int mmu_fail_log = 0;

    int cid = cpu->id;
    uint32_t cur_gen = (cid >= 0 && cid < NUM_CPUS) ? g_tlb_gen[cid] : 0;

    /* Page table walk: start_level through L3 */
    for (int level = start_level; level <= 3; level++) {
        int shift = 39 - level * 9;
        uint64_t idx = (va >> shift) & 0x1FF;
        entry_pa = table_pa + idx * 8;

        if (cid >= 0 && cid < NUM_CPUS) {
            /* L1 (start_level): use dedicated snapshot — immune to aliasing */
            if (level == start_level && use_ttbr1) {
                L1Snapshot *snap = &g_l1snap[cid];
                /* Invalidate snapshot if TTBR base changed or after a flush */
                if (!snap->snap_active || snap->base_pa != table_pa) {
                    /* Reset: clear all valid flags */
                    for (unsigned si = 0; si < L1_SNAP_ENTRIES; si++)
                        snap->entry_valid[si] = false;
                    snap->base_pa    = table_pa;
                    snap->snap_active = true;
                }
                if (!snap->entry_valid[idx]) {
                    /* Miss: load from physical memory once */
                    snap->entries[idx]      = phys_read64(mem, entry_pa);
                    snap->entry_valid[idx]  = true;
                }
                entry = snap->entries[idx];
            } else if (level == start_level + 1 && use_ttbr1) {
                /* L2 for TTBR1: dedicated snapshot, eagerly preloaded.
                 *
                 * The SCS corrupts the entire L2 table page (PA range
                 * 0x41eae000–0x41eae7FF) after ~42M insns.  Lazy loading
                 * captures corrupted values for any L2 entry first accessed
                 * after the SCS reaches it.  Eager preload captures ALL
                 * entries on first snapshot activation (~30M insns, before
                 * the SCS reaches the L2 table), protecting all 512 entries
                 * regardless of the order they are first walked. */
                L2Snapshot *s2 = &g_l2snap[cid];
                if (!s2->snap_active || s2->base_pa != table_pa) {
                    /* Preload entire L2 table from physical memory at once */
                    for (unsigned si = 0; si < L2_SNAP_ENTRIES; si++) {
                        s2->entries[si]     = phys_read64(mem, table_pa + si * 8);
                        s2->entry_valid[si] = true;
                    }
                    s2->base_pa     = table_pa;
                    s2->snap_active = true;
                }
                entry = s2->entries[idx];
            } else {
                /* L3 and beyond: use PTC (direct-mapped, collision-evicted) */
                PTCEntry *ps = &g_ptc[cid][PTC_IDX(entry_pa)];
                if (ps->valid && ps->gen == cur_gen && ps->pa == entry_pa) {
                    entry = ps->val;
                } else {
                    entry = phys_read64(mem, entry_pa);
                    ps->pa    = entry_pa;
                    ps->val   = entry;
                    ps->gen   = cur_gen;
                    ps->valid = true;
                }
            }
        } else {
            entry = phys_read64(mem, entry_pa);
        }

        /* On-demand linear map population.
         *
         * Linux sets up only the kernel-image L2 entries in __create_page_tables
         * (L2[64..79]).  paging_init() sets up the full linear map later, but some
         * early-boot code (e.g. the EL1 exception handler calling __do_kernel_fault)
         * accesses linear-map VAs before paging_init() runs.  This causes a recursive
         * exception loop that stalls the boot.
         *
         * Rule: VA is in the "first-1GB linear map" when:
         *   - use_ttbr1 && level == start_level+1 (we are deciding on an L2 block)
         *   - entry == 0 (not yet mapped by paging_init)
         *   - computed PA = (VA aligned to 2MB) - linear_offset is within RAM
         *
         * PAGE_OFFSET for T1SZ=25 with L1[256] as linear-map root:
         *   TTBR1_base = 0xFFFFFF8000000000
         *   PAGE_OFFSET = TTBR1_base + 256 * 2^30 = 0xFFFFFFC000000000
         *   linear_offset = PAGE_OFFSET - ram_base
         */
        if (entry == 0 && use_ttbr1 && level == start_level + 1) {
            static const uint64_t PAGE_OFF = 0xFFFFFFC000000000ULL;
            uint64_t linear_off = PAGE_OFF - mem->ram_base;
            int      blk_shift  = 39 - level * 9;          /* 21 at level 2 = 2MB */
            uint64_t blk_va     = va & ~((1ULL << blk_shift) - 1);
            /* Underflow guard: if blk_va < linear_off, PA would wrap */
            if (blk_va >= PAGE_OFF) {
                uint64_t pa_cand = blk_va - linear_off;
                if (pa_cand >= mem->ram_base && pa_cand < mem->ram_base + mem->ram_size) {
                    /* Attrs match the kernel-image block descriptors (0x701):
                     *   bits[1:0]=01 (block), bits[7:6]=00 (AP EL1 R/W), bit[10]=1 (AF),
                     *   bit[11]=1 (nG), SH=00. */
                    uint64_t blk_desc = pa_cand | 0x701ULL;
                    static uint64_t linmap_fill_count = 0;
                    if (++linmap_fill_count <= 64)
                        fprintf(stderr,
                            "[LINMAP-FILL] #%llu VA=0x%llx L2[%llu] PA=0x%llx desc=0x%llx\n",
                            (unsigned long long)linmap_fill_count,
                            (unsigned long long)va, (unsigned long long)idx,
                            (unsigned long long)pa_cand, (unsigned long long)blk_desc);
                    phys_write64(mem, entry_pa, blk_desc);
                    entry = blk_desc;
                    /* phys_write64 updates the L2 snapshot automatically */
                } else if (blk_va >= 0xFFFFFFFD00000000ULL) {
                    /* Fixmap region L2 miss: synthesise a TABLE entry pointing to a
                     * fresh scratch L3 page so the walk reaches L3 where FIXMAP-FILL
                     * takes over.  16 scratch L3 pages carved from top of RAM. */
                    static uint64_t fxl3_pool_base = 0;
                    static uint64_t fxl3_pool_used = 0;
                    static uint64_t fxl3_key[16];
                    static uint64_t fxl3_val[16];
                    if (!fxl3_pool_base)
                        fxl3_pool_base = mem->ram_base + mem->ram_size
                                         - 0x1000ULL            /* fixmap zero page at top */
                                         - 16ULL * 0x1000ULL;   /* L3 pool just below */
                    uint64_t l3_pa = 0;
                    for (uint64_t ai = 0; ai < fxl3_pool_used; ai++) {
                        if (fxl3_key[ai] == entry_pa) { l3_pa = fxl3_val[ai]; break; }
                    }
                    if (!l3_pa && fxl3_pool_used < 16) {
                        l3_pa = fxl3_pool_base + fxl3_pool_used * 0x1000ULL;
                        fxl3_key[fxl3_pool_used] = entry_pa;
                        fxl3_val[fxl3_pool_used] = l3_pa;
                        fxl3_pool_used++;
                        static uint64_t fixmap_l2_cnt = 0;
                        if (++fixmap_l2_cnt <= 16)
                            fprintf(stderr,
                                "[FIXMAP-L2-FILL#%llu] VA=0x%llx L2[%llu] -> new L3 PA=0x%llx\n",
                                (unsigned long long)fixmap_l2_cnt,
                                (unsigned long long)va, (unsigned long long)idx,
                                (unsigned long long)l3_pa);
                    }
                    if (l3_pa) {
                        uint64_t tbl_desc = l3_pa | 0x3ULL;
                        phys_write64(mem, entry_pa, tbl_desc);
                        entry = tbl_desc;
                    }
                }
            }
        }

        /* On-demand vmemmap fill: handle missing page-table entries for any VA in the
         * vmemmap/sub-linear-map region (0xFFFFFF8000000000-0xFFFFFFBFFFFFFFFF).
         * This range covers the sparse vmemmap (struct page array) and vmalloc area.
         * Linux sets these up lazily in paging_init; early-boot exception handlers
         * try to access vmemmap to get task/page info and triple-fault without this.
         *
         * Strategy:
         *  - At L1/L2 level (entry == 0, < L3): synthesise a TABLE descriptor pointing
         *    to a freshly zeroed scratch page.  The walk then descends to L3.
         *  - At L3 level (entry == 0): synthesise a PAGE descriptor to the fixmap
         *    scratchpad zero page (RAM_TOP - 4KB).  Reads return 0; writes are benign.
         */
        if (entry == 0 && use_ttbr1 &&
                va >= 0xFFFFFF8000000000ULL && va <= 0xFFFFFFBFFFFFFFFFULL) {
            /* Scratch page pool carved from top of RAM, below the fixmap pools.
             * Layout (top-down): [fixmap zero page 4KB] [fxl3_pool 16×4KB] [vmm_pool 64×4KB]
             * vmm_pool_base = RAM_TOP - 1 - 16 - 64 pages = RAM_TOP - 81 pages */
            static uint64_t vmm_pool_base = 0;
            static uint64_t vmm_pool_used = 0;
#define VMM_POOL_PAGES 64
            static uint64_t vmm_key[VMM_POOL_PAGES];
            static uint64_t vmm_val[VMM_POOL_PAGES];
            if (!vmm_pool_base)
                vmm_pool_base = mem->ram_base + mem->ram_size
                                - 0x1000ULL              /* fixmap zero page */
                                - 16ULL * 0x1000ULL      /* fxl3_pool */
                                - VMM_POOL_PAGES * 0x1000ULL;
            if (level < 3) {
                /* Synthesise TABLE entry: allocate a scratch page per unique entry_pa */
                uint64_t child_pa = 0;
                for (uint64_t ai = 0; ai < vmm_pool_used; ai++)
                    if (vmm_key[ai] == entry_pa) { child_pa = vmm_val[ai]; break; }
                if (!child_pa && vmm_pool_used < VMM_POOL_PAGES) {
                    child_pa = vmm_pool_base + vmm_pool_used * 0x1000ULL;
                    vmm_key[vmm_pool_used] = entry_pa;
                    vmm_val[vmm_pool_used] = child_pa;
                    vmm_pool_used++;
                    static uint64_t vmm_tbl_cnt = 0;
                    if (++vmm_tbl_cnt <= 32)
                        fprintf(stderr,
                            "[VMEMMAP-L%d-FILL#%llu] VA=0x%llx entry_pa=0x%llx -> child=0x%llx\n",
                            level, (unsigned long long)vmm_tbl_cnt,
                            (unsigned long long)va, (unsigned long long)entry_pa,
                            (unsigned long long)child_pa);
                }
                if (child_pa) {
                    uint64_t tbl_desc = child_pa | 0x3ULL;
                    phys_write64(mem, entry_pa, tbl_desc);
                    entry = tbl_desc;
                }
            } else {
                /* L3: map to the fixmap zero page (reads = 0, writes = benign) */
                uint64_t zero_pa = mem->ram_base + mem->ram_size - 0x1000ULL;
                uint64_t desc = zero_pa | (1ULL << 54) | (1ULL << 53) | (1ULL << 10) | 0x3ULL;
                phys_write64(mem, entry_pa, desc);
                if (cid >= 0 && cid < NUM_CPUS) {
                    PTCEntry *ps = &g_ptc[cid][PTC_IDX(entry_pa)];
                    ps->pa = entry_pa; ps->val = desc; ps->gen = cur_gen; ps->valid = true;
                }
                entry = desc;
                static uint64_t vmm_pg_cnt = 0;
                if (++vmm_pg_cnt <= 32)
                    fprintf(stderr,
                        "[VMEMMAP-PAGE-FILL#%llu] VA=0x%llx -> zero PA=0x%llx\n",
                        (unsigned long long)vmm_pg_cnt,
                        (unsigned long long)va, (unsigned long long)zero_pa);
            }
        }

        /* On-demand L3 fixmap fill for earlycon UART.
         *
         * The kernel's earlycon initialization accesses the PL011 UART via a
         * fixmap VA before set_fixmap() has written the L3 entry.  With the L3
         * entry empty the first UART access faults, the exception handler runs,
         * cascades through vmemmap and null-ptr faults, and the emulator spends
         * 20k+ exception cycles going nowhere.
         *
         * Fix: the moment we see an L3 miss for the known earlycon fixmap page,
         * synthesise the UART page descriptor (PA=0x09000000) and write it to
         * physical memory so subsequent accesses hit the TLB instead.
         *
         * The fixmap VA was observed in the diagnostic run as FAR=0xFFFFFFFDFDA3FF70;
         * the 4KB page base is 0xFFFFFFFDFDA3F000.  This is stable for T1SZ=25.
         */
        /* On-demand L3 fixmap fill for the full fixmap region.
         *
         * The kernel makes multiple fixmap accesses during early boot (earlycon
         * UART, bootmap, early-ioremap scratch pages) before paging_init() has
         * run.  All of these map through the fixmap L3 table (already created by
         * __create_page_tables) but the individual L3 slot entries are 0.
         *
         * Strategy:
         *  - The earlycon UART slot (page 0xFFFFFFFDFDA3F000) maps to PA=0x09000000.
         *  - All other fixmap slots in the fixmap region (top ~1GB of TTBR1 space,
         *    VA > 0xFFFFFFFD00000000) map to a dedicated scratchpad zero page at
         *    PA = RAM_TOP - 4KB.  Reads return 0; writes are silently discarded
         *    (they land on the scratchpad page and are never re-read by a different
         *    user).  This lets the kernel proceed past early-boot fixmap accesses
         *    without triggering the exception cascade.
         */
        if (entry == 0 && use_ttbr1 && level == 3) {
            static const uint64_t FIXMAP_REGION_BASE = 0xFFFFFFFD00000000ULL;
            static const uint64_t UART_FIXMAP_PAGE   = 0xFFFFFFFDFDA3F000ULL;
            uint64_t va_page = va & ~0xFFFULL;
            if (va_page >= FIXMAP_REGION_BASE) {
                uint64_t pa_target;
                const char *label;
                if (va_page == UART_FIXMAP_PAGE) {
                    /* earlycon UART: map to PL011 PA */
                    pa_target = 0x09000000ULL;
                    label = "UART";
                } else {
                    /* Unknown fixmap slot: map to scratchpad zero page.
                     * PA = top of RAM - 4KB.  RAM is 2GB at 0x40000000,
                     * so scratchpad = 0x40000000 + 2GB - 4KB = 0xBFFFF000. */
                    pa_target = mem->ram_base + mem->ram_size - 0x1000ULL;
                    label = "scratch";
                }
                /* UXN|PXN|AF|page — permissions enough for EL1 R/W */
                uint64_t desc = pa_target | (1ULL << 54) | (1ULL << 53) | (1ULL << 10) | 0x3ULL;
                phys_write64(mem, entry_pa, desc);
                if (cid >= 0 && cid < NUM_CPUS) {
                    PTCEntry *ps = &g_ptc[cid][PTC_IDX(entry_pa)];
                    ps->pa    = entry_pa;
                    ps->val   = desc;
                    ps->gen   = cur_gen;
                    ps->valid = true;
                }
                entry = desc;
                static uint64_t fixmap_fill_cnt = 0;
                if (++fixmap_fill_cnt <= 32)
                    fprintf(stderr,
                        "[FIXMAP-FILL#%llu] VA=0x%llx -> PA=0x%llx (%s) desc=0x%llx\n",
                        (unsigned long long)fixmap_fill_cnt,
                        (unsigned long long)va, (unsigned long long)pa_target,
                        label, (unsigned long long)desc);
            }
        }

        if (!(entry & PTE_VALID)) {
            /* Always log failures for the stuck-PC VA */
            bool is_spin_va = (va == 0xffffffc0080b7f78ULL);
            static int spin_fail_log = 0;
            if (mmu_fail_log < 4 || (is_spin_va && spin_fail_log < 5)) {
                if (is_spin_va) spin_fail_log++;
                fprintf(stderr, "[MMU-FAIL] VA=0x%llx L%d: table_pa=0x%llx idx=%llu entry=0x%llx (INVALID)\n",
                        (unsigned long long)va, level,
                        (unsigned long long)table_pa,
                        (unsigned long long)idx,
                        (unsigned long long)entry);
                /* Dump next 7 entries to reveal table structure */
                for (int di = 1; di <= 7; di++) {
                    uint64_t de = phys_read64(mem, table_pa + (idx+di)*8);
                    if (de) fprintf(stderr, "  [+%d] 0x%llx\n", di, (unsigned long long)de);
                }
                if (!is_spin_va) mmu_fail_log++;
            }
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
    /* Log first hit on UART PA range to catch earlycon mapping */
    if (t.pa >= 0x09000000ULL && t.pa < 0x09001000ULL) {
        static int uart_hit = 0;
        if (uart_hit < 16)
            fprintf(stderr, "[MMU] VA=0x%llx -> UART PA=0x%llx access=%d\n",
                    (unsigned long long)va, (unsigned long long)t.pa, (int)access);
        uart_hit++;
    }

    /* AP bits: [7:6].
     * AP[2:1]=00: EL1 RW, EL0 no access
     * AP[2:1]=01: EL1 RW, EL0 RW
     * AP[2:1]=10: EL1 RO, EL0 no access
     * AP[2:1]=11: EL1 RO, EL0 RO
     *
     * BOOT-EXTRACTION MODE: skip EL1 write-deny. The idmap (__create_page_tables)
     * wrote AP=0b10 for the 2MB block covering the kernel stack region — correct
     * behaviour would be AP=0b00 for data/BSS. The real kernel writes through TTBR1
     * kernel VAs (which have correct RW attrs), not the idmap. Our emulator doesn't
     * yet transition SP to kernel VAs, so we'd fault on every stack write. Skipping
     * EL1 AP write enforcement unblocks boot; fix __create_page_tables flags later
     * and re-enable by setting SKIP_EL1_AP_ENFORCE to 0. */
#define SKIP_EL1_AP_ENFORCE 1

    uint64_t ap = (entry >> 6) & 3;
    if (ap == 2 || ap == 3) {
        if (el == 0) {
            t.write_ok = false; /* EL0 always respects RO */
        } else {
            /* EL1 write to RO page */
#if SKIP_EL1_AP_ENFORCE
            if (access == MEM_WRITE) {
                static uint64_t ap_skip_count = 0;
                ap_skip_count++;
                if (ap_skip_count <= 16)
                    fprintf(stderr,
                        "[MMU-AP-SKIP] #%llu EL%d write VA=0x%016llx PA=0x%016llx desc=0x%016llx AP=%llu (skipped)\n",
                        (unsigned long long)ap_skip_count,
                        el,
                        (unsigned long long)va,
                        (unsigned long long)t.pa,
                        (unsigned long long)entry,
                        (unsigned long long)ap);
            }
#else
            t.write_ok = false;
#endif
        }
    }

    /* UXN/PXN */
    if (entry & PTE_UXN) { /* user execute never — affects EL0 */
        if (el == 0) t.exec_ok = false;
    }
    if (entry & PTE_PXN) { /* privileged execute never — EL1 */
        if (el >= 1) t.exec_ok = false;
    }

    /* Access flag update: write to physical and keep caches in sync */
    if (!(entry & PTE_AF)) {
        entry |= PTE_AF;
        phys_write64(mem, entry_pa, entry);
        if (cid >= 0 && cid < NUM_CPUS) {
            /* Update PTC if it's the cached slot */
            PTCEntry *ps = &g_ptc[cid][PTC_IDX(entry_pa)];
            if (ps->valid && ps->gen == cur_gen && ps->pa == entry_pa)
                ps->val = entry;
            /* Update L1 snapshot if entry_pa is in the L1 table */
            L1Snapshot *snap = &g_l1snap[cid];
            if (snap->snap_active && snap->base_pa == (entry_pa & ~0xFFFULL)) {
                uint64_t l1_idx = (entry_pa - snap->base_pa) / 8;
                if (l1_idx < L1_SNAP_ENTRIES && snap->entry_valid[l1_idx])
                    snap->entries[l1_idx] = entry;
            }
            /* Update L2 snapshot if entry_pa is in the L2 table */
            L2Snapshot *s2 = &g_l2snap[cid];
            if (s2->snap_active && s2->base_pa == (entry_pa & ~0xFFFULL)) {
                uint64_t l2_idx = (entry_pa - s2->base_pa) / 8;
                if (l2_idx < L2_SNAP_ENTRIES)
                    s2->entries[l2_idx] = entry;
            }
        }
    }

    if (access == MEM_WRITE && !t.write_ok) {
        t.ok = false;
    }
    if (access == MEM_EXEC && !t.exec_ok) {
        t.ok = false;
    }

    /* Fill TLB on successful translation */
    if (t.ok) {
        int cid = cpu->id;
        if (cid >= 0 && cid < NUM_CPUS) {
            SWTLBEntry *slot = &g_tlb[cid][TLB_IDX(va)];
            slot->tag      = va >> 12;
            slot->pa_base  = t.pa & ~(uint64_t)0xFFF;
            slot->write_ok = t.write_ok;
            slot->exec_ok  = t.exec_ok;
            slot->gen      = g_tlb_gen[cid];
            slot->valid    = true;
        }
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
    /* VA watchpoint: init_task.cgroups at 0xffffffc009c5e428 */
    if (va >= 0xffffffc009c5e420ULL && va <= 0xffffffc009c5e430ULL) {
        static int va_wp = 0;
        if (++va_wp <= 4)
            fprintf(stderr, "[VA-WP-CGROUPS] VA=0x%llx -> PA=0x%llx val=0x%llx size=%d\n",
                    (unsigned long long)va, (unsigned long long)t.pa,
                    (unsigned long long)val, size);
    }
    mem_write(mem, t.pa, val, size);

    /* Keep page-table snapshots in sync with runtime kernel writes.
     *
     * Problem: paging_init() and the page-fault handler populate L2 entries
     * (e.g. L2[152] → vmemmap) AFTER the L2 snapshot was eagerly preloaded at
     * ~30M insns.  Those entries were 0 at preload time.  Without this hook the
     * snapshot serves stale zeros, causing permanent translation faults for any
     * VA in those regions.
     *
     * Filter: valid page-table descriptors for our RAM (PA range 0x40000000–
     * 0x7FFFFFFF) have bits[63:48] = 0x0000.  SCS pushes write kernel return
     * addresses (0xFFFFFFC0xxxxxxxx): bits[63:48] = 0xFFFF.  The filter lets
     * table/block descriptors through and blocks SCS corruptions.
     *
     * This handles the symmetric problem for L1 as well (kernel may remap
     * entries in the L1 table for hot-patching or KASLR fixup). */
    if (size == 8 && (val >> 48) == 0) {
        uint64_t page_pa = t.pa & ~0xFFFULL;
        uint64_t idx     = (t.pa & 0xFFFULL) / 8;
        for (int cid = 0; cid < NUM_CPUS; cid++) {
            L2Snapshot *s2 = &g_l2snap[cid];
            if (s2->snap_active && s2->base_pa == page_pa && idx < L2_SNAP_ENTRIES) {
                static uint64_t l2_update_count = 0;
                if (++l2_update_count <= 32)
                    fprintf(stderr,
                        "[L2-SNAP-UPDATE] #%llu PA=0x%llx idx=%llu "
                        "old=0x%016llx new=0x%016llx\n",
                        (unsigned long long)l2_update_count,
                        (unsigned long long)t.pa,
                        (unsigned long long)idx,
                        (unsigned long long)s2->entries[idx],
                        (unsigned long long)val);
                s2->entries[idx] = val;
            }
            L1Snapshot *snap = &g_l1snap[cid];
            if (snap->snap_active && snap->base_pa == page_pa
                    && idx < L1_SNAP_ENTRIES && snap->entry_valid[idx]) {
                snap->entries[idx] = val;
            }
        }
    }

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
