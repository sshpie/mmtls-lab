/*
 * mmtls_inject — PLT/GOT injector for libwechatnetwork.so
 *
 * Runs on the Android device as root.  Given a target PID:
 *   1. ptrace-attaches to stop the target
 *   2. Finds libwechatnetwork.so and libhook.so bases in /proc/pid/maps
 *   3. Parses libwechatnetwork.so ELF from /proc/pid/mem (live image):
 *      PT_DYNAMIC → DT_JMPREL/DT_SYMTAB/DT_STRTAB → scan R_AARCH64_JUMP_SLOT entries
 *      for each target symbol → runtime GOT address = base + r_offset
 *   4. Reads libhook.so ELF from disk to find hook_ and g_real_ symbol offsets
 *   5. For each symbol:
 *      a. Locate mprotect in target libc.so (found once, cached)
 *      b. Inject mprotect(page, PAGE_SIZE, PROT_READ|PROT_WRITE) via ptrace register dance
 *      c. PEEK original GOT value, POKE hook address
 *      d. Write original value into g_real_* global in libhook.so
 *      e. Restore page to PROT_READ
 *   6. Bonus: dumps gILinkKey (live 72-byte MMTLS session key) from libwechatnetwork.so BSS
 *   7. ptrace-detaches → target resumes with hooks active
 *
 * FULL_RELRO bypass: Android's dynamic linker calls mprotect(PROT_READ) on .got.plt
 * after all relocations are done.  PTRACE_POKEDATA into a read-only page returns EIO.
 * We inject a mprotect(PROT_READ|PROT_WRITE) call *inside* the target process by
 * manipulating AArch64 registers via PTRACE_GETREGSET/SETREGSET, then single-step
 * until the function returns, then restore all registers.
 *
 * PAC: no-op on Android 12 QEMU/AVD emulator — hook function pointers do not need
 *      valid PAC signatures; blr xN works with plain addresses.
 *
 * Usage:
 *   mmtls_inject <pid>
 *   mmtls_inject <pid> --dump-key-only
 *
 * Requires: root, ptrace capability, libhook.so already mapped in target process
 *           (inject via wrap.com.tencent.mm LD_PRELOAD before starting WeChat)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <elf.h>

/* R_AARCH64_JUMP_SLOT = 1026 decimal (from AArch64 ELF ABI) */
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

/* NT_PRSTATUS register set type for PTRACE_GETREGSET/SETREGSET */
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#define MAX_PATH    512
#define MAX_MODULES 512

/* gILinkKey VA in libwechatnetwork.so v8.0.56 arm64 (BSS offset from load base) */
#define GILIINKKEY_VA   0x3d4648ULL
#define GILIINKKEY_SIZE 72

/* ── AArch64 register layout for PTRACE_GETREGSET(NT_PRSTATUS) ────────────── */

/* Matches struct user_pt_regs in <sys/user.h> on AArch64 Linux / Android NDK */
typedef struct {
    uint64_t regs[31];   /* x0 – x30 (x30 = LR) */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} AArch64Regs;

/* ── Symbols to hook ─────────────────────────────────────────────────────── */

typedef struct {
    const char *sym;          /* PLT symbol name in libwechatnetwork.so */
    const char *hook_sym;     /* function name in libhook.so            */
    const char *real_sym;     /* global name in libhook.so for orig ptr */
} HookEntry;

static const HookEntry HOOKS[] = {
    { "connect",  "hook_connect",  "g_real_connect"  },
    { "send",     "hook_send",     "g_real_send"      },
    { "recv",     "hook_recv",     "g_real_recv"      },
    { "sendto",   "hook_sendto",   "g_real_sendto"    },
    { "recvfrom", "hook_recvfrom", "g_real_recvfrom"  },
    { NULL, NULL, NULL }
};

/* ── /proc/pid/maps helpers ─────────────────────────────────────────────── */

typedef struct {
    uint64_t start;
    char     perms[5];
    char     path[MAX_PATH];
} MapEntry;

static int read_maps(pid_t pid, MapEntry *out, int max_entries, int *count) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) { perror("fopen maps"); return -1; }

    *count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && *count < max_entries) {
        uint64_t start = 0;
        char perms[5] = {0};
        char path[MAX_PATH] = {0};
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) < 3)
            continue;
        start = (uint64_t)lo;
        /* extract path from after the 5th space-separated field */
        {
            char *p = line;
            int sp = 0;
            while (*p && sp < 5) { if (*p++ == ' ') sp++; }
            while (*p == ' ') p++;
            size_t n = strlen(p);
            while (n > 0 && (p[n-1] == '\n' || p[n-1] == '\r')) n--;
            if (n > 0 && n < MAX_PATH) { strncpy(path, p, n); path[n] = '\0'; }
        }
        out[*count].start = start;
        strncpy(out[*count].perms, perms, 4);
        strncpy(out[*count].path, path, MAX_PATH - 1);
        (*count)++;
    }
    fclose(fp);
    return 0;
}

/* Return first executable mapping's base for module_name, and optionally its path. */
static uint64_t find_module_base(MapEntry *maps, int count,
                                  const char *module_name, char *out_path) {
    for (int i = 0; i < count; i++) {
        if (strstr(maps[i].path, module_name) &&
            maps[i].perms[0] == 'r' && maps[i].perms[2] == 'x') {
            if (out_path) strncpy(out_path, maps[i].path, MAX_PATH - 1);
            return maps[i].start;
        }
    }
    return 0;
}

/* ── /proc/pid/mem helpers ───────────────────────────────────────────────── */

static int mem_read(pid_t pid, uint64_t addr, void *buf, size_t len) {
    struct iovec local  = { buf,             len };
    struct iovec remote = { (void *)addr,    len };
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (r == (ssize_t)len) ? 0 : -1;
}

/* ── ptrace helpers ─────────────────────────────────────────────────────── */

static int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH"); return -1;
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) { perror("waitpid"); return -1; }
    return 0;
}

static int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_DETACH"); return -1;
    }
    return 0;
}

static uint64_t ptrace_peek_u64(pid_t pid, uint64_t addr) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (v == -1 && errno) { perror("PTRACE_PEEKDATA"); return 0; }
    return (uint64_t)v;
}

static int ptrace_poke_u64(pid_t pid, uint64_t addr, uint64_t val) {
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)val) == -1) {
        perror("PTRACE_POKEDATA"); return -1;
    }
    return 0;
}

/* ── AArch64 register access ────────────────────────────────────────────── */

static int get_regs(pid_t pid, AArch64Regs *out) {
    struct iovec iov = { .iov_base = out, .iov_len = sizeof(*out) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_GETREGSET"); return -1;
    }
    return 0;
}

static int set_regs(pid_t pid, const AArch64Regs *r) {
    struct iovec iov = { .iov_base = (void *)r, .iov_len = sizeof(*r) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_SETREGSET"); return -1;
    }
    return 0;
}

/*
 * call_func_in_target — execute func(x0, x1, x2) inside pid via ptrace.
 *
 * Strategy: save all registers, set args + PC = func, set LR = orig_pc so
 * the callee's "ret" will return execution to the same address the target was
 * stopped at.  Single-step until PC == orig_pc (function returned) or until
 * max_steps is exhausted.  Restore saved registers and return x0.
 *
 * Works for small libc stubs (mprotect is ~4 instructions in bionic).
 */
static int call_func_in_target(pid_t pid, uint64_t func_addr,
                                uint64_t a0, uint64_t a1, uint64_t a2,
                                uint64_t *retval) {
    AArch64Regs regs, saved;
    if (get_regs(pid, &regs) != 0) return -1;
    saved = regs;

    uint64_t orig_pc = regs.pc;

    regs.regs[0] = a0;
    regs.regs[1] = a1;
    regs.regs[2] = a2;
    regs.pc       = func_addr;
    regs.regs[30] = orig_pc;   /* LR = orig_pc: "ret" returns here → we stop */

    if (set_regs(pid, &regs) != 0) return -1;

    /* Single-step until PC returns to orig_pc (function returned) */
    int max_steps = 4096;
    int returned  = 0;
    while (max_steps-- > 0) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            perror("PTRACE_SINGLESTEP"); break;
        }
        int status;
        if (waitpid(pid, &status, 0) == -1) break;
        if (!WIFSTOPPED(status)) break;

        AArch64Regs cur;
        if (get_regs(pid, &cur) != 0) break;

        if (cur.pc == orig_pc) {
            if (retval) *retval = cur.regs[0];
            returned = 1;
            break;
        }
    }

    /* Always restore the original register state */
    if (set_regs(pid, &saved) != 0) return -1;

    if (!returned) {
        fprintf(stderr, "[!] call_func_in_target: did not return in %d steps\n", 4096);
        return -1;
    }
    return 0;
}

/* ── ELF dynamic info (from live /proc/pid/mem) ─────────────────────────── */

typedef struct {
    uint64_t dynsym_va;
    uint64_t dynstr_va;
    uint64_t jmprel_va;
    uint64_t jmprel_size;
} DynInfo;

static int load_dyninfo_mem(pid_t pid, uint64_t base, DynInfo *out) {
    Elf64_Ehdr eh;
    if (mem_read(pid, base, &eh, sizeof(eh)) != 0) {
        fprintf(stderr, "read ELF header failed\n"); return -1;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "not 64-bit ELF at 0x%llx\n", (unsigned long long)base); return -1;
    }

    /* Read program headers */
    size_t ph_sz = eh.e_phnum * sizeof(Elf64_Phdr);
    Elf64_Phdr *phdrs = malloc(ph_sz);
    if (!phdrs) return -1;
    if (mem_read(pid, base + eh.e_phoff, phdrs, ph_sz) != 0) {
        free(phdrs); return -1;
    }

    /* Find PT_DYNAMIC */
    uint64_t dyn_va = 0; uint64_t dyn_sz = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_va = phdrs[i].p_vaddr;
            dyn_sz = phdrs[i].p_memsz;
            break;
        }
    }
    free(phdrs);
    if (!dyn_va) { fprintf(stderr, "no PT_DYNAMIC\n"); return -1; }

    /* Read dynamic section */
    size_t n = dyn_sz / sizeof(Elf64_Dyn);
    Elf64_Dyn *dyn = malloc(dyn_sz);
    if (!dyn) return -1;
    if (mem_read(pid, base + dyn_va, dyn, dyn_sz) != 0) { free(dyn); return -1; }

    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < n; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:   out->dynsym_va    = dyn[i].d_un.d_ptr; break;
        case DT_STRTAB:   out->dynstr_va    = dyn[i].d_un.d_ptr; break;
        case DT_JMPREL:   out->jmprel_va    = dyn[i].d_un.d_ptr; break;
        case DT_PLTRELSZ: out->jmprel_size  = dyn[i].d_un.d_val; break;
        default: break;
        }
    }
    free(dyn);

    if (!out->dynsym_va || !out->dynstr_va ||
        !out->jmprel_va || !out->jmprel_size) {
        fprintf(stderr, "missing dynamic entries\n"); return -1;
    }
    return 0;
}

/* Scan RELA PLT for symbol_name; return runtime GOT address or 0 */
static uint64_t find_got_entry(pid_t pid, uint64_t base,
                                const DynInfo *di, const char *symbol_name) {
    uint64_t dynsym_rt = base + di->dynsym_va;
    uint64_t dynstr_rt = base + di->dynstr_va;
    uint64_t jmprel_rt = base + di->jmprel_va;

    size_t n_rela = di->jmprel_size / sizeof(Elf64_Rela);
    Elf64_Rela *rela = malloc(di->jmprel_size);
    if (!rela) return 0;
    if (mem_read(pid, jmprel_rt, rela, di->jmprel_size) != 0) {
        free(rela); return 0;
    }

    uint64_t result = 0;
    for (size_t i = 0; i < n_rela; i++) {
        uint32_t r_type = ELF64_R_TYPE(rela[i].r_info);
        uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
        if (r_type != R_AARCH64_JUMP_SLOT) continue;

        /* Read Elf64_Sym */
        Elf64_Sym sym;
        if (mem_read(pid,
                     dynsym_rt + sym_idx * sizeof(Elf64_Sym),
                     &sym, sizeof(sym)) != 0) continue;

        /* Read symbol name (null-terminated, up to 255 chars) */
        char name[256] = {0};
        uint64_t name_addr = dynstr_rt + sym.st_name;
        if (mem_read(pid, name_addr, name, sizeof(name) - 1) != 0) continue;

        if (strcmp(name, symbol_name) == 0) {
            result = base + rela[i].r_offset;
            break;
        }
    }
    free(rela);
    return result;
}

/* ── ELF symbol lookup from disk ─────────────────────────────────────────── */

/* Return st_value for named symbol in on-disk shared object, or 0 */
static uint64_t find_sym_offset(const char *so_path, const char *sym_name) {
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) { perror("open so"); return 0; }

    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)) goto fail;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) goto fail;

    /* Read section headers */
    size_t sh_sz = eh.e_shnum * sizeof(Elf64_Shdr);
    Elf64_Shdr *shdrs = malloc(sh_sz);
    if (!shdrs) goto fail;
    if (lseek(fd, eh.e_shoff, SEEK_SET) == -1 ||
        read(fd, shdrs, sh_sz) != (ssize_t)sh_sz) { free(shdrs); goto fail; }

    /* Section name string table */
    Elf64_Shdr *shstr_sh = &shdrs[eh.e_shstrndx];
    char *shstrtab = malloc(shstr_sh->sh_size);
    if (!shstrtab) { free(shdrs); goto fail; }
    lseek(fd, shstr_sh->sh_offset, SEEK_SET);
    read(fd, shstrtab, shstr_sh->sh_size);

    Elf64_Shdr *dynsym_sh = NULL, *dynstr_sh = NULL;
    for (int i = 0; i < eh.e_shnum; i++) {
        const char *sname = shstrtab + shdrs[i].sh_name;
        if (strcmp(sname, ".dynsym") == 0) dynsym_sh = &shdrs[i];
        else if (strcmp(sname, ".dynstr") == 0) dynstr_sh = &shdrs[i];
    }
    free(shstrtab);
    if (!dynsym_sh || !dynstr_sh) { free(shdrs); goto fail; }

    size_t nsyms = dynsym_sh->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = malloc(dynsym_sh->sh_size);
    char *dynstr = malloc(dynstr_sh->sh_size);
    if (!syms || !dynstr) { free(syms); free(dynstr); free(shdrs); goto fail; }

    lseek(fd, dynsym_sh->sh_offset, SEEK_SET);
    read(fd, syms, dynsym_sh->sh_size);
    lseek(fd, dynstr_sh->sh_offset, SEEK_SET);
    read(fd, dynstr, dynstr_sh->sh_size);

    uint64_t result = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const char *name = dynstr + syms[i].st_name;
        if (strcmp(name, sym_name) == 0) {
            result = syms[i].st_value;
            break;
        }
    }
    free(syms); free(dynstr); free(shdrs);
    close(fd);
    return result;

fail:
    close(fd);
    return 0;
}

/* ── FULL_RELRO bypass: mprotect injection ──────────────────────────────── */

/*
 * Find mprotect in the target process's libc.so.
 * Returns runtime address, or 0 on failure.
 */
static uint64_t find_libc_mprotect(MapEntry *maps, int map_count) {
    char libc_path[MAX_PATH] = {0};
    uint64_t libc_base = find_module_base(maps, map_count, "libc.so", libc_path);
    if (!libc_base) {
        /* Try libc.bionic path variant */
        libc_base = find_module_base(maps, map_count, "/libc.so", libc_path);
    }
    if (!libc_base || !libc_path[0]) {
        fprintf(stderr, "[!] libc.so not found in target maps\n");
        return 0;
    }
    uint64_t mprotect_off = find_sym_offset(libc_path, "mprotect");
    if (!mprotect_off) {
        fprintf(stderr, "[!] mprotect not found in %s\n", libc_path);
        return 0;
    }
    return libc_base + mprotect_off;
}

/*
 * make_page_writable — inject mprotect(page_addr, PAGE_SIZE, PROT_READ|PROT_WRITE)
 * into pid using the provided mprotect_rt runtime address.
 */
static int make_page_writable(pid_t pid, uint64_t mprotect_rt, uint64_t addr) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uint64_t page_addr = addr & ~(uint64_t)(page_size - 1);

    uint64_t retval = 0;
    int rc = call_func_in_target(pid, mprotect_rt,
                                  page_addr, (uint64_t)page_size,
                                  PROT_READ | PROT_WRITE, &retval);
    if (rc != 0) return -1;
    if ((int64_t)retval != 0) {
        fprintf(stderr, "[!] mprotect(RW) returned %lld\n", (long long)(int64_t)retval);
        return -1;
    }
    return 0;
}

/*
 * restore_page_perms — restore page to PROT_READ after GOT patch.
 */
static void restore_page_perms(pid_t pid, uint64_t mprotect_rt, uint64_t addr) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uint64_t page_addr = addr & ~(uint64_t)(page_size - 1);
    call_func_in_target(pid, mprotect_rt,
                         page_addr, (uint64_t)page_size,
                         PROT_READ, NULL);
}

/* ── gILinkKey extraction ────────────────────────────────────────────────── */

static void dump_giliinkkey(pid_t pid, uint64_t wechat_net_base) {
    uint64_t key_addr = wechat_net_base + GILIINKKEY_VA;
    uint8_t key[GILIINKKEY_SIZE];
    if (mem_read(pid, key_addr, key, sizeof(key)) != 0) {
        fprintf(stderr, "[!] gILinkKey read failed (wrong VA for this build?)\n");
        return;
    }
    printf("[KEY] gILinkKey @ 0x%llx (runtime 0x%llx):\n",
           (unsigned long long)GILIINKKEY_VA, (unsigned long long)key_addr);
    for (int i = 0; i < GILIINKKEY_SIZE; i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    if (GILIINKKEY_SIZE % 16 != 0) printf("\n");

    /* JSON output for ablation ingest */
    printf("[JSON] {\"gILinkKey\":\"");
    for (int i = 0; i < GILIINKKEY_SIZE; i++) printf("%02x", key[i]);
    printf("\",\"va\":\"0x%llx\",\"runtime\":\"0x%llx\"}\n",
           (unsigned long long)GILIINKKEY_VA, (unsigned long long)key_addr);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: mmtls_inject <pid> [--dump-key-only]\n");
        return 1;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    int key_only = (argc >= 3 && strcmp(argv[2], "--dump-key-only") == 0);

    printf("[*] target pid=%d\n", pid);

    /* Read maps before attaching (readable without ptrace on Android root) */
    MapEntry *maps = calloc(MAX_MODULES, sizeof(MapEntry));
    if (!maps) { perror("calloc"); return 1; }
    int map_count = 0;
    if (read_maps(pid, maps, MAX_MODULES, &map_count) != 0) {
        free(maps); return 1;
    }

    char wnet_path[MAX_PATH] = {0};
    char hook_path[MAX_PATH] = {0};

    uint64_t base_wnet = find_module_base(maps, map_count,
                                           "libwechatnetwork.so", wnet_path);
    uint64_t base_hook = find_module_base(maps, map_count,
                                           "libhook.so", hook_path);

    if (!base_wnet) {
        fprintf(stderr, "[!] libwechatnetwork.so not mapped in pid %d\n", pid);
        free(maps); return 1;
    }
    printf("[*] libwechatnetwork.so base = 0x%llx  (%s)\n",
           (unsigned long long)base_wnet, wnet_path);

    /* Find mprotect in target libc.so (needed for FULL_RELRO bypass) */
    uint64_t mprotect_rt = 0;
    if (!key_only) {
        mprotect_rt = find_libc_mprotect(maps, map_count);
        if (!mprotect_rt) {
            fprintf(stderr, "[!] cannot locate mprotect in target — GOT patches may fail\n");
            /* continue: page may already be writable on older linker */
        } else {
            printf("[*] mprotect @ 0x%llx in target libc.so\n",
                   (unsigned long long)mprotect_rt);
        }
    }
    free(maps);

    /* Attach to stop target */
    if (ptrace_attach(pid) != 0) return 1;

    /* Dump key regardless of mode */
    dump_giliinkkey(pid, base_wnet);

    if (key_only) {
        ptrace_detach(pid);
        return 0;
    }

    if (!base_hook) {
        fprintf(stderr, "[!] libhook.so not mapped — is LD_PRELOAD set?\n");
        ptrace_detach(pid);
        return 1;
    }
    printf("[*] libhook.so base         = 0x%llx  (%s)\n",
           (unsigned long long)base_hook, hook_path);

    /* Parse libwechatnetwork.so dynamic info from live memory */
    DynInfo di;
    if (load_dyninfo_mem(pid, base_wnet, &di) != 0) {
        fprintf(stderr, "[!] failed to parse dynamic info\n");
        ptrace_detach(pid);
        return 1;
    }

    /* Patch GOT for each symbol */
    int patched = 0;
    for (int i = 0; HOOKS[i].sym; i++) {
        const char *sym       = HOOKS[i].sym;
        const char *hook_fn   = HOOKS[i].hook_sym;
        const char *real_glob = HOOKS[i].real_sym;

        /* GOT entry address in libwechatnetwork.so */
        uint64_t got_addr = find_got_entry(pid, base_wnet, &di, sym);
        if (!got_addr) {
            printf("[-] %s: no PLT entry (not in libwechatnetwork.so PLT, skip)\n", sym);
            continue;
        }

        /* Hook function address in libhook.so */
        uint64_t hook_off = find_sym_offset(hook_path, hook_fn);
        if (!hook_off) {
            printf("[-] %s: %s not found in libhook.so\n", sym, hook_fn);
            continue;
        }
        uint64_t hook_addr = base_hook + hook_off;

        /* g_real_* global address in libhook.so */
        uint64_t real_off = find_sym_offset(hook_path, real_glob);
        if (!real_off) {
            printf("[-] %s: %s not found in libhook.so\n", sym, real_glob);
            continue;
        }
        uint64_t real_glob_addr = base_hook + real_off;

        /* Read original GOT value */
        uint64_t orig = ptrace_peek_u64(pid, got_addr);
        if (!orig && errno) continue;

        /*
         * FULL_RELRO bypass: make the GOT page writable before patching.
         * If mprotect_rt is 0 (lookup failed), attempt the write anyway —
         * it will fail with EIO if RELRO is active; the error is printed and
         * we skip this symbol rather than crashing.
         */
        int page_was_made_writable = 0;
        if (mprotect_rt) {
            if (make_page_writable(pid, mprotect_rt, got_addr) != 0) {
                printf("[!] %s: mprotect(RW) failed — skipping\n", sym);
                continue;
            }
            page_was_made_writable = 1;
        }

        /* Patch GOT: libwechatnetwork.so's call to sym → hook_addr */
        int poke_ok = (ptrace_poke_u64(pid, got_addr, hook_addr) == 0);

        /* Write original pointer into libhook.so's g_real_* global.
         * libhook.so's own GOT is writable (not RELRO'd by us); if it
         * were, we'd need the same dance for real_glob_addr too.  */
        int real_ok = poke_ok && (ptrace_poke_u64(pid, real_glob_addr, orig) == 0);

        /* Restore page to PROT_READ */
        if (page_was_made_writable) {
            restore_page_perms(pid, mprotect_rt, got_addr);
        }

        if (!poke_ok) {
            printf("[!] %s: GOT patch failed\n", sym);
            continue;
        }
        if (!real_ok) {
            printf("[!] %s: g_real write failed\n", sym);
            continue;
        }

        printf("[+] %s patched: GOT[0x%llx] 0x%llx → 0x%llx  (orig @ 0x%llx)\n",
               sym,
               (unsigned long long)got_addr, (unsigned long long)orig,
               (unsigned long long)hook_addr, (unsigned long long)real_glob_addr);
        patched++;
    }

    ptrace_detach(pid);
    printf("[*] done — %d/%d symbols hooked\n", patched,
           (int)(sizeof(HOOKS)/sizeof(HOOKS[0]) - 1));
    return 0;
}
