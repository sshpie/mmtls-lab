/*
 * mmtls_probe.c — gILinkKey discover + hook + dump tool for libwechatnetwork.so
 *
 * Modes:
 *   discover  — break at HKDF_RET, single-step until gILinkKey changes, report writer_pc
 *   hook <pc> — BRK at writer_pc, emit JSON key line on each handshake
 *   dump      — poll gILinkKey until non-zero, emit one JSON snapshot
 *
 * JSON to stdout; diagnostics to stderr.
 * Output feeds directly into ablation/wechat_re.py injector_probe_* methods.
 *
 * Build:
 *   aarch64-linux-gnu-gcc -O2 -static -o mmtls_probe mmtls_probe.c
 *
 * Usage (device, root):
 *   ./mmtls_probe discover              # trigger one handshake after start
 *   ./mmtls_probe hook 0x<writer_pc>    # writer_pc from discover (absolute runtime)
 *   ./mmtls_probe dump                  # one-shot key snapshot
 *
 * Fixed from O'Reilly v3 skeleton:
 *   - removed non-existent <sys/sysconf.h> (sysconf is in <unistd.h>)
 *   - gILinkKey addr = base + 0x3d4648 (full ELF VA, NOT base + bss_vaddr + offset)
 *   - AArch64 BRK does NOT auto-advance PC; hit = regs.pc (not regs.pc - 4)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <elf.h>

/* ── Config ──────────────────────────────────────────────────────────────── */

#define TARGET_PACKAGE   "com.tencent.mm"
#define TARGET_MODULE    "libwechatnetwork.so"

/*
 * HKDF_RET_VA: ELF VA of the instruction immediately after bl 0x1dc424 (HKDF call).
 * Runtime address = load_base + HKDF_RET_VA.
 * Source: Capstone disassembly of libwechatnetwork.so v8.0.56 arm64.
 */
#define HKDF_RET_VA      0x00000000001ce290ULL

/*
 * GILINKKEY_VA: ELF virtual address of gILinkKey (72-byte BSS global).
 * Runtime address = load_base + GILINKKEY_VA.
 * This is the FULL VA in the ELF (not an offset within .bss).
 * Source: static RE of libwechatnetwork.so v8.0.56 arm64.
 */
#define GILINKKEY_VA     0x00000000003d4648ULL
#define KEY_LEN          72
#define STEP_LIMIT       4096

/* BRK #0 encoding (AArch64): 0xD4200000, little-endian in memory */
#define BRK0_INSN        0xD4200000UL

/* ── AArch64 register file ───────────────────────────────────────────────── */

struct user_pt_regs {
    uint64_t regs[31];   /* x0–x30 (x30 = LR) */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

/* ── /proc/<pid>/mem reader ─────────────────────────────────────────────── */

static int read_mem(pid_t pid, uint64_t addr, void *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
        fprintf(stderr, "[-] lseek 0x%lx: %s\n", addr, strerror(errno));
        close(fd); return -1;
    }
    ssize_t r = read(fd, buf, len);
    close(fd);
    if (r != (ssize_t)len) {
        fprintf(stderr, "[-] read_mem 0x%lx len=%zu got=%zd\n", addr, len, r);
        return -1;
    }
    return 0;
}

/* ── ptrace helpers ─────────────────────────────────────────────────────── */

static long peek_word(pid_t pid, uint64_t addr) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    if (v == -1 && errno)
        fprintf(stderr, "[-] PEEKTEXT 0x%lx: %s\n", addr, strerror(errno));
    return v;
}

static int poke_word(pid_t pid, uint64_t addr, long val) {
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)val) == -1) {
        fprintf(stderr, "[-] POKETEXT 0x%lx: %s\n", addr, strerror(errno));
        return -1;
    }
    return 0;
}

static int get_regs(pid_t pid, struct user_pt_regs *out) {
    struct iovec iov = { .iov_base = out, .iov_len = sizeof(*out) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        fprintf(stderr, "[-] GETREGSET: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int set_regs(pid_t pid, const struct user_pt_regs *r) {
    struct iovec iov = { .iov_base = (void *)r, .iov_len = sizeof(*r) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        fprintf(stderr, "[-] SETREGSET: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* ── PID by package name ─────────────────────────────────────────────────── */

static pid_t find_pid(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_type != DT_DIR) continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 0) continue;
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256]; ssize_t r = read(fd, buf, sizeof(buf) - 1); close(fd);
        if (r <= 0) continue;
        buf[r] = '\0';
        if (strstr(buf, pkg)) { closedir(d); return pid; }
    }
    closedir(d);
    return -1;
}

/* ── Module base + path from /proc/<pid>/maps ───────────────────────────── */

static int find_module(pid_t pid, const char *name,
                       uint64_t *base_out, char *path_out, size_t path_sz) {
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps, "r");
    if (!fp) return -1;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end;
        char perms[5] = {0}, p[512] = {0};
        if (sscanf(line, "%lx-%lx %4s %*lx %*s %*d %s", &start, &end, perms, p) < 4)
            continue;
        if (strstr(p, name) && perms[0] == 'r' && perms[2] == 'x') {
            *base_out = start;
            strncpy(path_out, p, path_sz - 1);
            found = 1; break;
        }
    }
    fclose(fp);
    return found ? 0 : -1;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

static long long now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* Plant BRK #0 at addr; return original word */
static long arm_brk(pid_t pid, uint64_t addr) {
    errno = 0;
    long orig = peek_word(pid, addr);
    if (errno) return 0;
    long patched = (orig & ~(long)0xffffffffL) | (long)BRK0_INSN;
    if (poke_word(pid, addr, patched) != 0) return 0;
    return orig;
}

/* ── discover mode ───────────────────────────────────────────────────────── */

static int mode_discover(void) {
    pid_t pid = find_pid(TARGET_PACKAGE);
    if (pid <= 0) {
        fprintf(stderr, "[-] discover: %s not found\n", TARGET_PACKAGE); return 1;
    }

    uint64_t base; char path[512];
    if (find_module(pid, TARGET_MODULE, &base, path, sizeof(path)) != 0) {
        fprintf(stderr, "[-] discover: %s not in maps\n", TARGET_MODULE); return 1;
    }

    /*
     * GILINKKEY_VA is the full ELF virtual address (link-time base = 0).
     * Runtime addr = load_base + VA.  No additional .bss-vaddr offset needed.
     */
    uint64_t key_addr  = base + GILINKKEY_VA;
    uint64_t hkdf_addr = base + HKDF_RET_VA;

    fprintf(stderr, "[+] discover: pid=%d base=0x%lx key=0x%lx hkdf_ret=0x%lx\n",
            pid, base, key_addr, hkdf_addr);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "[-] discover: ATTACH: %s\n", strerror(errno)); return 1;
    }
    int status; waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] discover: not stopped after attach\n"); return 1;
    }

    long orig = arm_brk(pid, hkdf_addr);
    if (!orig && errno) goto out;

    fprintf(stderr, "[+] discover: BRK at HKDF_RET planted — trigger one handshake\n");

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        fprintf(stderr, "[-] PTRACE_CONT: %s\n", strerror(errno)); goto restore;
    }
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[-] discover: did not hit HKDF_RET breakpoint\n"); goto restore;
    }

    struct user_pt_regs regs;
    if (get_regs(pid, &regs) != 0) goto restore;

    uint8_t g_before[KEY_LEN] = {0}, g_after[KEY_LEN] = {0};
    if (read_mem(pid, key_addr, g_before, KEY_LEN) != 0) goto restore;

    /* Restore original instruction and re-run from HKDF_RET */
    if (poke_word(pid, hkdf_addr, orig) != 0) goto out;
    regs.pc = hkdf_addr;
    if (set_regs(pid, &regs) != 0) goto out;

    int steps = 0;
    uint64_t writer_pc = 0;

    while (steps < STEP_LIMIT) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) break;
        if (get_regs(pid, &regs) != 0) break;
        steps++;

        if (read_mem(pid, key_addr, g_after, KEY_LEN) != 0) break;
        if (memcmp(g_before, g_after, KEY_LEN) != 0) {
            /*
             * regs.pc is now the NEXT instruction after the one that wrote gILinkKey.
             * Use this as writer_pc for hook mode — the BRK fires after the write,
             * so we always read the freshly-written key.
             */
            writer_pc = regs.pc;
            fprintf(stderr, "[+] discover: gILinkKey changed at step=%d writer_pc=0x%lx\n",
                    steps, writer_pc);
            break;
        }
    }

    if (writer_pc) {
        printf("{\"mode\":\"discover\",\"pid\":%d,\"writer_pc\":\"0x%lx\","
               "\"key\":\"", pid, writer_pc);
        print_hex(g_after, KEY_LEN);
        printf("\",\"steps\":%d}\n", steps);
        fflush(stdout);
    } else {
        fprintf(stderr, "[-] discover: no gILinkKey change within %d steps\n", STEP_LIMIT);
    }
    goto out;

restore:
    poke_word(pid, hkdf_addr, orig);
out:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return writer_pc ? 0 : 1;
}

/* ── hook mode ───────────────────────────────────────────────────────────── */

static int mode_hook(uint64_t writer_pc) {
    pid_t pid = find_pid(TARGET_PACKAGE);
    if (pid <= 0) {
        fprintf(stderr, "[-] hook: %s not found\n", TARGET_PACKAGE); return 1;
    }

    uint64_t base; char path[512];
    if (find_module(pid, TARGET_MODULE, &base, path, sizeof(path)) != 0) {
        fprintf(stderr, "[-] hook: %s not in maps\n", TARGET_MODULE); return 1;
    }

    uint64_t key_addr = base + GILINKKEY_VA;
    fprintf(stderr, "[+] hook: pid=%d base=0x%lx key=0x%lx writer_pc=0x%lx\n",
            pid, base, key_addr, writer_pc);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "[-] hook: ATTACH: %s\n", strerror(errno)); return 1;
    }
    int status; waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] hook: not stopped\n"); return 1;
    }

    long orig = arm_brk(pid, writer_pc);
    if (!orig && errno) goto out;
    fprintf(stderr, "[+] hook: BRK at writer_pc — logging key JSON lines\n");

    unsigned long long id = 0;
    while (1) {
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status)) break;
        if (WSTOPSIG(status) != SIGTRAP) continue;

        struct user_pt_regs regs;
        if (get_regs(pid, &regs) != 0) break;

        /*
         * AArch64 BRK does NOT auto-advance PC (unlike x86 INT3).
         * regs.pc == address of the BRK instruction == writer_pc.
         */
        if (regs.pc != writer_pc) continue;   /* stray SIGTRAP */

        uint8_t key[KEY_LEN];
        if (read_mem(pid, key_addr, key, KEY_LEN) == 0) {
            long long t = now_ms();
            printf("{\"mode\":\"hook\",\"id\":%llu,\"pid\":%d,\"ts_ms\":%lld,"
                   "\"pc\":\"0x%lx\",\"key\":\"", id++, pid, t, regs.pc);
            print_hex(key, KEY_LEN);
            printf("\"}\n");
            fflush(stdout);
        }

        /* restore, re-execute original instruction, re-arm BRK */
        if (poke_word(pid, writer_pc, orig) != 0) break;
        regs.pc = writer_pc;
        if (set_regs(pid, &regs) != 0) break;
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status)) break;
        if (poke_word(pid, writer_pc, (orig & ~(long)0xffffffffL) | (long)BRK0_INSN) != 0)
            break;
    }

    poke_word(pid, writer_pc, orig);
out:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

/* ── dump mode (poll until non-zero, one-shot) ───────────────────────────── */

static int mode_dump(void) {
    pid_t pid = find_pid(TARGET_PACKAGE);
    if (pid <= 0) {
        fprintf(stderr, "[-] dump: %s not found\n", TARGET_PACKAGE); return 1;
    }

    uint64_t base; char path[512];
    if (find_module(pid, TARGET_MODULE, &base, path, sizeof(path)) != 0) {
        fprintf(stderr, "[-] dump: %s not in maps\n", TARGET_MODULE); return 1;
    }

    uint64_t key_addr = base + GILINKKEY_VA;
    fprintf(stderr, "[+] dump: pid=%d base=0x%lx key=0x%lx\n", pid, base, key_addr);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "[-] dump: ATTACH: %s\n", strerror(errno)); return 1;
    }
    int status; waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[-] dump: not stopped\n"); return 1;
    }

    uint8_t last[KEY_LEN] = {0}, cur[KEY_LEN] = {0};
    static const uint8_t zeroes[KEY_LEN] = {0};
    int iters = 0;

    while (iters++ < 200) {
        if (read_mem(pid, key_addr, cur, KEY_LEN) != 0) break;
        if (memcmp(cur, zeroes, KEY_LEN) != 0 &&
            memcmp(cur, last, KEY_LEN) != 0) {
            memcpy(last, cur, KEY_LEN);
            /* verify stability: re-read after 200ms */
            usleep(200000);
            uint8_t chk[KEY_LEN];
            if (read_mem(pid, key_addr, chk, KEY_LEN) == 0 &&
                memcmp(chk, cur, KEY_LEN) == 0) {
                long long t = now_ms();
                printf("{\"mode\":\"dump\",\"pid\":%d,\"ts_ms\":%lld,\"key\":\"",
                       pid, t);
                print_hex(cur, KEY_LEN);
                printf("\"}\n");
                fflush(stdout);
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
                return 0;
            }
        }
        usleep(100000);
    }

    fprintf(stderr, "[-] dump: timeout waiting for non-zero gILinkKey\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  %s discover\n"
                "  %s hook <writer_pc_hex>\n"
                "  %s dump\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "discover") == 0) {
        return mode_discover();
    } else if (strcmp(argv[1], "hook") == 0) {
        if (argc < 3) { fprintf(stderr, "hook requires writer_pc_hex\n"); return 1; }
        uint64_t pc = strtoull(argv[2], NULL, 16);
        if (!pc) { fprintf(stderr, "invalid writer_pc_hex\n"); return 1; }
        return mode_hook(pc);
    } else if (strcmp(argv[1], "dump") == 0) {
        return mode_dump();
    }

    fprintf(stderr, "unknown mode '%s'\n", argv[1]);
    return 1;
}
