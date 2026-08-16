/*
 * mmtls_hide.so — LD_PRELOAD evasion shim for Android ARM64
 *
 * Injected into WeChat via:
 *   adb shell setprop wrap.com.tencent.mm "LD_PRELOAD=/data/local/tmp/mmtls_hide.so"
 *
 * Intercepts open/stat/access/fopen at libc level to:
 *   1. Return ENOENT for emulator device node paths
 *   2. Patch /proc/cpuinfo to replace QEMU/Goldfish strings with real device strings
 *
 * We already delete /dev/qemu_pipe etc. in launch.sh; this is the defence-in-depth
 * layer for any paths the delete missed and for /proc/cpuinfo content checks.
 *
 * Build: aarch64-linux-android34-clang -shared -fPIC -o mmtls_hide.so mmtls_hide.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── Paths that reveal emulator identity ────────────────────────────────── */

static const char *BLOCKED[] = {
    "/dev/qemu_pipe",
    "/dev/socket/qemud",
    "/dev/qemu_trace",
    "/sys/qemu_trace",
    "/dev/goldfish_pipe",
    NULL,
};

static int blocked(const char *path) {
    if (!path) return 0;
    for (int i = 0; BLOCKED[i]; i++)
        if (strcmp(path, BLOCKED[i]) == 0) return 1;
    return 0;
}

/* ── Library names to hide from /proc/self/maps ─────────────────────────── */

static const char *MAPS_HIDE[] = {
    "mmtls_hide",
    NULL,
};

static int maps_line_hidden(const char *line) {
    for (int i = 0; MAPS_HIDE[i]; i++)
        if (strstr(line, MAPS_HIDE[i])) return 1;
    return 0;
}

/* Build a filtered /proc/self/maps that omits our shim's entries.
 * DBI detection: WeChat reads its own maps looking for unexpected .so files. */
static FILE *fake_maps(void) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *real = real_fopen("/proc/self/maps", "r");
    if (!real) return NULL;

    FILE *tmp = tmpfile();
    if (!tmp) { fclose(real); return NULL; }

    char line[512];
    while (fgets(line, sizeof(line), real)) {
        if (!maps_line_hidden(line))
            fputs(line, tmp);
    }
    fclose(real);
    rewind(tmp);
    return tmp;
}

/* Patch /proc/self/status: zero out TracerPid so ptrace-detection
 * (which would show our gdbserver/debugger if attached) reports clean. */
static FILE *fake_status(void) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *real = real_fopen("/proc/self/status", "r");
    if (!real) return NULL;

    FILE *tmp = tmpfile();
    if (!tmp) { fclose(real); return NULL; }

    char line[512];
    while (fgets(line, sizeof(line), real)) {
        if (strncmp(line, "TracerPid:", 10) == 0)
            fputs("TracerPid:\t0\n", tmp);
        else
            fputs(line, tmp);
    }
    fclose(real);
    rewind(tmp);
    return tmp;
}

/* ── /proc/cpuinfo content patches ─────────────────────────────────────── */

typedef struct { const char *from; const char *to; } Patch;

static const Patch CPUINFO_PATCHES[] = {
    /* QEMU virtual CPU model strings → Snapdragon Kryo 585 (Pixel 4 / SM8150) */
    { "Goldfish Arm",        "Kryo 585"                 },
    { "QEMU",                "Kryo 585"                 },
    { "Virtual CPU",         "ARMv8 Processor rev 0"    },
    { "Hardware\t: Goldfish", "Hardware\t: qcom"         },
    { "Hardware\t: ranchu",  "Hardware\t: qcom"          },
    { NULL, NULL },
};

/* Apply all patches to buf in-place (safe only if replacements are same length
 * or shorter, which all ours are).  Returns new length. */
static size_t patch_cpuinfo(char *buf, size_t len) {
    for (int i = 0; CPUINFO_PATCHES[i].from; i++) {
        const char *f = CPUINFO_PATCHES[i].from;
        const char *t = CPUINFO_PATCHES[i].to;
        size_t flen = strlen(f), tlen = strlen(t);
        char *p = buf;
        while ((p = memmem(p, len - (p - buf), f, flen)) != NULL) {
            /* tlen <= flen always for our table; pad remainder with spaces */
            memcpy(p, t, tlen);
            if (tlen < flen)
                memset(p + tlen, ' ', flen - tlen);
            p += flen;
        }
    }
    return len;
}

/* Build a fake FILE* for /proc/cpuinfo with strings replaced.
 * Uses an anonymous tmpfile so the caller gets a real seekable FILE. */
static FILE *fake_cpuinfo(void) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *real = real_fopen("/proc/cpuinfo", "r");
    if (!real) return NULL;

    /* Read full content */
    fseek(real, 0, SEEK_END);
    long sz = ftell(real);
    rewind(real);
    if (sz <= 0) { fclose(real); return NULL; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(real); return NULL; }
    size_t got = fread(buf, 1, sz, real);
    fclose(real);
    buf[got] = '\0';

    patch_cpuinfo(buf, got);

    /* Write into an anonymous temp file and rewind for the caller */
    FILE *tmp = tmpfile();
    if (!tmp) { free(buf); return NULL; }
    fwrite(buf, 1, got, tmp);
    free(buf);
    rewind(tmp);
    return tmp;
}

/* ── Interceptors ───────────────────────────────────────────────────────── */

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open");
    if (blocked(path)) { errno = ENOENT; return -1; }
    va_list ap; va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real(path, flags, mode);
}

int open64(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open64");
    if (blocked(path)) { errno = ENOENT; return -1; }
    va_list ap; va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "openat");
    if (blocked(path)) { errno = ENOENT; return -1; }
    va_list ap; va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real(dirfd, path, flags, mode);
}

int stat(const char *path, struct stat *buf) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "stat");
    if (blocked(path)) { errno = ENOENT; return -1; }
    return real(path, buf);
}

int lstat(const char *path, struct stat *buf) {
    static int (*real)(const char *, struct stat *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "lstat");
    if (blocked(path)) { errno = ENOENT; return -1; }
    return real(path, buf);
}

int access(const char *path, int mode) {
    static int (*real)(const char *, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "access");
    if (blocked(path)) { errno = ENOENT; return -1; }
    return real(path, mode);
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*real)(const char *, const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "fopen");
    if (blocked(path)) { errno = ENOENT; return NULL; }
    if (strcmp(path, "/proc/cpuinfo") == 0)   return fake_cpuinfo();
    if (strcmp(path, "/proc/self/maps") == 0)  return fake_maps();
    if (strcmp(path, "/proc/self/status") == 0) return fake_status();
    return real(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    static FILE *(*real)(const char *, const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "fopen64");
    if (blocked(path)) { errno = ENOENT; return NULL; }
    if (strcmp(path, "/proc/cpuinfo") == 0)   return fake_cpuinfo();
    if (strcmp(path, "/proc/self/maps") == 0)  return fake_maps();
    if (strcmp(path, "/proc/self/status") == 0) return fake_status();
    return real(path, mode);
}
