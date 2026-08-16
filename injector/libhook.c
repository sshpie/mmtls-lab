/*
 * libhook.so — MMTLS runtime hook library for WeChat libwechatnetwork.so
 *
 * Injected via wrap.com.tencent.mm LD_PRELOAD so it lands in WeChat's address space.
 * mmtls_inject then patches libwechatnetwork.so's GOT entries for target symbols to
 * point into this library.  Namespace isolation is bypassed because the GOT patch
 * happens at the address level — the CPU has no concept of linker namespaces.
 *
 * Hooks provided:
 *   connect   — logs destination IP:port
 *   send      — hexdump first 512B of every send (MMTLS records going out)
 *   recv      — hexdump first 512B of every recv (MMTLS records coming in)
 *   sendto    — redirects to send hook
 *   recvfrom  — redirects to recv hook
 *
 * Log tag "mmhook" → readable via:  adb logcat -s mmhook
 *
 * Build: see build.sh
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef ANDROID_LOG_STUB
#include <stdio.h>
/* Stub for non-NDK cross-compilation — redirect to stderr */
#define ANDROID_LOG_DEBUG 3
#define ANDROID_LOG_INFO  4
static void __android_log_print(int prio, const char *tag,
                                 const char *fmt, ...) {
    (void)prio;
    va_list ap;
    fprintf(stderr, "[%s] ", tag);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}
#else
#include <android/log.h>
#endif

#define TAG     "mmhook"
#define HEXMAX  512   /* bytes to hexdump per call */

/* ── Per-symbol original-pointer globals ───────────────────────────────────
 * mmtls_inject writes these after patching the GOT.
 * Declared volatile so the compiler doesn't cache NULL across the patch window.
 */
volatile uint64_t g_real_connect  = 0;
volatile uint64_t g_real_send     = 0;
volatile uint64_t g_real_recv     = 0;
volatile uint64_t g_real_sendto   = 0;
volatile uint64_t g_real_recvfrom = 0;

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void hexlog(const char *label, int fd, const void *buf, ssize_t len) {
    if (len <= 0) return;
    ssize_t n = len > HEXMAX ? HEXMAX : len;
    /* 3 chars per byte ("xx ") + NUL */
    char hex[HEXMAX * 3 + 4];
    char *p = hex;
    const unsigned char *b = (const unsigned char *)buf;
    for (ssize_t i = 0; i < n; i++) {
        static const char hc[] = "0123456789abcdef";
        *p++ = hc[b[i] >> 4];
        *p++ = hc[b[i] & 0xf];
        *p++ = ' ';
    }
    *p = '\0';
    __android_log_print(ANDROID_LOG_DEBUG, TAG,
        "%s fd=%d len=%zd%s hex=%s",
        label, fd, len, len > HEXMAX ? "(truncated)" : "", hex);
}

static void log_sockaddr(const char *label, const struct sockaddr *sa) {
    if (!sa) return;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        __android_log_print(ANDROID_LOG_DEBUG, TAG,
            "%s dst=%s:%d", label, ip, ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        __android_log_print(ANDROID_LOG_DEBUG, TAG,
            "%s dst=[%s]:%d", label, ip, ntohs(sin6->sin6_port));
    }
}

/* ── Hook implementations ───────────────────────────────────────────────── */

int hook_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    log_sockaddr("CONNECT", addr);
    typedef int (*fn_t)(int, const struct sockaddr *, socklen_t);
    fn_t real = (fn_t)(uintptr_t)g_real_connect;
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, addr, addrlen);
}

ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    hexlog("SEND", fd, buf, (ssize_t)len);
    typedef ssize_t (*fn_t)(int, const void *, size_t, int);
    fn_t real = (fn_t)(uintptr_t)g_real_send;
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, buf, len, flags);
}

ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    typedef ssize_t (*fn_t)(int, void *, size_t, int);
    fn_t real = (fn_t)(uintptr_t)g_real_recv;
    if (!real) { errno = ENOSYS; return -1; }
    ssize_t r = real(fd, buf, len, flags);
    hexlog("RECV", fd, buf, r);
    return r;
}

ssize_t hook_sendto(int fd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen) {
    log_sockaddr("SENDTO", dest_addr);
    hexlog("SEND", fd, buf, (ssize_t)len);
    typedef ssize_t (*fn_t)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);
    fn_t real = (fn_t)(uintptr_t)g_real_sendto;
    if (!real) { errno = ENOSYS; return -1; }
    return real(fd, buf, len, flags, dest_addr, addrlen);
}

ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen) {
    typedef ssize_t (*fn_t)(int, void *, size_t, int,
                             struct sockaddr *, socklen_t *);
    fn_t real = (fn_t)(uintptr_t)g_real_recvfrom;
    if (!real) { errno = ENOSYS; return -1; }
    ssize_t r = real(fd, buf, len, flags, src_addr, addrlen);
    hexlog("RECV", fd, buf, r);
    return r;
}

__attribute__((constructor))
static void libhook_init(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "libhook.so loaded — waiting for GOT patches from mmtls_inject");
}
