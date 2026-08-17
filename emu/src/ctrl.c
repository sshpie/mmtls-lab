/* ctrl.c — LLM god-mode control socket implementation
 *
 * Newline-delimited JSON protocol over a Unix domain socket.
 * One client at a time, non-blocking accept.
 *
 * Commands: mem_read, mem_write, reg_read, reg_write, sysreg_read,
 *           sysreg_write, cpu_state, step, run_until, run, pause,
 *           bp_set, bp_clear, bp_list, wp_set, wp_clear, status, halt
 */
#include "ctrl.h"
#include "machine.h"
#include "arm64.h"
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── Minimal JSON helpers ─────────────────────────────────────────────── */

/* Extract string value for "key":"value" → writes into out[outlen], returns 1 on success */
static int json_str(const char *buf, const char *key, char *out, int outlen) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(buf, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return 1;
}

/* Extract uint64 value for "key":N or "key":"0x..." */
static int json_u64(const char *buf, const char *key, uint64_t *out) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(buf, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p == '"') {
        p++;
        *out = strtoull(p, NULL, 0);
        return 1;
    }
    if (*p >= '0' && *p <= '9') {
        *out = strtoull(p, NULL, 0);
        return 1;
    }
    return 0;
}

/* Extract int value for "key":N */
static int json_int(const char *buf, const char *key, int *out) {
    uint64_t v;
    if (!json_u64(buf, key, &v)) return 0;
    *out = (int)v;
    return 1;
}

/* ── Register name → CPU field mapping ──────────────────────────────── */

static int reg_read_by_name(ARM64CPU *c, const char *name, uint64_t *val) {
    if (name[0] == 'x') {
        int n = atoi(name + 1);
        if (n >= 0 && n <= 30) { *val = c->x[n]; return 1; }
    }
    if (!strcmp(name, "sp"))      { *val = cpu_sp(c); return 1; }
    if (!strcmp(name, "sp_el0"))  { *val = c->sp_el0; return 1; }
    if (!strcmp(name, "sp_el1"))  { *val = c->sp_el1; return 1; }
    if (!strcmp(name, "pc"))      { *val = c->pc; return 1; }
    if (!strcmp(name, "pstate"))  { *val = c->pstate; return 1; }
    if (!strcmp(name, "elr_el1")) { *val = c->elr_el1; return 1; }
    if (!strcmp(name, "spsr_el1")){ *val = c->spsr_el1; return 1; }
    if (!strcmp(name, "lr"))      { *val = c->x[30]; return 1; }
    return 0;
}

static int reg_write_by_name(ARM64CPU *c, const char *name, uint64_t val) {
    if (name[0] == 'x') {
        int n = atoi(name + 1);
        if (n >= 0 && n <= 30) { c->x[n] = val; return 1; }
    }
    if (!strcmp(name, "sp"))      { cpu_set_sp(c, val); return 1; }
    if (!strcmp(name, "sp_el0"))  { c->sp_el0 = val; return 1; }
    if (!strcmp(name, "sp_el1"))  { c->sp_el1 = val; return 1; }
    if (!strcmp(name, "pc"))      { c->pc = val; return 1; }
    if (!strcmp(name, "pstate"))  { c->pstate = (uint32_t)val; return 1; }
    if (!strcmp(name, "elr_el1")) { c->elr_el1 = val; return 1; }
    if (!strcmp(name, "spsr_el1")){ c->spsr_el1 = val; return 1; }
    if (!strcmp(name, "lr"))      { c->x[30] = val; return 1; }
    return 0;
}

static int sysreg_read_by_name(ARM64CPU *c, const char *name, uint64_t *val) {
    if (!strcmp(name, "sctlr_el1"))     { *val = c->sctlr_el1; return 1; }
    if (!strcmp(name, "tcr_el1"))       { *val = c->tcr_el1; return 1; }
    if (!strcmp(name, "ttbr0_el1"))     { *val = c->ttbr0_el1; return 1; }
    if (!strcmp(name, "ttbr1_el1"))     { *val = c->ttbr1_el1; return 1; }
    if (!strcmp(name, "mair_el1"))      { *val = c->mair_el1; return 1; }
    if (!strcmp(name, "vbar_el1"))      { *val = c->vbar_el1; return 1; }
    if (!strcmp(name, "esr_el1"))       { *val = c->esr_el1; return 1; }
    if (!strcmp(name, "far_el1"))       { *val = c->far_el1; return 1; }
    if (!strcmp(name, "cpacr_el1"))     { *val = c->cpacr_el1; return 1; }
    if (!strcmp(name, "tpidr_el0"))     { *val = c->tpidr_el0; return 1; }
    if (!strcmp(name, "tpidrro_el0"))   { *val = c->tpidrro_el0; return 1; }
    if (!strcmp(name, "tpidr_el1"))     { *val = c->tpidr_el1; return 1; }
    if (!strcmp(name, "cntkctl_el1"))   { *val = c->cntkctl_el1; return 1; }
    if (!strcmp(name, "cntp_ctl_el0"))  { *val = c->cntp_ctl_el0; return 1; }
    if (!strcmp(name, "cntp_cval_el0")) { *val = c->cntp_cval_el0; return 1; }
    if (!strcmp(name, "mdscr_el1"))     { *val = c->mdscr_el1; return 1; }
    if (!strcmp(name, "hcr_el2"))       { *val = c->hcr_el2; return 1; }
    return 0;
}

static int sysreg_write_by_name(ARM64CPU *c, const char *name, uint64_t val) {
    if (!strcmp(name, "sctlr_el1"))     { c->sctlr_el1 = val; return 1; }
    if (!strcmp(name, "tcr_el1"))       { c->tcr_el1 = val; return 1; }
    if (!strcmp(name, "ttbr0_el1"))     { c->ttbr0_el1 = val; return 1; }
    if (!strcmp(name, "ttbr1_el1"))     { c->ttbr1_el1 = val; return 1; }
    if (!strcmp(name, "mair_el1"))      { c->mair_el1 = val; return 1; }
    if (!strcmp(name, "vbar_el1"))      { c->vbar_el1 = val; return 1; }
    if (!strcmp(name, "cpacr_el1"))     { c->cpacr_el1 = val; return 1; }
    if (!strcmp(name, "tpidr_el0"))     { c->tpidr_el0 = val; return 1; }
    if (!strcmp(name, "tpidrro_el0"))   { c->tpidrro_el0 = val; return 1; }
    if (!strcmp(name, "tpidr_el1"))     { c->tpidr_el1 = val; return 1; }
    if (!strcmp(name, "cntkctl_el1"))   { c->cntkctl_el1 = val; return 1; }
    if (!strcmp(name, "mdscr_el1"))     { c->mdscr_el1 = val; return 1; }
    if (!strcmp(name, "hcr_el2"))       { c->hcr_el2 = val; return 1; }
    return 0;
}

/* ── Command dispatch ──────────────────────────────────────────────────── */

static void send_resp(int fd, const char *resp) {
    size_t len = strlen(resp);
    send(fd, resp, len, MSG_NOSIGNAL);
}

#define RESP_OK     "{\"ok\":true}\n"
#define RESP_ERR(m) ("{\"ok\":false,\"err\":\"" m "\"}\n")

static void handle_cmd(CtrlServer *s, const char *buf, int fd) {
    char cmd[64] = {0};
    if (!json_str(buf, "cmd", cmd, sizeof(cmd))) {
        send_resp(fd, RESP_ERR("no cmd field"));
        return;
    }

    EmuMachine *m = s->machine;
    ARM64CPU   *c = &m->cpu[0];  /* default CPU 0 */
    int cpu_id = 0;
    if (json_int(buf, "cpu", &cpu_id) && cpu_id >= 0 && cpu_id < NUM_CPUS)
        c = &m->cpu[cpu_id];

    char out[8192];

    /* ── mem_read ─────────────────────────────────────────────────── */
    if (!strcmp(cmd, "mem_read")) {
        uint64_t addr = 0; int len = 1;
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        json_int(buf, "len", &len);
        if (len < 1) len = 1;
        if (len > 256) len = 256;

        char hex[513];
        for (int i = 0; i < len; i++) {
            uint8_t b = (uint8_t)mem_read(&m->mem, addr + i, 1);
            snprintf(hex + i*2, 3, "%02x", b);
        }
        snprintf(out, sizeof(out), "{\"ok\":true,\"data\":\"%s\"}\n", hex);
        send_resp(fd, out);
        return;
    }

    /* ── mem_write ────────────────────────────────────────────────── */
    if (!strcmp(cmd, "mem_write")) {
        uint64_t addr = 0;
        char data[513] = {0};
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        if (!json_str(buf, "data", data, sizeof(data))) { send_resp(fd, RESP_ERR("missing data")); return; }
        int n = strlen(data) / 2;
        for (int i = 0; i < n; i++) {
            char byte_str[3] = { data[i*2], data[i*2+1], '\0' };
            uint8_t b = (uint8_t)strtoul(byte_str, NULL, 16);
            mem_write(&m->mem, addr + i, b, 1);
        }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── reg_read ─────────────────────────────────────────────────── */
    if (!strcmp(cmd, "reg_read")) {
        char reg[32] = {0};
        if (!json_str(buf, "reg", reg, sizeof(reg))) { send_resp(fd, RESP_ERR("missing reg")); return; }
        uint64_t val = 0;
        if (!reg_read_by_name(c, reg, &val)) { send_resp(fd, RESP_ERR("unknown reg")); return; }
        snprintf(out, sizeof(out), "{\"ok\":true,\"val\":\"0x%016llx\"}\n", (unsigned long long)val);
        send_resp(fd, out);
        return;
    }

    /* ── reg_write ────────────────────────────────────────────────── */
    if (!strcmp(cmd, "reg_write")) {
        char reg[32] = {0}; uint64_t val = 0;
        if (!json_str(buf, "reg", reg, sizeof(reg))) { send_resp(fd, RESP_ERR("missing reg")); return; }
        if (!json_u64(buf, "val", &val)) { send_resp(fd, RESP_ERR("missing val")); return; }
        if (!reg_write_by_name(c, reg, val)) { send_resp(fd, RESP_ERR("unknown reg")); return; }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── sysreg_read ─────────────────────────────────────────────── */
    if (!strcmp(cmd, "sysreg_read")) {
        char reg[64] = {0};
        if (!json_str(buf, "reg", reg, sizeof(reg))) { send_resp(fd, RESP_ERR("missing reg")); return; }
        uint64_t val = 0;
        if (!sysreg_read_by_name(c, reg, &val)) { send_resp(fd, RESP_ERR("unknown sysreg")); return; }
        snprintf(out, sizeof(out), "{\"ok\":true,\"val\":\"0x%016llx\"}\n", (unsigned long long)val);
        send_resp(fd, out);
        return;
    }

    /* ── sysreg_write ─────────────────────────────────────────────── */
    if (!strcmp(cmd, "sysreg_write")) {
        char reg[64] = {0}; uint64_t val = 0;
        if (!json_str(buf, "reg", reg, sizeof(reg))) { send_resp(fd, RESP_ERR("missing reg")); return; }
        if (!json_u64(buf, "val", &val)) { send_resp(fd, RESP_ERR("missing val")); return; }
        if (!sysreg_write_by_name(c, reg, val)) { send_resp(fd, RESP_ERR("unknown sysreg")); return; }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── cpu_state ────────────────────────────────────────────────── */
    if (!strcmp(cmd, "cpu_state")) {
        int pos = snprintf(out, sizeof(out),
            "{\"ok\":true,\"pc\":\"0x%016llx\",\"pstate\":\"0x%08x\","
            "\"sp\":\"0x%016llx\",\"sp_el0\":\"0x%016llx\",\"sp_el1\":\"0x%016llx\","
            "\"elr_el1\":\"0x%016llx\",\"insns\":%llu,\"x\":[",
            (unsigned long long)c->pc, c->pstate,
            (unsigned long long)cpu_sp(c),
            (unsigned long long)c->sp_el0,
            (unsigned long long)c->sp_el1,
            (unsigned long long)c->elr_el1,
            (unsigned long long)c->insn_count);
        for (int i = 0; i < 31; i++) {
            pos += snprintf(out+pos, sizeof(out)-pos,
                "\"0x%016llx\"%s", (unsigned long long)c->x[i],
                i < 30 ? "," : "");
        }
        snprintf(out+pos, sizeof(out)-pos, "]}\n");
        send_resp(fd, out);
        return;
    }

    /* ── step ─────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "step")) {
        int n = 1;
        json_int(buf, "n", &n);
        if (n < 1) n = 1;
        uint64_t before = c->insn_count;
        c->stopped = false;
        for (int i = 0; i < n && !c->stopped; i++) {
            c->single_step = true;
            cpu_step(c, m);
        }
        c->single_step = false;
        snprintf(out, sizeof(out),
            "{\"ok\":true,\"pc\":\"0x%016llx\",\"insns\":%llu}\n",
            (unsigned long long)c->pc, (unsigned long long)(c->insn_count - before));
        send_resp(fd, out);
        return;
    }

    /* ── run_until ────────────────────────────────────────────────── */
    if (!strcmp(cmd, "run_until")) {
        uint64_t target_pc = 0; int max_insns = 0;
        json_u64(buf, "pc", &target_pc);
        json_int(buf, "max_insns", &max_insns);
        if (max_insns <= 0) max_insns = 10000000;

        const char *reason = "limit";
        uint64_t before = c->insn_count;
        c->stopped = false;
        for (int i = 0; i < max_insns; i++) {
            if (c->pc == target_pc && target_pc != 0) { reason = "pc_match"; break; }
            if (c->halted) { reason = "halt"; break; }
            cpu_step(c, m);
            if (c->stopped) { reason = "breakpoint"; break; }
        }
        snprintf(out, sizeof(out),
            "{\"ok\":true,\"pc\":\"0x%016llx\",\"insns\":%llu,\"reason\":\"%s\"}\n",
            (unsigned long long)c->pc,
            (unsigned long long)(c->insn_count - before),
            reason);
        send_resp(fd, out);
        return;
    }

    /* ── run ──────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "run")) {
        m->running = true;
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── pause ────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "pause")) {
        m->running = false;
        snprintf(out, sizeof(out),
            "{\"ok\":true,\"pc\":\"0x%016llx\"}\n", (unsigned long long)c->pc);
        send_resp(fd, out);
        return;
    }

    /* ── bp_set ───────────────────────────────────────────────────── */
    if (!strcmp(cmd, "bp_set")) {
        uint64_t addr = 0;
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        if (c->bp_count < 64) c->bp[c->bp_count++] = addr;
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── bp_clear ─────────────────────────────────────────────────── */
    if (!strcmp(cmd, "bp_clear")) {
        uint64_t addr = 0;
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        for (int i = 0; i < c->bp_count; i++) {
            if (c->bp[i] == addr) {
                c->bp[i] = c->bp[--c->bp_count];
                break;
            }
        }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── bp_list ──────────────────────────────────────────────────── */
    if (!strcmp(cmd, "bp_list")) {
        int pos = snprintf(out, sizeof(out), "{\"ok\":true,\"bps\":[");
        for (int i = 0; i < c->bp_count; i++) {
            pos += snprintf(out+pos, sizeof(out)-pos,
                "\"0x%016llx\"%s", (unsigned long long)c->bp[i],
                i < c->bp_count-1 ? "," : "");
        }
        snprintf(out+pos, sizeof(out)-pos, "]}\n");
        send_resp(fd, out);
        return;
    }

    /* ── wp_set ───────────────────────────────────────────────────── */
    if (!strcmp(cmd, "wp_set")) {
        uint64_t addr = 0; int len = 1; char type[4] = "w";
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        json_int(buf, "len", &len);
        json_str(buf, "type", type, sizeof(type));
        if (c->wp_count < 16) {
            c->wp[c->wp_count].addr = addr;
            c->wp[c->wp_count].len  = len;
            c->wp[c->wp_count].type = (!strcmp(type,"r") ? 1 :
                                        !strcmp(type,"w") ? 2 : 3);
            c->wp_count++;
        }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── wp_clear ─────────────────────────────────────────────────── */
    if (!strcmp(cmd, "wp_clear")) {
        uint64_t addr = 0;
        if (!json_u64(buf, "addr", &addr)) { send_resp(fd, RESP_ERR("missing addr")); return; }
        for (int i = 0; i < c->wp_count; i++) {
            if (c->wp[i].addr == addr) {
                c->wp[i] = c->wp[--c->wp_count];
                break;
            }
        }
        send_resp(fd, RESP_OK);
        return;
    }

    /* ── status ───────────────────────────────────────────────────── */
    if (!strcmp(cmd, "status")) {
        uint64_t total = 0;
        for (int i = 0; i < NUM_CPUS; i++) total += m->cpu[i].insn_count;
        snprintf(out, sizeof(out),
            "{\"ok\":true,\"running\":%s,\"insns\":%llu,\"cpus\":%d,\"pc\":\"0x%016llx\"}\n",
            m->running ? "true" : "false",
            (unsigned long long)total, NUM_CPUS,
            (unsigned long long)m->cpu[0].pc);
        send_resp(fd, out);
        return;
    }

    /* ── halt ─────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "halt")) {
        m->running = false;
        for (int i = 0; i < NUM_CPUS; i++) m->cpu[i].halted = true;
        send_resp(fd, RESP_OK);
        return;
    }

    send_resp(fd, RESP_ERR("unknown cmd"));
}

/* ── Server lifecycle ──────────────────────────────────────────────────── */

int ctrl_init(CtrlServer *s, struct EmuMachine *m, const char *path) {
    memset(s, 0, sizeof(*s));
    s->machine   = m;
    s->client_fd = -1;
    s->listen_fd = -1;
    s->running   = true;
    if (!path) path = CTRL_SOCK_DEFAULT;
    strncpy(s->sock_path, path, sizeof(s->sock_path)-1);

    unlink(path);

    s->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->listen_fd < 0) { perror("ctrl socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    if (bind(s->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("ctrl bind"); close(s->listen_fd); return -1;
    }
    if (listen(s->listen_fd, 1) < 0) {
        perror("ctrl listen"); close(s->listen_fd); return -1;
    }

    /* Non-blocking */
    int flags = fcntl(s->listen_fd, F_GETFL, 0);
    fcntl(s->listen_fd, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "ctrl: listening on %s\n", path);
    return 0;
}

void ctrl_poll(CtrlServer *s) {
    /* Try to accept a new client if we don't have one */
    if (s->client_fd < 0) {
        int fd = accept(s->listen_fd, NULL, NULL);
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            s->client_fd = fd;
        }
    }
    if (s->client_fd < 0) return;

    /* Read one command line */
    static char buf[4096];
    static int  buf_len = 0;

    ssize_t n = recv(s->client_fd, buf + buf_len, sizeof(buf) - buf_len - 1, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        close(s->client_fd); s->client_fd = -1; buf_len = 0;
        return;
    }
    if (n == 0) {
        close(s->client_fd); s->client_fd = -1; buf_len = 0;
        return;
    }
    buf_len += n;
    buf[buf_len] = '\0';

    /* Process complete lines */
    char *line = buf;
    char *nl;
    while ((nl = memchr(line, '\n', buf + buf_len - line))) {
        *nl = '\0';
        if (nl > line) handle_cmd(s, line, s->client_fd);
        line = nl + 1;
    }
    /* Shift remaining partial line to front */
    int remaining = (int)(buf + buf_len - line);
    if (remaining > 0) memmove(buf, line, remaining);
    buf_len = remaining;
}

void ctrl_close(CtrlServer *s) {
    if (s->client_fd >= 0) { close(s->client_fd); s->client_fd = -1; }
    if (s->listen_fd >= 0) { close(s->listen_fd); s->listen_fd = -1; }
    unlink(s->sock_path);
}
