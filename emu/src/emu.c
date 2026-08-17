/* emu.c — arm64emu entry point
 *
 * Usage:
 *   emu64 -kernel <image.gz> -initrd <ramdisk.img> \
 *         -cmdline "console=ttyAMA0 ..." \
 *         -disk <disk.img>[,ro] [-disk <disk2.img>] ...
 *         [-mem 2048]         # RAM in MB, default 2048
 *         [-ctrl /tmp/emu64.sock]
 */
#include "machine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static EmuMachine g_machine;

static void sigint_handler(int sig)
{
    (void)sig;
    g_machine.exit_request = true;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -kernel <image> [-initrd <img>] [-cmdline <str>]\n"
        "          [-disk <img>[,ro]] [-mem <MB>]\n"
        "          [-ctrl <sock_path>]\n"
        "\n"
        "LLM control socket (default /tmp/emu64-ctrl.sock):\n"
        "  Send JSON commands over Unix socket for god-mode control.\n"
        "  Commands: mem_read, mem_write, reg_read, reg_write,\n"
        "            sysreg_read, sysreg_write, cpu_state,\n"
        "            step, run_until, run, pause,\n"
        "            bp_set, bp_clear, bp_list,\n"
        "            wp_set, wp_clear, status, halt\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *kernel   = NULL;
    const char *initrd   = NULL;
    const char *cmdline  = NULL;
    const char *ctrl_sock = "/tmp/emu64-ctrl.sock";
    uint64_t    ram_mb   = 2048;
    uint64_t    max_insns = 0;

    const char *disk_paths[MAX_VIRTIO_DEVS];
    bool        disk_ro[MAX_VIRTIO_DEVS];
    int         num_disks = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-kernel") && i+1 < argc) {
            kernel = argv[++i];
        } else if (!strcmp(argv[i], "-initrd") && i+1 < argc) {
            initrd = argv[++i];
        } else if (!strcmp(argv[i], "-cmdline") && i+1 < argc) {
            cmdline = argv[++i];
        } else if (!strcmp(argv[i], "-ctrl") && i+1 < argc) {
            ctrl_sock = argv[++i];
        } else if (!strcmp(argv[i], "-mem") && i+1 < argc) {
            ram_mb = strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "-max-insns") && i+1 < argc) {
            max_insns = strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "-disk") && i+1 < argc) {
            if (num_disks >= MAX_VIRTIO_DEVS) {
                fprintf(stderr, "Too many disks (max %d)\n", MAX_VIRTIO_DEVS);
                return 1;
            }
            char *spec = argv[++i];
            char *comma = strrchr(spec, ',');
            if (comma && !strcmp(comma+1, "ro")) {
                *comma = '\0';
                disk_ro[num_disks] = true;
            } else {
                disk_ro[num_disks] = false;
            }
            disk_paths[num_disks++] = spec;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!kernel) {
        fprintf(stderr, "[-] -kernel required\n");
        usage(argv[0]);
        return 1;
    }

    fprintf(stderr,
            "arm64emu — from-scratch ARM64 system emulator\n"
            "  kernel : %s\n"
            "  initrd : %s\n"
            "  RAM    : %llu MB\n"
            "  CPUs   : %d\n"
            "  ctrl   : %s\n"
            "  disks  : %d\n",
            kernel, initrd ? initrd : "(none)",
            (unsigned long long)ram_mb, NUM_CPUS,
            ctrl_sock, num_disks);

    signal(SIGINT, sigint_handler);

    uint64_t ram_size = ram_mb * 1024ULL * 1024;
    int rc = machine_init(&g_machine, ram_size,
                          kernel, initrd, cmdline, ctrl_sock,
                          disk_paths, disk_ro, num_disks);
    if (rc < 0) {
        fprintf(stderr, "[-] machine_init failed\n");
        return 1;
    }

    g_machine.max_insns = max_insns;
    machine_run(&g_machine);
    return 0;
}
