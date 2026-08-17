/* ctrl.h — LLM god-mode control socket */
#pragma once
#include <stdbool.h>

#define CTRL_SOCK_DEFAULT "/tmp/emu64-ctrl.sock"

/* Forward declaration */
struct EmuMachine;

typedef struct CtrlServer {
    int    listen_fd;
    int    client_fd;
    char   sock_path[256];
    struct EmuMachine *machine;
    bool   running;
} CtrlServer;

int  ctrl_init(CtrlServer *s, struct EmuMachine *m, const char *path);
void ctrl_poll(CtrlServer *s);
void ctrl_close(CtrlServer *s);
