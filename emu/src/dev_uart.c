/* dev_uart.c — PL011 UART emulation */
#include "dev_uart.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void uart_init(PL011 *u, int out_fd, int irq, void *gic,
               void (*raise_irq)(void*, int, bool))
{
    memset(u, 0, sizeof(*u));
    u->out_fd    = out_fd;
    u->irq       = irq;
    u->gic       = gic;
    u->raise_irq = raise_irq;
    u->cr        = UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;
    u->ifls      = 0x12;  /* half-full */
}

static void uart_update_irq(PL011 *u)
{
    bool level = !!(u->ris & u->imsc);
    if (u->raise_irq && u->gic)
        u->raise_irq(u->gic, u->irq, level);
}

uint64_t uart_read(void *dev, uint64_t off, int size)
{
    PL011 *u = dev;
    (void)size;
    switch (off) {
    case UART_DR: {
        if (u->rx_head == u->rx_tail)
            return 0;
        uint8_t c = u->rxbuf[u->rx_head++ % 16];
        uart_update_irq(u);
        return c;
    }
    case UART_FR: {
        uint32_t fr = UART_FR_TXFE;  /* TX always empty (instant) */
        if (u->rx_head == u->rx_tail)
            fr |= UART_FR_RXFE;
        return fr;
    }
    case UART_CR:    return u->cr;
    case UART_LCR_H: return u->lcr_h;
    case UART_IBRD:  return u->ibrd;
    case UART_FBRD:  return u->fbrd;
    case UART_IMSC:  return u->imsc;
    case UART_RIS:   return u->ris;
    case UART_MIS:   return u->ris & u->imsc;
    case UART_IFLS:  return u->ifls;
    default:
        /* PL011 peripheral ID bytes at 0xFE0-0xFFC */
        if (off >= 0xfe0 && off <= 0xffc) {
            static const uint8_t pid[] = {0x11,0x10,0x14,0x00,
                                           0x0d,0xf0,0x05,0xb1};
            return pid[(off - 0xfe0) / 4];
        }
        return 0;
    }
}

void uart_write(void *dev, uint64_t off, uint64_t val, int size)
{
    PL011 *u = dev;
    (void)size;
    switch (off) {
    case UART_DR: {
        uint8_t c = val & 0xff;
        write(u->out_fd, &c, 1);
        /* Debug: log first 200 chars so we can confirm UART is being hit */
        static uint64_t uart_write_count = 0;
        uart_write_count++;
        if (uart_write_count <= 200)
            fprintf(stderr, "[UART_DR#%llu] char=0x%02x '%c'\n",
                    (unsigned long long)uart_write_count,
                    (unsigned)c, (c >= 0x20 && c < 0x7f) ? (char)c : '.');
        break;
    }
    case UART_CR:    u->cr    = val; break;
    case UART_LCR_H: u->lcr_h = val; break;
    case UART_IBRD:  u->ibrd  = val; break;
    case UART_FBRD:  u->fbrd  = val; break;
    case UART_IFLS:  u->ifls  = val; break;
    case UART_IMSC:
        u->imsc = val;
        uart_update_irq(u);
        break;
    case UART_ICR:
        u->ris &= ~val;
        uart_update_irq(u);
        break;
    default: break;
    }
}

void uart_rx_push(PL011 *u, uint8_t c)
{
    int next = (u->rx_tail + 1) % 16;
    if (next == u->rx_head)
        return;  /* drop if full */
    u->rxbuf[u->rx_tail] = c;
    u->rx_tail = next;
    u->ris |= (1 << 4);  /* RXRIS */
    uart_update_irq(u);
}
