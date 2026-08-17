/* dev_uart.h — PL011 UART emulation */
#pragma once
#include <stdint.h>
#include <stdbool.h>

/* PL011 register offsets */
#define UART_DR     0x000   /* Data register */
#define UART_RSR    0x004   /* Receive status / error clear */
#define UART_FR     0x018   /* Flag register */
#define UART_IBRD   0x024   /* Integer baud rate divisor */
#define UART_FBRD   0x028   /* Fractional baud rate divisor */
#define UART_LCR_H  0x02c   /* Line control */
#define UART_CR     0x030   /* Control register */
#define UART_IFLS   0x034   /* Interrupt FIFO level select */
#define UART_IMSC   0x038   /* Interrupt mask set/clear */
#define UART_RIS    0x03c   /* Raw interrupt status */
#define UART_MIS    0x040   /* Masked interrupt status */
#define UART_ICR    0x044   /* Interrupt clear */

/* FR bits */
#define UART_FR_TXFF    (1 << 5)    /* TX FIFO full */
#define UART_FR_RXFE    (1 << 4)    /* RX FIFO empty */
#define UART_FR_BUSY    (1 << 3)    /* UART busy */
#define UART_FR_TXFE    (1 << 7)    /* TX FIFO empty */

/* CR bits */
#define UART_CR_UARTEN  (1 << 0)
#define UART_CR_TXE     (1 << 8)
#define UART_CR_RXE     (1 << 9)

typedef struct PL011 {
    uint32_t cr;
    uint32_t lcr_h;
    uint32_t ibrd;
    uint32_t fbrd;
    uint32_t imsc;
    uint32_t ris;
    uint32_t ifls;

    /* RX FIFO */
    uint8_t  rxbuf[16];
    int      rx_head, rx_tail;

    /* Output: write to fd (stdout by default) */
    int      out_fd;
    int      irq;           /* GIC SPI line */

    /* IRQ callback */
    void    (*raise_irq)(void *gic, int irq, bool level);
    void    *gic;
} PL011;

void    uart_init(PL011 *u, int out_fd, int irq, void *gic,
                  void (*raise_irq)(void*, int, bool));
uint64_t uart_read(void *dev, uint64_t off, int size);
void    uart_write(void *dev, uint64_t off, uint64_t val, int size);
void    uart_rx_push(PL011 *u, uint8_t c);  /* inject a byte into RX FIFO */
