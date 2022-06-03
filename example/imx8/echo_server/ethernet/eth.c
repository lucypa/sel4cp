/*
 * Copyright 2022, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stdint.h>
#include <sel4cp.h>
#include <sel4/sel4.h>
#include "eth.h"
#include "shared_ringbuffer.h"
#include "util.h"

#define IRQ_CH 1
#define TX_CH  2
#define RX_CH  2
#define INIT   4

#define MDC_FREQ    20000000UL

/* Memory regions. These all have to be here to keep compiler happy */
uintptr_t hw_ring_buffer_vaddr;
uintptr_t hw_ring_buffer_paddr;
uintptr_t shared_dma_vaddr;
uintptr_t shared_dma_paddr;
uintptr_t rx_cookies;
uintptr_t tx_cookies;
uintptr_t rx_avail;
uintptr_t rx_used;
uintptr_t tx_avail;
uintptr_t tx_used;
uintptr_t uart_base;

/* Make the minimum frame buffer 2k. This is a bit of a waste of memory, but ensure alignment */
#define PACKET_BUFFER_SIZE (2 * 1024)
#define MAX_PACKET_SIZE     1536

#define RX_COUNT 128
#define TX_COUNT 128

struct descriptor {
    uint16_t len;
    uint16_t stat;
    uint32_t addr;
};

typedef struct {
    unsigned int cnt;
    unsigned int remain;
    unsigned int tail;
    unsigned int head;
    volatile struct descriptor *descr;
    uintptr_t phys;
    void **cookies;
} ring_ctx_t;

ring_ctx_t rx;
ring_ctx_t tx;
unsigned int tx_lengths[TX_COUNT];

/* Pointers to shared_ringbuffers */
ring_handle_t rx_ring;
ring_handle_t tx_ring;

static uint8_t mac[6];

volatile struct enet_regs *eth = (void *)(uintptr_t)0x2000000;

static void get_mac_addr(volatile struct enet_regs *reg, uint8_t *mac)
{
    uint32_t l, h;
    l = reg->palr;
    h = reg->paur;

    mac[0] = l >> 24;
    mac[1] = l >> 16 & 0xff;
    mac[2] = l >> 8 & 0xff;
    mac[3] = l & 0xff;
    mac[4] = h >> 24;
    mac[5] = h >> 16 & 0xff;
}

static void set_mac(volatile struct enet_regs *reg, uint8_t *mac)
{
    reg->palr = (mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | (mac[3]);
    reg->paur = (mac[4] << 24) | (mac[5] << 16);
}

static void
dump_mac(uint8_t *mac)
{
    for (unsigned i = 0; i < 6; i++) {
        sel4cp_dbg_putc(hexchar((mac[i] >> 4) & 0xf));
        sel4cp_dbg_putc(hexchar(mac[i] & 0xf));
        if (i < 5) {
            sel4cp_dbg_putc(':');
        }
    }
}

static uintptr_t 
getPhysAddr(uintptr_t virtual)
{
    uint64_t offset = virtual - shared_dma_vaddr;
    uintptr_t phys;

    if (offset < 0) {
        sel4cp_dbg_puts("getPhysAddr: offset < 0");
        return 0;
    }

    phys = shared_dma_paddr + offset;
    return phys;
}

static void update_ring_slot(
    ring_ctx_t *ring,
    unsigned int idx,
    uintptr_t phys,
    uint16_t len,
    uint16_t stat)
{
    volatile struct descriptor *d = &(ring->descr[idx]);
    d->addr = phys;
    d->len = len;

    /* Ensure all writes to the descriptor complete, before we set the flags
     * that makes hardware aware of this slot.
     */
    __sync_synchronize();

    d->stat = stat;
}

static uintptr_t 
alloc_rx_buf(size_t buf_size, void **cookie)
{
    uintptr_t addr;
    unsigned int len;

    /* Try to grab a buffer from the available ring */
    if (driver_dequeue(rx_ring.avail_ring, &addr, &len, cookie)) {
        sel4cp_dbg_puts("RX Available ring is empty\n");
        return 0;
    }

    /* Invalidate the memory */
    // Addr is a virtual address.
    seL4_ARM_VSpace_Invalidate_Data(3, addr, addr + buf_size);

    return getPhysAddr(addr);
}

static void fill_rx_bufs()
{
    ring_ctx_t *ring = &rx;
    __sync_synchronize();
    while (ring->remain > 0) {
        /* request a buffer */
        void *cookie = NULL;
        // TODO CHANGE THIS. 
        uintptr_t phys = alloc_rx_buf(MAX_PACKET_SIZE, &cookie);
        if (!phys) {
            break;
        }
        uint16_t stat = RXD_EMPTY;
        int idx = ring->tail;
        int new_tail = idx + 1;
        if (new_tail == ring->cnt) {
            new_tail = 0;
            stat |= WRAP;
        }
        ring->cookies[idx] = cookie;
        update_ring_slot(ring, idx, phys, 0, stat);
        ring->tail = new_tail;
        /* There is a race condition if add/remove is not synchronized. */
        ring->remain--;
    }
    __sync_synchronize();

    if (ring->tail != ring->head) {
        /* Make sure rx is enabled */
        eth->rdar = RDAR_RDAR;
    }
}

static void
handle_rx(volatile struct enet_regs *eth)
{
    ring_ctx_t *ring = &rx;
    unsigned int head = ring->head;

    while (head != ring->tail) {
        volatile struct descriptor *d = &(ring->descr[head]);

        /* If the slot is still marked as empty we are done. */
        if (d->stat & RXD_EMPTY) {
            break;
        }

        void *cookie = ring->cookies[head];
        /* Go to next buffer, handle roll-over. */
        if (++head == ring->cnt) {
            head = 0;
        }
        ring->head = head;

        /* There is a race condition here if add/remove is not synchronized. */
        ring->remain++;

        buff_desc_t *desc = (buff_desc_t *)cookie;

        enqueue_used(&rx_ring, desc->encoded_addr, d->len, desc->cookie);
    }

    /* Notify client */
    sel4cp_notify(RX_CH);
}

static void
complete_tx(volatile struct enet_regs *eth)
{
    unsigned int cnt_org;
    void *cookie;
    ring_ctx_t *ring = &tx;
    unsigned int head = ring->head;
    unsigned int cnt = 0;

    while (head != ring->tail) {
        if (0 == cnt) {
            cnt = tx_lengths[head];
            if ((0 == cnt) || (cnt > TX_COUNT)) {
                /* We are not supposed to read 0 here. */
                sel4cp_dbg_puts("complete_tx with cnt=0 or max");
                return;
            }
            cnt_org = cnt;
            cookie = ring->cookies[head];
        }

        volatile struct descriptor *d = &(ring->descr[head]);

        /* If this buffer was not sent, we can't release any buffer. */
        if (d->stat & TXD_READY) {
            /* give it another chance */
            if (!(eth->tdar & TDAR_TDAR)) {
                eth->tdar = TDAR_TDAR;
            }
            if (d->stat & TXD_READY) {
                return;
            }
        }

        /* Go to next buffer, handle roll-over. */
        if (++head == TX_COUNT) {
            head = 0;
        }

        if (0 == --cnt) {
            ring->head = head;
            /* race condition if add/remove is not synchronized. */
            ring->remain += cnt_org;
            /* give the buffer back */
            buff_desc_t *desc = (buff_desc_t *)cookie;
            enqueue_avail(&tx_ring, desc->encoded_addr, desc->len, desc->cookie);
        }
    }

    /* The only reason to arrive here is when head equals tails. If cnt is not
     * zero, then there is some kind of overflow or data corruption. The number
     * of tx descriptors holding data can't exceed the space in the ring.
     */
    if (0 != cnt) {
        sel4cp_dbg_puts("head reached tail, but cnt!= 0");
    }
}

static void
raw_tx(volatile struct enet_regs *eth, unsigned int num, uintptr_t *phys,
                  unsigned int *len, void *cookie)
{
    ring_ctx_t *ring = &tx;

    /* Ensure we have room */
    if (ring->remain < num) {
        /* not enough room, try to complete some and check again */
        complete_tx(eth);
        unsigned int rem = ring->remain;
        if (rem < num) {
            sel4cp_dbg_puts("TX queue lacks space");
            return;
        }
    }

    __sync_synchronize();

    unsigned int tail = ring->tail;
    unsigned int tail_new = tail;

    unsigned int i = num;
    while (i-- > 0) {
        uint16_t stat = TXD_READY;
        if (0 == i) {
            stat |= TXD_ADDCRC | TXD_LAST;
        }

        unsigned int idx = tail_new;
        if (++tail_new == TX_COUNT) {
            tail_new = 0;
            stat |= WRAP;
        }
        update_ring_slot(ring, idx, *phys++, *len++, stat);
    }

    ring->cookies[tail] = cookie;
    tx_lengths[tail] = num;
    ring->tail = tail_new;
    /* There is a race condition here if add/remove is not synchronized. */
    ring->remain -= num;

    __sync_synchronize();

    if (!(eth->tdar & TDAR_TDAR)) {
        eth->tdar = TDAR_TDAR;
    }

}

static void 
handle_tx(volatile struct enet_regs *eth)
{
    uintptr_t buffer = 0;
    unsigned int len = 0;
    void *cookie = NULL;

    while (!driver_dequeue(tx_ring.used_ring, &buffer, &len, &cookie)) {
        seL4_ARM_VSpace_Clean_Data(3, buffer, buffer + len);
        uintptr_t phys = getPhysAddr(buffer);
        raw_tx(eth, 1, &phys, &len, cookie);
    }
}

static void 
handle_eth(volatile struct enet_regs *eth)
{
    uint32_t e = eth->eir & IRQ_MASK;
    /* write to clear events */
    eth->eir = e;

    while (e & IRQ_MASK) {
        if (e & NETIRQ_TXF) {
            complete_tx(eth);
        }
        if (e & NETIRQ_RXF) {
            handle_rx(eth);
            fill_rx_bufs(eth);
        }
        if (e & NETIRQ_EBERR) {
            sel4cp_dbg_puts("Error: System bus/uDMA");
            while (1);
        }
        e = eth->eir & IRQ_MASK;
        /* write to clear events */
        eth->eir = e;
    }
}

static void 
eth_setup(void)
{
    get_mac_addr(eth, mac);
    sel4cp_dbg_puts("MAC: ");
    dump_mac(mac);
    sel4cp_dbg_puts("\n");

    /* set up descriptor rings */
    rx.cnt = RX_COUNT;
    rx.remain = rx.cnt - 2;
    rx.tail = 0;
    rx.head = 0;
    rx.phys = shared_dma_paddr;
    rx.cookies = (void **)rx_cookies;
    rx.descr = (volatile struct descriptor *)hw_ring_buffer_vaddr;

    tx.cnt = TX_COUNT;
    tx.remain = tx.cnt - 2;
    tx.tail = 0;
    tx.head = 0;
    tx.phys = shared_dma_paddr + (sizeof(struct descriptor) * RX_COUNT);
    tx.cookies = (void **)tx_cookies;
    tx.descr = (volatile struct descriptor *)(hw_ring_buffer_vaddr + (sizeof(struct descriptor) * RX_COUNT));

    /* Perform reset */
    eth->ecr = ECR_RESET;
    while (eth->ecr & ECR_RESET);
    eth->ecr |= ECR_DBSWP;

    /* Clear and mask interrupts */
    eth->eimr = 0x00000000;
    eth->eir  = 0xffffffff;

    /* set MDIO freq */
    eth->mscr = 24 << 1;

    /* Disable */
    eth->mibc |= MIBC_DIS;
    while (!(eth->mibc & MIBC_IDLE));
    /* Clear */
    eth->mibc |= MIBC_CLEAR;
    while (!(eth->mibc & MIBC_IDLE));
    /* Restart */
    eth->mibc &= ~MIBC_CLEAR;
    eth->mibc &= ~MIBC_DIS;

    /* Descriptor group and individual hash tables - Not changed on reset */
    eth->iaur = 0;
    eth->ialr = 0;
    eth->gaur = 0;
    eth->galr = 0;

    if (eth->palr == 0) {
        // the mac address needs setting again. 
        set_mac(eth, mac);
    }

    eth->opd = PAUSE_OPCODE_FIELD;
    eth->tipg = TIPG;
    /* Transmit FIFO Watermark register - store and forward */
    eth->tfwr = 0;
    /* Do not forward frames with errors */
    eth->racc = RACC_LINEDIS;

    /* Set RDSR */
    eth->rdsr = hw_ring_buffer_paddr;
    eth->tdsr = hw_ring_buffer_paddr + (sizeof(struct descriptor) * RX_COUNT);

    /* Size of max eth packet size */
    eth->mrbr = MAX_PACKET_SIZE;

    eth->rcr = RCR_MAX_FL(1518) | RCR_RGMII_EN | RCR_MII_MODE;
    eth->tcr = TCR_FDEN;

    /* set speed */
    eth->ecr |= ECR_SPEED;

    /* Set Enable  in ECR */
    eth->ecr |= ECR_ETHEREN;

    eth->rdar = RDAR_RDAR;

    /* enable events */
    eth->eir = eth->eir;
    eth->eimr = IRQ_MASK;
}

void init_post()
{
    /* Set up shared memory regions */
    ring_init(&rx_ring, (ring_buffer_t *)rx_avail, (ring_buffer_t *)rx_used, NULL, 0);
    ring_init(&tx_ring, (ring_buffer_t *)tx_avail, (ring_buffer_t *)tx_used, NULL, 0);

    fill_rx_bufs();
    sel4cp_dbg_puts(sel4cp_name);
    sel4cp_dbg_puts(": init complete -- waiting for interrupt\n");
    sel4cp_notify(INIT);
}

void init(void)
{
    sel4cp_dbg_puts(sel4cp_name);
    sel4cp_dbg_puts(": elf PD init function running\n");

    eth_setup();

    /* wait for lwip to initialise buffers */
}

seL4_MessageInfo_t
protected(sel4cp_channel ch, sel4cp_msginfo msginfo)
{
    switch (ch) {
        case INIT:
            // get mac
            sel4cp_mr_set(0, eth->palr);
            sel4cp_mr_set(1, eth->paur);
            return sel4cp_msginfo_new(0, 2);
        default:
            sel4cp_dbg_puts("Received ppc on unexpected channel ");
            puthex64(ch);
            break;
    }
    return sel4cp_msginfo_new(0, 0);
}

void notified(sel4cp_channel ch)
{
    //sel4cp_dbg_puts("We got a notification");
    switch(ch) {
        case IRQ_CH:
            handle_eth(eth);
            sel4cp_irq_ack(ch);
            break;
        case TX_CH:
            handle_tx(eth);
            break;
        case INIT:
            init_post();
            break;
        default:
            sel4cp_dbg_puts("eth driver: received notification on unexpected channel\n");
            break;
    }
}