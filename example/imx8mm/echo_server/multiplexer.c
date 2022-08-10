
#include <stdint.h>
#include <sel4cp.h>
#include <string.h>
#include "shared_ringbuffer.h"
#include "util.h"

#define BUF_SIZE 2048
#define NUM_BUFFERS 512

#define INIT            1
#define DRIVER_RX_CH    2
#define STACK_RX_CH     3
#define STACK_TX_CH     4
#define DRIVER_TX_CH    5
#define INIT_DRIVER     6

/* Memory regions. These all have to be here to keep compiler happy */
uintptr_t driver_rx_avail;
uintptr_t driver_rx_used;
uintptr_t driver_tx_avail;
uintptr_t driver_tx_used;

uintptr_t server_rx_avail;
uintptr_t server_rx_used;
uintptr_t server_tx_avail;
uintptr_t server_tx_used;

uintptr_t shared_dma_vaddr;
uintptr_t shared_dma_vaddr2;
uintptr_t uart_base;

typedef struct state {
    /* Pointers to shared buffers */
    ring_handle_t dev_rx_ring;
    ring_handle_t dev_tx_ring;

    ring_handle_t stack_rx_ring;
    ring_handle_t stack_tx_ring;

} state_t;

state_t state;

void process_rx_complete(void) 
{
    bool was_empty = ring_empty(state.stack_rx_ring.used_ring);

    while(!ring_empty(state.dev_rx_ring.used_ring)) {
        uintptr_t d_addr, s_addr;
        unsigned int d_len, s_len;
        void *cookie;
        void *cookie2;

        dequeue_used(&state.dev_rx_ring, &d_addr, &d_len, &cookie);

        dequeue_avail(&state.stack_rx_ring, &s_addr, &s_len, &cookie2);

        memcpy(s_addr, d_addr, d_len);
        /* Copy data at addr to a new buffer from stack_rx_ring.avail and enqueue it. */
        enqueue_used(&state.stack_rx_ring, s_addr, d_len, cookie2);

        /* enqueue the old buffer back to dev_rx_ring.avail so the driver can use it again. */
        enqueue_avail(&state.dev_rx_ring, d_addr, BUF_SIZE, cookie);
    }

    if (was_empty && !have_signal) {
        have_signal = true;
        msg = seL4_MessageInfo_new(0, 0, 0, 0);
        signal = (BASE_OUTPUT_NOTIFICATION_CAP + STACK_RX_CH);
    } else if (was_empty) {
        sel4cp_notify(STACK_RX_CH);
    }
}

/*void process_rx_free(void)
{
    while(!ring_empty(state.stack_rx_ring.avail_ring)) {
        uintptr_t addr;
        unsigned int len;
        void *buffer;

        dequeue_avail(&state.stack_rx_ring, &addr, &len, &buffer);   
        enqueue_avail(&state.dev_rx_ring, addr, len, buffer);
    }
}*/

void process_tx_ready(void)
{
    bool was_empty = ring_empty(state.dev_tx_ring.used_ring);

    while(!ring_empty(state.stack_tx_ring.used_ring)) {
        uintptr_t d_addr, s_addr;
        unsigned int d_len, s_len;
        void *cookie;
        void *cookie2;

        dequeue_used(&state.stack_tx_ring, &s_addr, &s_len, &cookie);   
        /* Copy data at addr to a new buffer taken from dev_tx_ring.avail */  
        dequeue_avail(&state.dev_tx_ring, &d_addr, &d_len, &cookie2);

        memcpy(d_addr, s_addr, s_len);

        enqueue_used(&state.dev_tx_ring, d_addr, s_len, cookie2);
        /* enqueue the old buffer back to stack_tx_ring.avail so the stack can use it again. */
        enqueue_avail(&state.dev_tx_ring, s_addr, BUF_SIZE, cookie);
    }

    if (was_empty && !have_signal) {
        have_signal = true;
        msg = seL4_MessageInfo_new(0, 0, 0, 0);
        signal = (BASE_OUTPUT_NOTIFICATION_CAP + DRIVER_TX_CH);
    } else if (was_empty) {
        sel4cp_notify(DRIVER_TX_CH);
    }
}

/*void process_tx_complete(void)
{
    while(!ring_empty(state.dev_tx_ring.avail_ring)) {
        uintptr_t addr;
        unsigned int len;
        void *cookie;

        dequeue_avail(&state.dev_tx_ring, &addr, &len, &cookie);
        enqueue_avail(&state.stack_tx_ring, addr, len, cookie);
    }
}*/

void init(void)
{
    print("multi init running\n");
    /* Set up shared memory regions */
    ring_init(&state.dev_rx_ring, (ring_buffer_t *)driver_rx_avail, (ring_buffer_t *)driver_rx_used, NULL, 1);
    ring_init(&state.dev_tx_ring, (ring_buffer_t *)driver_tx_avail, (ring_buffer_t *)driver_tx_used, NULL, 1);

    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        enqueue_avail(&state.dev_rx_ring, shared_dma_vaddr + (BUF_SIZE * i), BUF_SIZE, NULL);
    }

    for (int i = 0; i < NUM_BUFFERS - 1; i++) {
        enqueue_avail(&state.dev_tx_ring, shared_dma_vaddr + (BUF_SIZE * (i + NUM_BUFFERS)), BUF_SIZE, NULL);
    }

    ring_init(&state.stack_rx_ring, (ring_buffer_t *)server_rx_avail, (ring_buffer_t *)server_rx_used, NULL, 0);
    ring_init(&state.stack_tx_ring, (ring_buffer_t *)server_tx_avail, (ring_buffer_t *)server_tx_used, NULL, 0);

    return;
}

void notified(sel4cp_channel ch)
{
    switch(ch) {
        case DRIVER_RX_CH:
            process_rx_complete();
            break;
        case STACK_TX_CH:
            process_tx_ready();
            break;
        case INIT:
            have_signal = true;
            msg = seL4_MessageInfo_new(0, 0, 0, 0);
            signal = (BASE_OUTPUT_NOTIFICATION_CAP + INIT_DRIVER);
            return;
        case INIT_DRIVER:
            print("passing on driver init notification\n");
            have_signal = true;
            msg = seL4_MessageInfo_new(0, 0, 0, 0);
            signal = (BASE_OUTPUT_NOTIFICATION_CAP + INIT);
            return;
        default:
            sel4cp_dbg_puts("multiplexer: received notification on unexpected channel\n");
            puthex64(ch);
            break;
    }
}
