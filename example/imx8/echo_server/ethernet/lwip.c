#include <stdbool.h>
#include <stdint.h>
#include <sel4cp.h>
#include <string.h>

#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/sys.h"

#include "shared_ringbuffer.h"

#define TX_CH  2
#define RX_CH  2

#define LINK_SPEED 1000000000 // Gigabit
#define ETHER_MTU 1500
#define NUM_BUFFERS 128
#define BUF_SIZE 2048

/* Memory regions. These all have to be here to keep compiler happy */
uintptr_t rx_avail;
uintptr_t rx_used;
uintptr_t tx_avail;
uintptr_t tx_used;
uintptr_t shared_dma_vaddr;


typedef enum {
    ORIGIN_RX_QUEUE,
    ORIGIN_TX_QUEUE,
} ethernet_buffer_origin_t;

typedef struct ethernet_buffer {
    /* The acutal underlying memory of the buffer */
    unsigned char *buffer;
    /* The encoded DMA address */
    uintptr_t dma_addr;
    /* The physical size of the buffer */
    size_t size;
    /* Queue from which the buffer was allocated */
    char origin;
    /* Index into buffer_metadata array */
    unsigned int index;
} ethernet_buffer_t;

typedef struct state {
    struct netif netif;
    /* mac address for this client */
    uint8_t mac[6];

    /* Pointers to shared buffers */
    ring_handle_t rx_ring;
    ring_handle_t tx_ring;
    /*
     * Metadata associated with buffers
     */
    ethernet_buffer_t buffer_metadata[NUM_BUFFERS * 2];
} state_t;

state_t state;

static char
hexchar(unsigned int v)
{
    return v < 10 ? '0' + v : ('a' - 10) + v;
}

static void
puthex64(uint64_t x)
{
    char buffer[19];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[2] = hexchar((x >> 60) & 0xf);
    buffer[3] = hexchar((x >> 56) & 0xf);
    buffer[4] = hexchar((x >> 52) & 0xf);
    buffer[5] = hexchar((x >> 48) & 0xf);
    buffer[6] = hexchar((x >> 44) & 0xf);
    buffer[7] = hexchar((x >> 40) & 0xf);
    buffer[8] = hexchar((x >> 36) & 0xf);
    buffer[9] = hexchar((x >> 32) & 0xf);
    buffer[10] = hexchar((x >> 28) & 0xf);
    buffer[11] = hexchar((x >> 24) & 0xf);
    buffer[12] = hexchar((x >> 20) & 0xf);
    buffer[13] = hexchar((x >> 16) & 0xf);
    buffer[14] = hexchar((x >> 12) & 0xf);
    buffer[15] = hexchar((x >> 8) & 0xf);
    buffer[16] = hexchar((x >> 4) & 0xf);
    buffer[17] = hexchar(x & 0xf);
    buffer[18] = 0;
    sel4cp_dbg_puts(buffer);
}

static inline void return_buffer(state_t *state, ethernet_buffer_t *buffer)
{
    /* As the rx_available ring is the size of the number of buffers we have,
    the ring should never be full. */
    enqueue_avail(&(state->rx_ring), buffer->dma_addr, BUF_SIZE, buffer);
}

typedef struct lwip_custom_pbuf {
    struct pbuf_custom custom;
    ethernet_buffer_t *buffer;
    state_t *state;
} lwip_custom_pbuf_t;
LWIP_MEMPOOL_DECLARE(
    RX_POOL,
    NUM_BUFFERS * 2,
    sizeof(lwip_custom_pbuf_t),
    "Zero-copy RX pool"
);

/**
 * Free a pbuf. This also returns the underlying buffer to
 * the appropriate place.
 *
 * @param buf pbuf to free.
 *
 */
static void interface_free_buffer(struct pbuf *buf)
{
    SYS_ARCH_DECL_PROTECT(old_level);

    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) buf;

    SYS_ARCH_PROTECT(old_level);
    return_buffer(custom_pbuf->state, custom_pbuf->buffer);
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
    SYS_ARCH_UNPROTECT(old_level);
}

/**
 * Create a pbuf structure to pass to the network interface.
 *
 * @param state client state data.
 * @param buffer ethernet buffer containing metadata for the actual buffer
 * @param length length of data
 * 
 * @return the newly created pbuf.
 */
static struct pbuf *create_interface_buffer(state_t *state, ethernet_buffer_t *buffer, size_t length)
{
    lwip_custom_pbuf_t *custom_pbuf = (lwip_custom_pbuf_t *) LWIP_MEMPOOL_ALLOC(RX_POOL);

    custom_pbuf->state = state;
    custom_pbuf->buffer = buffer;
    custom_pbuf->custom.custom_free_function = interface_free_buffer;

    return pbuf_alloced_custom(
        PBUF_RAW,
        length,
        PBUF_REF,
        &custom_pbuf->custom,
        buffer->buffer,
        buffer->size
    );
}

static err_t lwip_eth_send(struct netif *netif, struct pbuf *p)
{
    /* Grab an available TX buffer, copy pbuf data over,
    add to used tx ring, notify server */
    err_t ret = ERR_OK;

    sel4cp_dbg_puts("We have packets to send from lwip");

    return ret;
}

void process_rx_queue(void) 
{   
    while(!ring_empty(state.rx_ring.used_ring)) {
        uintptr_t addr;
        unsigned int len;
        ethernet_buffer_t *buffer;

        dequeue_used(&state.rx_ring, &addr, &len, (void **)&buffer);

        sel4cp_dbg_puts("processing packet ");
        puthex64(addr);
        sel4cp_dbg_puts(" of length ");
        puthex64(len);
        sel4cp_dbg_puts("\n");

        struct pbuf *p = create_interface_buffer(&state, buffer, len);

        if (state.netif.input(p, &state.netif) != ERR_OK) {
            // If it is successfully received, the receiver controls whether or not it gets freed.
            sel4cp_dbg_puts("netif.input() != ERR_OK");
            pbuf_free(p);
        }
    }
}

/**
 * Initialise the network interface data structure.
 *
 * @param netif network interface data structuer.
 */
static err_t ethernet_init(struct netif *netif)
{
    if (netif->state == NULL) {
        return ERR_ARG;
    }

    state_t *data = netif->state;

    netif->hwaddr[0] = data->mac[0];
    netif->hwaddr[1] = data->mac[1];
    netif->hwaddr[2] = data->mac[2];
    netif->hwaddr[3] = data->mac[3];
    netif->hwaddr[4] = data->mac[4];
    netif->hwaddr[5] = data->mac[5];
    netif->mtu = ETHER_MTU;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->output = etharp_output;
    netif->linkoutput = lwip_eth_send;
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;

    sel4cp_dbg_puts("netif initialised");
    return ERR_OK;
}

void init(void)
{
    sel4cp_dbg_puts(sel4cp_name);
    sel4cp_dbg_puts(": elf PD init function running\n");

    /* Set up shared memory regions */
    ring_init(&state.rx_ring, (ring_buffer_t *)rx_avail, (ring_buffer_t *)rx_used, NULL, 0);
    ring_init(&state.tx_ring, (ring_buffer_t *)tx_avail, (ring_buffer_t *)tx_used, NULL, 0);

    LWIP_MEMPOOL_INIT(RX_POOL);

    /* Lets just hard code this for now and pass it via PPC later
        TODO
        00:04:9f:05:a6:62
     */
    state.mac[0] = 0x00;
    state.mac[1] = 0x04;
    state.mac[2] = 0x9f;
    state.mac[3] = 0x05;
    state.mac[4] = 0xa6;
    state.mac[5] = 0x62;

    /* Set some dummy IP configuration values to get lwIP bootstrapped  */
    struct ip4_addr netmask, ipaddr, gw, multicast;
    ipaddr_aton("0.0.0.0", &gw);
    ipaddr_aton("0.0.0.0", &ipaddr);
    ipaddr_aton("0.0.0.0", &multicast);
    ipaddr_aton("255.255.255.0", &netmask);

    state.netif.name[0] = 'e';
    state.netif.name[1] = '0';

    if (!netif_add(&(state.netif), &ipaddr, &netmask, &gw, &state,
              ethernet_init, ethernet_input)) {
        sel4cp_dbg_puts("Netif add returned NULL");
    }
    netif_set_default(&(state.netif));


    sel4cp_dbg_puts(sel4cp_name);
    sel4cp_dbg_puts(": init complete -- waiting for notification\n");
}

void notified(sel4cp_channel ch)
{
    sel4cp_dbg_puts("We got a notification");
    switch(ch) {
        case RX_CH:
            sel4cp_dbg_puts("?");
            process_rx_queue();
        default:
            sel4cp_dbg_puts("lwip: received notification on unexpected channel\n");
            break;
    }
}