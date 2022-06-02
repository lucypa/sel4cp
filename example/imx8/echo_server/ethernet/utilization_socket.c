/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <string.h>
#include <sel4cp.h>

#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "echo.h"
#include "bench.h"

/* This file implements a TCP based utilization measurment process that starts
 * and stops utilization measurements based on a client's requests.
 * The protocol used to communicate is as follows:
 * - Client connects
 * - Server sends: 100 IPBENCH V1.0\n
 * - Client sends: HELLO\n
 * - Server sends: 200 OK (Ready to go)\n
 * - Client sends: LOAD cpu_target_lukem\n
 * - Server sends: 200 OK\n
 * - Client sends: SETUP args::""\n
 * - Server sends: 200 OK\n
 * - Client sends: START\n
 * - Client sends: STOP\n
 * - Server sends: 220 VALID DATA (Data to follow)\n
 *                                Content-length: %d\n
 *                                ${content}\n
 * - Server closes socket.
 *
 * It is also possible for client to send QUIT\n during operation.
 *
 * The server starts recording utilization stats when it receives START and
 * finishes recording when it receives STOP.
 *
 * Only one client can be connected.
 */

static struct tcp_pcb *utiliz_socket;
uintptr_t data_packet;
uintptr_t cyclecounters_vaddr;

#define WHOAMI "100 IPBENCH V1.0\n"
#define HELLO "HELLO\n"
#define OK_READY "200 OK (Ready to go)\n"
#define LOAD "LOAD cpu_target_lukem\n"
#define OK "200 OK\n"
#define SETUP "SETUP args::\"\"\n"
#define START "START\n"
#define STOP "STOP\n"
#define QUIT "QUIT\n"
#define RESPONSE "220 VALID DATA (Data to follow)\n"    \
    "Content-length: %d\n"                              \
    "%s\n"
#define IDLE_FORMAT ",%ld,%ld"
#define ERROR "400 ERROR\n"

#define msg_match(msg, match) (strncmp(msg, match, strlen(match))==0)

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define RES(x, y, z) "220 VALID DATA (Data to follow)\n"    \
    "Content-length: "STR(x)"\n"\
    ","STR(y)","STR(z)


#define ULONG_MAX 0xffffffff

struct bench *bench = (void *)(uintptr_t)0x5001000;

uint64_t start;
uint64_t idle_ccount_start;
uint64_t idle_overflow_start;


static inline void my_reverse(char s[])
{
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

static inline void my_itoa(uint64_t n, char s[])
{
    int i;
    uint64_t sign;

    if ((sign = n) < 0)  /* record sign */
        n = -n;          /* make n positive */
    i = 0;
    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    my_reverse(s);
}

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

static err_t utilization_sent_callback(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    return ERR_OK;
}

static err_t utilization_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    if (p == NULL) {
        tcp_close(pcb);
        return ERR_OK;
    }

    pbuf_copy_partial(p, data_packet, p->tot_len, 0);
    err_t error;

    if (msg_match(data_packet, HELLO)) {
        error = tcp_write(pcb, OK_READY, strlen(OK_READY), TCP_WRITE_FLAG_COPY);
        if (error) {
            sel4cp_dbg_puts("Failed to send OK_READY message through utilization peer");
        }
    } else if (msg_match(data_packet, LOAD)) {
        error = tcp_write(pcb, OK, strlen(OK), TCP_WRITE_FLAG_COPY);
        if (error) {
            sel4cp_dbg_puts("Failed to send OK message through utilization peer");
        }
    } else if (msg_match(data_packet, SETUP)) {
        error = tcp_write(pcb, OK, strlen(OK), TCP_WRITE_FLAG_COPY);
        if (error) {
            sel4cp_dbg_puts("Failed to send OK message through utilization peer");
        }
    } else if (msg_match(data_packet, START)) {
        sel4cp_dbg_puts("measurement starting... \n");
        start = bench->ts;
        idle_ccount_start = bench->ccount;
        idle_overflow_start = bench->overflows;

    } else if (msg_match(data_packet, STOP)) {
        sel4cp_dbg_puts("measurement finished \n");
        uint64_t total, idle;

        total = bench->ts - start;
        total += ULONG_MAX * (bench->overflows - idle_overflow_start);
        idle = bench->ccount - idle_ccount_start;

        puthex64(total);
        sel4cp_dbg_puts("\n");
        puthex64(idle);
        sel4cp_dbg_puts("\n");

        char tbuf[16];
        my_itoa(total, tbuf);
        sel4cp_dbg_puts(tbuf);
        sel4cp_dbg_puts("\n");

        char ibuf[16];
        my_itoa(idle, ibuf);
        sel4cp_dbg_puts(ibuf);
        sel4cp_dbg_puts("\n");

        char buffer[100];

        int len = strlen(tbuf) + strlen(ibuf) + 2;
        char lbuf[16];
        my_itoa(len, lbuf);
        sel4cp_dbg_puts(lbuf);
        sel4cp_dbg_puts("\n");

        strcat(strcpy(buffer, "220 VALID DATA (Data to follow)\nContent-length: "), lbuf);
        strcat(buffer, "\n,");
        strcat(buffer, ibuf);
        strcat(buffer, ",");
        strcat(buffer, tbuf);

        sel4cp_dbg_puts(buffer);
        error = tcp_write(pcb, buffer, strlen(buffer), TCP_WRITE_FLAG_COPY);

        tcp_shutdown(pcb, 0, 1);
    } else if (msg_match(data_packet, QUIT)) {
        /* Do nothing for now */
    } else {
        sel4cp_dbg_puts("Received a message that we can't handle ");
        sel4cp_dbg_puts(data_packet);
        sel4cp_dbg_puts("\n");
        error = tcp_write(pcb, ERROR, strlen(ERROR), TCP_WRITE_FLAG_COPY);
        if (error) {
            sel4cp_dbg_puts("Failed to send OK message through utilization peer");
        }
    }

    return ERR_OK;
}

static err_t utilization_accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    sel4cp_dbg_puts("Utilization connection established!\n");
    err_t error = tcp_write(newpcb, WHOAMI, strlen(WHOAMI), TCP_WRITE_FLAG_COPY);
    if (error) {
        sel4cp_dbg_puts("Failed to send WHOAMI message through utilization peer");
    }
    tcp_sent(newpcb, utilization_sent_callback);
    tcp_recv(newpcb, utilization_recv_callback);
    return ERR_OK;
}

int setup_utilization_socket(void)
{
    utiliz_socket = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (utiliz_socket == NULL) {
        sel4cp_dbg_puts("Failed to open a socket for listening!");
        return -1;
    }

    err_t error = tcp_bind(utiliz_socket, IP_ANY_TYPE, UTILIZATION_PORT);
    if (error) {
        sel4cp_dbg_puts("Failed to bind the TCP socket");
        return -1;
    } else {
        sel4cp_dbg_puts("Utilisation port bound to port 1236");
    }

    utiliz_socket = tcp_listen_with_backlog_and_err(utiliz_socket, 1, &error);
    if (error != ERR_OK) {
        sel4cp_dbg_puts("Failed to listen on the utilization socket");
        return -1;
    }
    tcp_accept(utiliz_socket, utilization_accept_callback);

    return 0;
}