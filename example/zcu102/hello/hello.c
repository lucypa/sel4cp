/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <sel4cp.h>

uintptr_t shmem_vaddr;

static void
mycpy(char *dst, char *src, unsigned int length)
{   

    int i = 0;
    while (i < length) {
        dst[i] = src[i];
        i++;
    }
}

void
init(void)
{
    char *shello = "hello";
    sel4cp_dbg_puts("starting...\n");

    mycpy((char*)shmem_vaddr, shello, 5);

    sel4cp_notify(0);
}

void
notified(sel4cp_channel ch)
{
    sel4cp_dbg_puts("notified\n");
    sel4cp_dbg_puts((char *)shmem_vaddr);
    sel4cp_dbg_puts("\n");
}