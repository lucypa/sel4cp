#include <stdint.h>
#include <sel4cp.h>
#include "sel4bench.h"
#include "fence.h"
#include "bench.h"

#define MAGIC_CYCLES 150
#define ULONG_MAX 0xffffffffffffffff

uintptr_t cyclecounters_vaddr;
struct bench *b = (void *)(uintptr_t)0x5001000;

void count_idle(void)
{
    b->prev = sel4bench_get_cycle_count();
    b->ccount = 0;
    b->overflows = 0;

    while (1) {
        b->ts = (uint64_t)sel4bench_get_cycle_count();
        uint64_t diff;

        /* Handle overflow: This thread needs to run at least 2 times
           within any ULONG_MAX cycles period to detect overflows */
        if (b->ts < b->prev) {
            diff = ULONG_MAX - b->prev + b->ts + 1;
            b->overflows++;
        } else {
            diff = b->ts - b->prev;
        }

        if (diff < MAGIC_CYCLES) {
            COMPILER_MEMORY_FENCE();
            b->ccount += diff;
            COMPILER_MEMORY_FENCE();
        }
        b->prev = b->ts;
    }
}

void notified(sel4cp_channel ch) 
{
    sel4cp_dbg_puts("Idle thread notified on unexpected channel\n");
}

void init(void)
{
    sel4bench_init();

    count_idle();
}