#include <stdint.h>
#include <sel4cp.h>
#include <sel4/sel4.h>
#include "sel4bench.h"
#include "fence.h"
#include "bench.h"
#include "util.h"

#define MAGIC_CYCLES 150
#define ULONG_MAX 0xffffffff

#define START 1
#define STOP 2

uintptr_t uart_base;

uintptr_t cyclecounters_vaddr;
struct bench *b = (void *)(uintptr_t)0x5010000;

ccnt_t counter_values[8];
counter_bitfield_t benchmark_bf;

char *counter_names[] = {
    "L1 i-cache misses",
    "L1 d-cache misses",
    "L1 i-tlb misses",
    "L1 d-tlb misses",
    "Instructions",
    "Branch mispredictions",
};

event_id_t benchmarking_events[] = {
    SEL4BENCH_EVENT_CACHE_L1I_MISS,
    SEL4BENCH_EVENT_CACHE_L1D_MISS,
    SEL4BENCH_EVENT_TLB_L1I_MISS,
    SEL4BENCH_EVENT_TLB_L1D_MISS,
    SEL4BENCH_EVENT_EXECUTE_INSTRUCTION,
    SEL4BENCH_EVENT_BRANCH_MISPREDICT,
};

static int
mycmp(char *a, char *b) {
    int i = 0;
    do {
        if (a[i] != b[i]) {
            return -1;
        }
        i++;
    } while (a[i] != 0);
    return 0;
}


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
    switch(ch) {
        case START:
            sel4bench_reset_counters();
            sel4bench_start_counters(benchmark_bf);
            sel4cp_benchmark_start();
            break;
        case STOP:
            sel4bench_get_counters(benchmark_bf, &counter_values[0]);
            sel4bench_stop_counters(benchmark_bf);
            uint64_t total;
            uint64_t kernel;
            uint64_t entries;
            sel4cp_benchmark_stop(&total, &kernel, &entries);
            /* Dump the counters */
            print("{\n");
            for (int i = 0; i < ARRAY_SIZE(benchmarking_events); i++) {
                print(counter_names[i]);
                print(": ");
                puthex64(counter_values[i]);
                print("\n");
            }
            print("KernelUtilisation");
            print(": ");
            puthex64(kernel);
            print("\n");
            print("KernelEntries");
            print(": ");
            puthex64(entries);
            print("\n");
            print("}\n");
            break;
        default:
            print("Idle thread notified on unexpected channel\n");
    }
}

void init(void)
{
    if (mycmp("benchIdle", sel4cp_name) == 0) {
        sel4bench_init();
        count_idle();
    }

    seL4_Word n_counters = sel4bench_get_num_counters();
    int n_chunks = DIV_ROUND_UP(ARRAY_SIZE(benchmarking_events), n_counters);


    counter_bitfield_t mask = 0;

    for (seL4_Word i = 0; i < n_counters; i++) {
        seL4_Word counter = i;
        if (counter >= ARRAY_SIZE(benchmarking_events)) {
            break;
        }
        sel4bench_set_count_event(i, benchmarking_events[counter]);
        mask |= BIT(i);
    }

    sel4bench_reset_counters();
    sel4bench_start_counters(mask);

    benchmark_bf = mask;
}