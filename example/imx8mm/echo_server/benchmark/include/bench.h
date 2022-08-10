#pragma once

struct bench {
    uint64_t ccount;
    uint64_t prev;
    uint64_t ts;
    uint64_t overflows;
};

struct instr {
    uint64_t instr_overflows;
    uint64_t instr_idle_count;
};