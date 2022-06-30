#pragma once

struct bench {
    uint64_t ccount;
    uint64_t prev;
    uint64_t ts;
    uint64_t overflows;
};